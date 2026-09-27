// SPDX-License-Identifier: Apache-2.0
//! Binaire du moteur de proxy : configuration, briques externes, serveur HTTP.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use sesame_core::audit::StdoutAuditSink;
use sesame_core::crypto::CookieCipher;
use sesame_core::ports::{DescriptorStore, DiagnosticStore, SecretStore, SessionStore};
use sesame_core::sources::{log_rejected, watch, DescriptorSource};
use sesame_proxy::config::{ProxyConfig, SecretStoreConfig};
use sesame_proxy::replay::Replayer;
use sesame_proxy::{build_apps, router, Proxy};
use sesame_secrets_openbao::{OpenBaoConfig, OpenBaoSecretStore};
use sesame_store_postgres::PgStore;

const PURGE_INTERVAL: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sesame_core::telemetry::init_logging();
    let cfg = ProxyConfig::from_env()?;
    let ca = cfg.ca_file.as_ref().map(std::fs::read).transpose()?;

    let cipher = CookieCipher::from_base64(&cfg.session_key)?;
    let store = Arc::new(PgStore::connect(&cfg.database_url, Some(cipher)).await?);
    store.migrate().await?;

    // Catalogue : fichiers (Git, lecture seule) + base (UI d'administration).
    let descriptor_store: Arc<dyn DescriptorStore> = store.clone();
    let source = Arc::new(DescriptorSource::new(
        Some(cfg.descriptors_dir.clone()),
        Some(descriptor_store),
    )?);
    let initial_version = source.version().await?;
    let catalog = source.load().await?;
    log_rejected(&catalog);
    let scheme = cfg.portal_url.scheme().to_owned();
    let (apps, rejected) = build_apps(catalog.descriptors, ca.as_deref(), &scheme);
    rejected
        .iter()
        .for_each(|r| tracing::error!(reason = %r, "appli écartée"));
    tracing::info!(count = apps.len(), "descripteurs chargés");

    let secrets: Arc<dyn SecretStore> = match cfg.secret_store {
        SecretStoreConfig::OpenBao {
            addr,
            mount,
            path_prefix,
            role_id,
            secret_id,
            namespace,
        } => {
            let mut http = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10));
            if let Some(ca) = &ca {
                http = http.add_root_certificate(reqwest::Certificate::from_pem(ca)?);
            }
            let cfg = OpenBaoConfig {
                addr,
                mount,
                path_prefix,
                role_id,
                secret_id,
                namespace,
            };
            Arc::new(OpenBaoSecretStore::new(cfg, http.build()?)?)
        }
    };

    let audit = Arc::new(StdoutAuditSink::default());
    let replayer = Replayer {
        secrets,
        accounts: store.clone(),
        audit: audit.clone(),
        diagnostics: cfg
            .replay_debug
            .then(|| store.clone() as Arc<dyn DiagnosticStore>),
    };
    if cfg.replay_debug {
        tracing::warn!("SESAME_REPLAY_DEBUG actif : diagnostic des rejeux en échec enregistré (ADR 0018)");
    }
    let sessions: Arc<dyn SessionStore> = store;
    let proxy = Arc::new(Proxy::new(
        apps,
        cfg.portal_url,
        cfg.cookie,
        sessions.clone(),
        audit,
        replayer,
        cfg.max_body_bytes,
    ));

    // Rechargement à chaud des descripteurs créés ou modifiés dans l'UI d'administration.
    let reloaded = proxy.clone();
    tokio::spawn(watch(
        source,
        cfg.reload_interval,
        initial_version,
        move |catalog| {
            log_rejected(&catalog);
            let (apps, rejected) = build_apps(catalog.descriptors, ca.as_deref(), &scheme);
            rejected
                .iter()
                .for_each(|r| tracing::error!(reason = %r, "appli écartée"));
            tracing::info!(count = apps.len(), "catalogue des applis rechargé");
            reloaded.set_apps(apps);
        },
    ));

    // Purge périodique des sessions expirées : PostgreSQL n'a pas de TTL natif.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PURGE_INTERVAL);
        loop {
            tick.tick().await;
            match sessions.purge_expired(SystemTime::now()).await {
                Ok(n) if n > 0 => tracing::info!(purged = n, "sessions expirées purgées"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "purge des sessions impossible"),
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    tracing::info!(addr = %cfg.listen, "proxy démarré");
    axum::serve(listener, router(proxy))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
