// SPDX-License-Identifier: Apache-2.0
//! Binaire du moteur de proxy : configuration, briques externes, serveur HTTP.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use sesame_core::audit::StdoutAuditSink;
use sesame_core::crypto::CookieCipher;
use sesame_core::descriptor::load_dir;
use sesame_core::ports::{SecretStore, SessionStore};
use sesame_proxy::config::{ProxyConfig, SecretStoreConfig};
use sesame_proxy::replay::Replayer;
use sesame_proxy::{build_client, router, App, Proxy};
use sesame_secrets_openbao::{OpenBaoConfig, OpenBaoSecretStore};
use sesame_store_postgres::PgStore;

const PURGE_INTERVAL: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sesame_core::telemetry::init_logging();
    let cfg = ProxyConfig::from_env()?;
    let ca = cfg.ca_file.as_ref().map(std::fs::read).transpose()?;

    let descriptors = load_dir(&cfg.descriptors_dir)?;
    let scheme = cfg.portal_url.scheme().to_owned();
    let apps = descriptors
        .into_iter()
        .map(|d| {
            let http = build_client(&d, ca.as_deref())?;
            Ok(App::new(d, http, &scheme))
        })
        .collect::<Result<Vec<_>, String>>()?;
    tracing::info!(count = apps.len(), "descripteurs chargés");

    let cipher = CookieCipher::from_base64(&cfg.session_key)?;
    let store = Arc::new(PgStore::connect(&cfg.database_url, Some(cipher)).await?);
    store.migrate().await?;

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
    };
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
