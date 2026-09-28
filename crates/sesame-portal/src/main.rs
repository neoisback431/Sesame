// SPDX-License-Identifier: Apache-2.0
//! Binaire du portail : configuration, connexion aux briques externes, serveur HTTP.

use std::sync::{Arc, RwLock};

use sesame_core::audit::StdoutAuditSink;
use sesame_core::crypto::CookieCipher;
use sesame_core::ports::DescriptorStore;
use sesame_core::sources::{log_rejected, watch, DescriptorSource};
use sesame_portal::config::PortalConfig;
use sesame_portal::oidc::Oidc;
use sesame_portal::{router, Portal};
use sesame_store_postgres::PgStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sesame_core::telemetry::init_logging();
    let cfg = PortalConfig::from_env()?;
    let store = Arc::new(PgStore::connect(&cfg.database_url, None).await?);
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
    tracing::info!(count = catalog.descriptors.len(), "descripteurs chargés");

    let mut http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10));
    if let Some(ca) = &cfg.ca_file {
        http = http.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
    }
    let redirect = cfg.public_url.join("auth/callback")?.to_string();
    let oidc = Oidc::discover(&cfg.oidc, redirect, http.build()?).await?;
    tracing::info!(issuer = %cfg.oidc.issuer, "fournisseur d'identité découvert");

    let portal = Arc::new(Portal {
        public_url: cfg.public_url,
        cookie: cfg.cookie,
        session_ttl: cfg.session_ttl,
        descriptors: RwLock::new(Arc::new(catalog.descriptors)),
        oidc,
        state_cipher: CookieCipher::from_base64(&cfg.state_key)?,
        sessions: store.clone(),
        accounts: store,
        audit: Arc::new(StdoutAuditSink::default()),
        admin_url: cfg.admin_url,
        admin_group: cfg.admin_group,
    });
    // Rechargement à chaud des descripteurs créés ou modifiés dans l'UI d'administration.
    let reloaded = portal.clone();
    tokio::spawn(watch(
        source,
        cfg.reload_interval,
        initial_version,
        move |catalog| {
            log_rejected(&catalog);
            tracing::info!(count = catalog.descriptors.len(), "catalogue des applis rechargé");
            reloaded.set_descriptors(catalog.descriptors);
        },
    ));

    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    tracing::info!(addr = %cfg.listen, "portail démarré");
    axum::serve(listener, router(portal))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
