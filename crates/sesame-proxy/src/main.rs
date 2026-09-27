// SPDX-License-Identifier: Apache-2.0
//! Moteur de proxy Sesame.
//!
//! Squelette : charge et valide les descripteurs au démarrage, expose `/healthz`.
//! Le relais, le rejeu et l'injection de session arrivent avec le MVP.

use std::path::{Path, PathBuf};

use axum::{routing::get, Json, Router};
use serde_json::json;
use sesame_core::descriptor::AppDescriptor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sesame_core::telemetry::init_logging();
    let dir = PathBuf::from(std::env::var("SESAME_DESCRIPTORS_DIR").unwrap_or_else(|_| "descriptors".into()));
    let descriptors = load_descriptors(&dir)?;
    tracing::info!(count = descriptors.len(), dir = %dir.display(), "descripteurs chargés");

    let addr = std::env::var("SESAME_PROXY_LISTEN").unwrap_or_else(|_| "0.0.0.0:8081".into());
    let app = Router::new().route(
        "/healthz",
        get(move || async move { Json(json!({ "status": "ok", "apps": descriptors.len() })) }),
    );
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "proxy démarré");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

/// Charge tous les `*.yaml` du dossier ; un descripteur invalide empêche le démarrage.
fn load_descriptors(dir: &Path) -> Result<Vec<AppDescriptor>, Box<dyn std::error::Error>> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "yaml" || ext == "yml"))
        .collect();
    paths.sort();
    let descriptors = paths
        .iter()
        .map(|p| AppDescriptor::from_file(p))
        .collect::<Result<Vec<_>, _>>()?;
    let mut ids: Vec<_> = descriptors.iter().map(|d| &d.metadata.id).collect();
    ids.sort();
    if let Some(w) = ids.windows(2).find(|w| w[0] == w[1]) {
        return Err(format!("metadata.id en double : {}", w[0]).into());
    }
    Ok(descriptors)
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
