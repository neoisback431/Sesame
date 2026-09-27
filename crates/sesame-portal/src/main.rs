// SPDX-License-Identifier: Apache-2.0
//! Portail d'authentification Sesame.
//!
//! Squelette : seul `/healthz` est exposé. L'authentification OIDC, la session
//! portail et la résolution des habilitations arrivent avec le MVP.

use axum::{routing::get, Json, Router};
use serde_json::json;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    sesame_core::telemetry::init_logging();
    let addr = std::env::var("SESAME_PORTAL_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let app = Router::new().route("/healthz", get(|| async { Json(json!({ "status": "ok" })) }));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "portail démarré");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
