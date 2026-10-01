// SPDX-License-Identifier: Apache-2.0
//! Banc du service interne des demandes d'accès (ADR 0029).
#![allow(dead_code)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use sesame_core::identity::UserIdentity;
use sesame_core::ports::SecretWriter;
use tower::ServiceExt;

use super::{alice, Bench};

pub const INTERNAL_TOKEN: &str = "internal-token-XYZ";

pub struct AccessBench {
    pub router: Router,
    pub requests: Arc<sesame_core::memory::MemoryAccessRequests>,
}

/// `writable` : `false` simule un coffre en lecture seule pour le proxy (OpenBao/Vault).
pub fn access_bench(b: &Bench, writable: bool) -> AccessBench {
    let requests = Arc::new(sesame_core::memory::MemoryAccessRequests::new(b.accounts.clone()));
    let router = sesame_proxy::internal::router(Arc::new(sesame_proxy::internal::Internal {
        proxy: b.engine.clone(),
        token: sesame_core::secret::SecretString::from(INTERNAL_TOKEN),
        requests: requests.clone(),
        writer: writable.then(|| b.secrets.clone() as Arc<dyn SecretWriter>),
    }));
    AccessBench { router, requests }
}

pub fn bob(groups: &[&str]) -> UserIdentity {
    UserIdentity {
        user_key: "bob".into(),
        subject: "sub-bob".into(),
        display_name: Some("Bob".into()),
        email: None,
        ..alice(groups)
    }
}

/// Soumission au service interne ; renvoie statut et corps.
pub async fn post_access(
    router: &Router,
    token: Option<&str>,
    user: &UserIdentity,
    fields: serde_json::Value,
) -> (StatusCode, String) {
    let body = serde_json::json!({ "app_id": "fake-app", "user": user, "fields": fields });
    let mut req = Request::builder()
        .method("POST")
        .uri("/internal/access-requests")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let text = String::from_utf8_lossy(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).into_owned();
    (status, text)
}
