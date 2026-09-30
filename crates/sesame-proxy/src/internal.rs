// SPDX-License-Identifier: Apache-2.0
//! Service interne du proxy : demandes d'accès avec identifiants fournis par l'utilisateur
//! (ADR 0029).
//!
//! Écoute sur une adresse distincte de celle du relais (`SESAME_PROXY_INTERNAL_LISTEN`),
//! jamais exposée par Nginx, et exige un jeton partagé (`SESAME_INTERNAL_TOKEN`). Seul le
//! portail l'appelle, après avoir vérifié la session de l'utilisateur.
//!
//! `POST /internal/access-requests` : vérifie les identifiants par un rejeu de test (une
//! seule tentative), crée le compte `pending`, écrit le secret dans le coffre. Les réponses
//! ne contiennent qu'un code d'état ; jamais une valeur saisie ni un contenu de l'appli.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sesame_core::audit::{AuditAction, AuditEvent, AuditOutcome};
use sesame_core::identity::{validate_user_key, UserIdentity};
use sesame_core::ports::{
    AccessRequestKind, AccessRequests, AccountStatus, NotificationEvent, SecretWriter, SubmitOutcome,
};
use sesame_core::secret::{Credential, ExposeSecret, SecretString};

use crate::replay::ReplayError;
use crate::Proxy;

const MAX_VALUE_LEN: usize = 4096;

pub struct Internal {
    pub proxy: Arc<Proxy>,
    pub token: SecretString,
    pub requests: Arc<dyn AccessRequests>,
    /// Absent avec un coffre en lecture seule pour le proxy (OpenBao/Vault) : la demande
    /// « j'ai un compte » répond alors `unsupported`.
    pub writer: Option<Arc<dyn SecretWriter>>,
}

pub fn router(internal: Arc<Internal>) -> Router {
    Router::new()
        .route("/internal/access-requests", post(access_request))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(internal)
}

#[derive(Deserialize)]
struct Submission {
    app_id: String,
    user: UserIdentity,
    fields: BTreeMap<String, SecretString>,
    correlation_id: Option<String>,
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn reply(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({ "status": code }))).into_response()
}

fn authorized(headers: &HeaderMap, token: &SecretString) -> bool {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|given| constant_time_eq(given.as_bytes(), token.expose_secret().as_bytes()))
}

fn valid_cid(cid: Option<String>) -> String {
    cid.filter(|c| c.len() <= 64 && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

async fn access_request(
    State(i): State<Arc<Internal>>,
    headers: HeaderMap,
    Json(sub): Json<Submission>,
) -> Response {
    if !authorized(&headers, &i.token) {
        return reply(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let cid = valid_cid(sub.correlation_id);
    let event = |outcome, reason: &str| {
        AuditEvent::new(AuditAction::AccessRequested, outcome)
            .actor(&sub.user)
            .app(&sub.app_id)
            .correlation(&cid)
            .reason(reason)
    };
    // L'échec d'un audit fait échouer l'opération : jamais d'action sans trace.
    macro_rules! audit {
        ($e:expr) => {
            if i.proxy.audit.record($e).await.is_err() {
                return reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
            }
        };
    }
    macro_rules! refuse {
        ($status:expr, $code:literal, $reason:expr) => {{
            audit!(event(AuditOutcome::Failure, $reason));
            return reply($status, $code);
        }};
    }

    let Some(app) = i.proxy.app_by_id(&sub.app_id) else {
        refuse!(StatusCode::NOT_FOUND, "unknown_app", "unknown_app");
    };
    let d = &app.descriptor;
    if validate_user_key(&sub.user.user_key).is_err() {
        refuse!(StatusCode::BAD_REQUEST, "invalid", "invalid_user");
    }
    if !d.spec.access.allows(&sub.user.user_key, &sub.user.groups) {
        refuse!(StatusCode::FORBIDDEN, "not_allowed", "not_allowed");
    }
    let Some(writer) = &i.writer else {
        refuse!(
            StatusCode::NOT_IMPLEMENTED,
            "unsupported",
            "secret_store_read_only"
        );
    };
    let keys = &d.spec.credentials.keys;
    let complete = sub.fields.len() == keys.len() && keys.iter().all(|k| sub.fields.contains_key(k));
    let values_ok = sub.fields.values().all(|v| {
        let v = v.expose_secret();
        !v.is_empty() && v.len() <= MAX_VALUE_LEN && !v.contains('\0')
    });
    if !complete || !values_ok {
        refuse!(StatusCode::BAD_REQUEST, "invalid", "invalid_fields");
    }

    // Un compte déjà actif, en échec ou désactivé n'est jamais écrasé par ce chemin.
    match i
        .proxy
        .replayer
        .accounts
        .get_account(&sub.app_id, &sub.user.user_key)
        .await
    {
        Ok(Some(a)) if a.status != AccountStatus::Pending => {
            refuse!(StatusCode::CONFLICT, "account_exists", "account_exists");
        }
        Ok(_) => {}
        Err(_) => refuse!(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "registry_unavailable"
        ),
    }

    let credential = Credential::new(sub.fields);
    if let Err(e) = i
        .proxy
        .replayer
        .verify(&app.http, d, &sub.user, &credential, &cid)
        .await
    {
        return match e {
            ReplayError::Rejected(r) => {
                audit!(event(AuditOutcome::Failure, &format!("verify_failed:{r}")));
                reply(StatusCode::UNPROCESSABLE_ENTITY, "invalid_credentials")
            }
            ReplayError::Upstream => {
                audit!(event(AuditOutcome::Failure, "upstream_unreachable"));
                reply(StatusCode::BAD_GATEWAY, "upstream_unreachable")
            }
            _ => reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
    }

    // Le compte `pending` est créé avant le secret : la condition côté base garantit qu'un
    // compte existant n'est pas écrasé, y compris face à une soumission concurrente.
    match i
        .requests
        .submit(
            &sub.app_id,
            &sub.user.user_key,
            AccessRequestKind::Credentials,
            None,
        )
        .await
    {
        Ok(SubmitOutcome::Recorded) => {}
        Ok(SubmitOutcome::AccountExists) => {
            refuse!(StatusCode::CONFLICT, "account_exists", "account_exists");
        }
        Err(_) => refuse!(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "registry_unavailable"
        ),
    }
    if writer
        .put_credential(&sub.app_id, &sub.user.user_key, &credential)
        .await
        .is_err()
    {
        let _ = i.requests.withdraw(&sub.app_id, &sub.user.user_key).await;
        refuse!(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "secret_write_failed"
        );
    }
    drop(credential);
    let written = AuditEvent::new(AuditAction::CredentialWritten, AuditOutcome::Success)
        .actor(&sub.user)
        .app(&sub.app_id)
        .correlation(&cid)
        .reason("access_request");
    let traced = i.proxy.audit.record(written).await.is_ok()
        && i.proxy
            .audit
            .record(event(AuditOutcome::Success, "credentials"))
            .await
            .is_ok();
    if !traced {
        // Pas de compte en attente sans trace : la demande est retirée (le secret, sans
        // compte associé, reste inutilisable et sera écrasé à la prochaine soumission).
        let _ = i.requests.withdraw(&sub.app_id, &sub.user.user_key).await;
        return reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    i.proxy
        .replayer
        .notifier
        .notify(
            NotificationEvent::AccessRequested,
            &sub.app_id,
            Some(&sub.user.user_key),
            "credentials",
        )
        .await;
    tracing::info!(
        app = %sub.app_id,
        user = %sub.user.user_key,
        correlation_id = %cid,
        "demande d'accès (identifiants fournis) enregistrée"
    );
    reply(StatusCode::OK, "recorded")
}
