// SPDX-License-Identifier: Apache-2.0
//! Demandes d'accès depuis une tuile grisée de « Mes applications » (ADR 0029).
//!
//! - `GET  /apps/<id>/request` : formulaire à deux options ;
//! - `POST /apps/<id>/request/credentials` : « j'ai déjà un compte », identifiants relayés au
//!   moteur de proxy (service interne) qui les vérifie puis les écrit dans le coffre ;
//! - `POST /apps/<id>/request/no-account` : « je n'ai pas de compte », demande enregistrée
//!   pour qu'un administrateur crée le compte.
//!
//! Le portail n'écrit ni ne lit jamais le coffre : il ne fait que relayer. Les valeurs saisies
//! ne sont ni journalisées, ni renvoyées, ni conservées au-delà de la requête.

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use sesame_core::audit::{AuditAction, AuditEvent, AuditOutcome};
use sesame_core::descriptor::AppDescriptor;
use sesame_core::html::{escape, page};
use sesame_core::ports::{AccessRequestKind, AccountStatus, NotificationEvent, PortalSession, SubmitOutcome};
use sesame_core::secret::{ExposeSecret, SecretString};
use url::Url;

use crate::{correlation_id, redirect, AppState, Portal};

const MAX_NOTE_LEN: usize = 500;

/// Service interne du proxy (`SESAME_PROXY_INTERNAL_URL`, `SESAME_INTERNAL_TOKEN`).
pub struct ProxyInternal {
    pub url: Url,
    pub token: SecretString,
    pub http: reqwest::Client,
}

/// Le type de champ suit le nom de la clé de coffre (`password`, `secret`, `token`, `pin`…).
fn input_type(key: &str) -> &'static str {
    let k = key.to_ascii_lowercase();
    if ["pass", "secret", "token", "pin"].iter().any(|w| k.contains(w)) {
        "password"
    } else {
        "text"
    }
}

fn label(key: &str) -> String {
    match key {
        "username" => "Identifiant".into(),
        "password" => "Mot de passe".into(),
        other => other.to_owned(),
    }
}

/// Descripteur visé, si l'utilisateur peut faire une demande : habilité, sans compte (ou avec
/// un compte `pending` : la demande est déjà en cours). Sinon, la réponse à renvoyer.
// `Err` est directement la réponse à renvoyer (redirection ou page d'erreur).
#[allow(clippy::result_large_err)]
async fn eligible(
    p: &Portal,
    session: &PortalSession,
    app_id: &str,
    cid: &str,
) -> Result<AppDescriptor, Response> {
    let descriptors = p.descriptors();
    let found = descriptors
        .iter()
        .find(|d| d.metadata.id == app_id)
        .filter(|d| d.spec.access.allows(&session.user.user_key, &session.user.groups));
    let Some(d) = found else {
        return Err(p.error(
            StatusCode::NOT_FOUND,
            "Application inconnue",
            "Cette application n'existe pas.",
            cid,
        ));
    };
    match p.accounts.get_account(app_id, &session.user.user_key).await {
        Ok(None) => Ok(d.clone()),
        Ok(Some(a)) if a.status == AccountStatus::Pending => Err(redirect("/", &[])),
        Ok(Some(_)) => Err(redirect("/?request=exists", &[])),
        Err(e) => {
            tracing::error!(correlation_id = %cid, error = %e, "registre des comptes indisponible");
            Err(unavailable(p, cid))
        }
    }
}

fn unavailable(p: &Portal, cid: &str) -> Response {
    p.error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Service indisponible",
        "Réessayez dans quelques instants.",
        cid,
    )
}

fn render_form(
    p: &Portal,
    d: &AppDescriptor,
    error: Option<&str>,
    cid: &str,
    status: StatusCode,
) -> Response {
    let id = escape(&d.metadata.id);
    let mut body = format!("<h1>Demander l'accès à {}</h1>", escape(&d.metadata.name));
    if let Some(e) = error {
        body.push_str(&format!(
            "<p class=\"error\" role=\"alert\">{}</p><p class=\"muted\">Référence : <code>{}</code></p>",
            escape(e),
            escape(cid)
        ));
    }
    if p.proxy_internal.is_some() {
        body.push_str(&format!(
            "<div class=\"card\"><h2>J'ai déjà un compte</h2>\
<p class=\"muted\">Saisissez vos identifiants de cette application. Sesame les vérifie, les enregistre \
chiffrés et ne vous les redemandera jamais ; un administrateur n'a plus qu'à activer votre accès.</p>\
<form method=\"post\" action=\"/apps/{id}/request/credentials\" autocomplete=\"off\">"
        ));
        for key in &d.spec.credentials.keys {
            body.push_str(&format!(
                "<label for=\"f-{k}\">{}</label><input id=\"f-{k}\" name=\"{k}\" type=\"{}\" required \
maxlength=\"4096\" autocomplete=\"off\">",
                escape(&label(key)),
                input_type(key),
                k = escape(key),
            ));
        }
        body.push_str("<p><button type=\"submit\">Envoyer mes identifiants</button></p></form></div>");
    }
    body.push_str(&format!(
        "<div class=\"card\"><h2>Je n'ai pas de compte</h2>\
<p class=\"muted\">Un administrateur verra votre demande et créera votre compte sur l'application.</p>\
<form method=\"post\" action=\"/apps/{id}/request/no-account\">\
<label for=\"note\">Message pour l'administrateur (facultatif)</label>\
<textarea id=\"note\" name=\"note\" rows=\"3\" maxlength=\"{MAX_NOTE_LEN}\"></textarea>\
<p><button type=\"submit\">Demander la création d'un compte</button></p></form></div>\
<p><a href=\"/\">Retour à mes applications</a></p>"
    ));
    let html = page("Demander l'accès", &body, p.public_url.as_str());
    (status, [(CACHE_CONTROL, "no-store")], Html(html)).into_response()
}

pub async fn form(State(p): State<AppState>, Path(app_id): Path<String>, headers: HeaderMap) -> Response {
    let cid = correlation_id(&headers);
    let Some(session) = p.current_session(&headers).await else {
        return p.start_login(p.public_url.to_string());
    };
    match eligible(&p, &session, &app_id, &cid).await {
        Ok(d) => render_form(&p, &d, None, &cid, StatusCode::OK),
        Err(resp) => resp,
    }
}

/// « J'ai déjà un compte » : les identifiants sont relayés au proxy, jamais lus ici.
pub async fn submit_credentials(
    State(p): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
    Form(mut values): Form<HashMap<String, String>>,
) -> Response {
    let cid = correlation_id(&headers);
    let Some(session) = p.current_session(&headers).await else {
        return p.start_login(p.public_url.to_string());
    };
    let d = match eligible(&p, &session, &app_id, &cid).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let Some(proxy) = &p.proxy_internal else {
        return p.error(
            StatusCode::NOT_IMPLEMENTED,
            "Indisponible",
            "Cette option n'est pas activée sur ce déploiement.",
            &cid,
        );
    };

    // Seules les clés attendues par le descripteur sont retenues, dans des types masqués.
    let mut fields: Vec<(String, SecretString)> = Vec::new();
    for key in &d.spec.credentials.keys {
        match values.remove(key).filter(|v| !v.is_empty()) {
            Some(v) => fields.push((key.clone(), SecretString::from(v))),
            None => {
                return render_form(
                    &p,
                    &d,
                    Some("Renseignez tous les champs."),
                    &cid,
                    StatusCode::UNPROCESSABLE_ENTITY,
                )
            }
        }
    }
    drop(values);
    let payload = {
        let fields: serde_json::Map<String, serde_json::Value> = fields
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.expose_secret().to_owned())))
            .collect();
        serde_json::json!({
            "app_id": app_id,
            "user": session.user,
            "fields": fields,
            "correlation_id": cid,
        })
    };
    drop(fields);
    let Ok(endpoint) = proxy.url.join("internal/access-requests") else {
        tracing::error!("SESAME_PROXY_INTERNAL_URL invalide");
        return unavailable(&p, &cid);
    };
    let sent = proxy
        .http
        .post(endpoint)
        .header(AUTHORIZATION, format!("Bearer {}", proxy.token.expose_secret()))
        .json(&payload)
        .send()
        .await;
    drop(payload);
    let status = match sent {
        Ok(r) => r.status(),
        Err(e) => {
            // `without_url` : l'adresse interne n'a rien à faire dans un journal.
            tracing::error!(correlation_id = %cid, error = %e.without_url(), "service interne du proxy injoignable");
            return unavailable(&p, &cid);
        }
    };
    match status {
        StatusCode::OK => redirect("/?request=credentials", &[]),
        StatusCode::CONFLICT => redirect("/?request=exists", &[]),
        StatusCode::UNPROCESSABLE_ENTITY => render_form(
            &p,
            &d,
            Some("L'application a refusé ces identifiants. Vérifiez-les puis réessayez."),
            &cid,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        StatusCode::BAD_GATEWAY => render_form(
            &p,
            &d,
            Some("L'application est injoignable pour le moment. Réessayez plus tard."),
            &cid,
            StatusCode::BAD_GATEWAY,
        ),
        StatusCode::NOT_IMPLEMENTED => p.error(
            StatusCode::NOT_IMPLEMENTED,
            "Indisponible",
            "Cette option n'est pas disponible avec le coffre de secrets configuré.",
            &cid,
        ),
        other => {
            tracing::error!(correlation_id = %cid, status = %other, "réponse inattendue du service interne");
            unavailable(&p, &cid)
        }
    }
}

#[derive(Deserialize)]
pub struct NoAccountForm {
    note: Option<String>,
}

/// Message libre nettoyé : sans caractères de contrôle (hors saut de ligne), borné.
fn clean_note(note: Option<String>) -> Option<String> {
    let cleaned: String = note
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(MAX_NOTE_LEN)
        .collect();
    let cleaned = cleaned.trim().to_owned();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// « Je n'ai pas de compte » : la demande est enregistrée, l'administrateur crée le compte.
pub async fn submit_no_account(
    State(p): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<NoAccountForm>,
) -> Response {
    let cid = correlation_id(&headers);
    let Some(session) = p.current_session(&headers).await else {
        return p.start_login(p.public_url.to_string());
    };
    if let Err(resp) = eligible(&p, &session, &app_id, &cid).await {
        return resp;
    }
    let note = clean_note(form.note);
    let event = |outcome, reason: &str| {
        AuditEvent::new(AuditAction::AccessRequested, outcome)
            .actor(&session.user)
            .app(&app_id)
            .correlation(&cid)
            .reason(reason)
    };
    let outcome = p
        .access
        .submit(
            &app_id,
            &session.user.user_key,
            AccessRequestKind::NoAccount,
            note.as_deref(),
        )
        .await;
    let recorded = matches!(outcome, Ok(SubmitOutcome::Recorded));
    let (audited, response) = match outcome {
        Ok(SubmitOutcome::Recorded) => (
            event(AuditOutcome::Success, "no_account"),
            redirect("/?request=no_account", &[]),
        ),
        Ok(SubmitOutcome::AccountExists) => (
            event(AuditOutcome::Failure, "account_exists"),
            redirect("/?request=exists", &[]),
        ),
        Err(e) => {
            tracing::error!(correlation_id = %cid, error = %e, "enregistrement de la demande impossible");
            let _ = p
                .audit
                .record(event(AuditOutcome::Failure, "store_unavailable"))
                .await;
            return unavailable(&p, &cid);
        }
    };
    if recorded {
        p.notifier
            .notify(
                NotificationEvent::AccessRequested,
                &app_id,
                Some(&session.user.user_key),
                "no_account",
            )
            .await;
    }
    if let Err(e) = p.audit.record(audited).await {
        tracing::error!(correlation_id = %cid, error = %e, "audit de la demande impossible");
    }
    tracing::info!(app_id = %app_id, user = %session.user.user_key, correlation_id = %cid, "demande d'accès enregistrée");
    response
}

/// Client HTTP du service interne : délai large, le rejeu de vérification pouvant enchaîner
/// plusieurs requêtes vers l'appli.
pub fn internal_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_types_follow_key_names() {
        assert_eq!(input_type("password"), "password");
        assert_eq!(input_type("api_token"), "password");
        assert_eq!(input_type("username"), "text");
    }

    #[test]
    fn notes_are_cleaned_and_bounded() {
        assert_eq!(clean_note(None), None);
        assert_eq!(clean_note(Some("  \u{7}  ".into())), None);
        assert_eq!(clean_note(Some("a\u{0}b\nc".into())).as_deref(), Some("ab\nc"));
        assert_eq!(clean_note(Some("x".repeat(900))).unwrap().len(), MAX_NOTE_LEN);
    }
}
