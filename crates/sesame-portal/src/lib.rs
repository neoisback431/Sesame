// SPDX-License-Identifier: Apache-2.0
//! Portail d'authentification Sesame.
//!
//! - `GET /` : page « Mes applications » (connexion OIDC si nécessaire) ;
//! - `GET /auth/login?return_to=…` : départ vers le fournisseur d'identité ;
//! - `GET /auth/callback` : retour OIDC, création de la session portail ;
//! - `POST /auth/logout` : destruction de la session portail et des sessions applicatives,
//!   puis, si activée, déconnexion chez le fournisseur d'identité ;
//! - `GET /auth/logged-out` : page de confirmation (retour du fournisseur).
//!
//! Le portail n'accède jamais au coffre de secrets.

pub mod catalog;
pub mod config;
pub mod oidc;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::header::{CACHE_CONTROL, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sesame_core::audit::{AuditAction, AuditEvent, AuditOutcome};
use sesame_core::cookies::{self, PortalCookie};
use sesame_core::crypto::{hash_token, new_token, CookieCipher};
use sesame_core::descriptor::AppDescriptor;
use sesame_core::html::error_page;
use sesame_core::ports::{AccountRegistry, AuditSink, PortalSession, SessionStore};
use sesame_core::secret::ExposeSecret;
use url::Url;

use crate::oidc::{Oidc, PendingLogin};

const LOGIN_COOKIE: &str = "sesame_oidc";
const LOGIN_TTL: Duration = Duration::from_secs(600);
const LOGIN_AAD: &[u8] = b"sesame-oidc-login";

pub struct Portal {
    pub public_url: Url,
    pub cookie: PortalCookie,
    pub session_ttl: Duration,
    pub descriptors: Vec<AppDescriptor>,
    pub oidc: Oidc,
    pub state_cipher: CookieCipher,
    pub sessions: Arc<dyn SessionStore>,
    pub accounts: Arc<dyn AccountRegistry>,
    pub audit: Arc<dyn AuditSink>,
}

type AppState = Arc<Portal>;

pub fn router(portal: Arc<Portal>) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/auth/logged-out", get(logged_out))
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
        )
        .with_state(portal)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn correlation_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 64 && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

fn redirect(to: &str, set_cookies: &[String]) -> Response {
    let mut resp = StatusCode::FOUND.into_response();
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(to) {
        h.insert(LOCATION, v);
    }
    for c in set_cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            h.append(SET_COOKIE, v);
        }
    }
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

impl Portal {
    fn error(&self, status: StatusCode, title: &str, message: &str, cid: &str) -> Response {
        let html = error_page(title, message, cid, self.public_url.as_str());
        (status, [(CACHE_CONTROL, "no-store")], Html(html)).into_response()
    }

    fn login_cookie(&self, value: &str, max_age: u64) -> String {
        let secure = if self.cookie.secure { "; Secure" } else { "" };
        format!("{LOGIN_COOKIE}={value}; Path=/auth; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")
    }

    async fn current_session(&self, headers: &HeaderMap) -> Option<PortalSession> {
        let values = headers.get_all(COOKIE).iter().filter_map(|v| v.to_str().ok());
        let token = cookies::find(values, &self.cookie.name)?;
        match self.sessions.get_portal_session(&hash_token(token)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "lecture de la session portail impossible");
                None
            }
        }
    }

    fn start_login(&self, return_to: String) -> Response {
        let (url, pending) = self.oidc.start(return_to, now_secs() + LOGIN_TTL.as_secs());
        match seal(&self.state_cipher, &pending) {
            Some(sealed) => redirect(&url, &[self.login_cookie(&sealed, LOGIN_TTL.as_secs())]),
            None => self.error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Erreur",
                "Connexion impossible.",
                "-",
            ),
        }
    }
}

async fn home(State(p): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = p.current_session(&headers).await else {
        return p.start_login(p.public_url.to_string());
    };
    let cid = correlation_id(&headers);
    let accounts = match p.accounts.list_accounts(&session.user.user_key).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, correlation_id = %cid, "registre des comptes indisponible");
            return p.error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service indisponible",
                "La liste de vos applications est momentanément indisponible.",
                &cid,
            );
        }
    };
    let tiles = catalog::tiles(&p.descriptors, &session.user, &accounts);
    let html = catalog::render(&session.user, &tiles, p.public_url.scheme());
    ([(CACHE_CONTROL, "no-store")], Html(html)).into_response()
}

#[derive(Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
}

async fn login(State(p): State<AppState>, Query(q): Query<LoginQuery>) -> Response {
    p.start_login(safe_return_to(
        &p.public_url,
        &p.descriptors,
        q.return_to.as_deref(),
    ))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn callback(State(p): State<AppState>, headers: HeaderMap, Query(q): Query<CallbackQuery>) -> Response {
    let cid = correlation_id(&headers);
    let clear_login = p.login_cookie("", 0);
    let values = headers.get_all(COOKIE).iter().filter_map(|v| v.to_str().ok());
    let pending = cookies::find(values, LOGIN_COOKIE).and_then(|v| unseal(&p.state_cipher, v, now_secs()));
    let state_ok = match (&pending, &q.state) {
        (Some(pending), Some(state)) => constant_time_eq(pending.state.as_bytes(), state.as_bytes()),
        _ => false,
    };
    let (Some(pending), Some(code), true, None) = (pending, q.code, state_ok, q.error.as_ref()) else {
        tracing::warn!(correlation_id = %cid, idp_error = ?q.error, "retour OIDC refusé");
        let _ = p
            .audit
            .record(
                AuditEvent::new(AuditAction::PortalLogin, AuditOutcome::Failure)
                    .correlation(&cid)
                    .reason("invalid_callback"),
            )
            .await;
        let mut resp = p.error(
            StatusCode::BAD_REQUEST,
            "Connexion refusée",
            "La connexion n'a pas pu aboutir. Réessayez depuis la page d'accueil.",
            &cid,
        );
        if let Ok(v) = HeaderValue::from_str(&clear_login) {
            resp.headers_mut().append(SET_COOKIE, v);
        }
        return resp;
    };

    let user = match p.oidc.finish(code, &pending).await {
        Ok(user) => user,
        Err(e) => {
            tracing::warn!(correlation_id = %cid, error = %e, "authentification OIDC échouée");
            let _ = p
                .audit
                .record(
                    AuditEvent::new(AuditAction::PortalLogin, AuditOutcome::Failure)
                        .correlation(&cid)
                        .reason("oidc_error"),
                )
                .await;
            return p.error(
                StatusCode::UNAUTHORIZED,
                "Connexion refusée",
                "Votre identité n'a pas pu être vérifiée.",
                &cid,
            );
        }
    };

    let token = new_token();
    let now = SystemTime::now();
    let session = PortalSession {
        id: hash_token(token.expose_secret()),
        user: user.clone(),
        created_at: now,
        expires_at: now + p.session_ttl,
    };
    let event = AuditEvent::new(AuditAction::PortalLogin, AuditOutcome::Success)
        .actor(&user)
        .correlation(&cid);
    // L'audit fait partie de l'opération : pas de session sans trace.
    let stored = async {
        p.audit.record(event).await?;
        p.sessions.create_portal_session(session).await
    };
    if let Err(e) = stored.await {
        tracing::error!(correlation_id = %cid, error = %e, "création de la session portail impossible");
        return p.error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service indisponible",
            "Réessayez dans quelques instants.",
            &cid,
        );
    }
    tracing::info!(correlation_id = %cid, user = %user.user_key, "session portail créée");
    let set = p.cookie.set(token.expose_secret(), p.session_ttl.as_secs());
    redirect(&pending.return_to, &[set, clear_login])
}

async fn logout(State(p): State<AppState>, headers: HeaderMap) -> Response {
    let cid = correlation_id(&headers);
    let back = p
        .public_url
        .join("auth/logged-out")
        .map(|u| u.to_string())
        .unwrap_or_else(|_| p.public_url.to_string());
    let idp_logout = p.oidc.logout_url(&back);
    if let Some(session) = p.current_session(&headers).await {
        let event = AuditEvent::new(AuditAction::PortalLogout, AuditOutcome::Success)
            .actor(&session.user)
            .correlation(&cid)
            .reason(if idp_logout.is_some() {
                "with_idp_logout"
            } else {
                "local"
            });
        if let Err(e) = p.sessions.delete_portal_session(&session.id).await {
            tracing::error!(correlation_id = %cid, error = %e, "suppression de la session portail impossible");
        } else if let Err(e) = p.audit.record(event).await {
            tracing::error!(correlation_id = %cid, error = %e, "audit de déconnexion impossible");
        }
    }
    match idp_logout {
        // 303 : le navigateur suit en GET vers le point de déconnexion du fournisseur.
        Some(url) => {
            let mut resp = redirect(&url, &[p.cookie.clear()]);
            *resp.status_mut() = StatusCode::SEE_OTHER;
            resp
        }
        None => logged_out_page(&p, Some(p.cookie.clear())),
    }
}

async fn logged_out(State(p): State<AppState>) -> Response {
    logged_out_page(&p, None)
}

fn logged_out_page(p: &Portal, clear_cookie: Option<String>) -> Response {
    let html = sesame_core::html::page(
        "Déconnecté",
        &format!(
            "<h1>Vous êtes déconnecté</h1><p><a href=\"{}\">Se reconnecter</a></p>",
            sesame_core::html::escape(p.public_url.as_str())
        ),
    );
    let mut resp = ([(CACHE_CONTROL, "no-store")], Html(html)).into_response();
    if let Some(v) = clear_cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
    resp
}

fn authority(url: &Url) -> Option<String> {
    match (url.host_str(), url.port()) {
        (Some(h), Some(p)) => Some(format!("{h}:{p}")),
        (Some(h), None) => Some(h.to_owned()),
        _ => None,
    }
}

/// `return_to` doit viser le portail ou une appli déclarée (pas de redirection ouverte).
pub fn safe_return_to(public_url: &Url, descriptors: &[AppDescriptor], candidate: Option<&str>) -> String {
    let fallback = public_url.to_string();
    let Some(url) = candidate.and_then(|c| Url::parse(c).ok()) else {
        return fallback;
    };
    let Some(target) = authority(&url) else {
        return fallback;
    };
    let known = authority(public_url).as_deref() == Some(target.as_str())
        || descriptors.iter().any(|d| d.spec.public.host == target);
    if known && url.scheme() == public_url.scheme() && url.username().is_empty() && url.password().is_none() {
        url.to_string()
    } else {
        fallback
    }
}

/// Chiffre l'état OIDC en cours pour le porter dans un cookie.
pub fn seal(cipher: &CookieCipher, pending: &PendingLogin) -> Option<String> {
    use base64::Engine;
    let plain = serde_json::to_vec(pending).ok()?;
    let sealed = cipher.encrypt(&plain, LOGIN_AAD);
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed))
}

/// Déchiffre l'état OIDC ; `None` s'il est altéré ou expiré.
pub fn unseal(cipher: &CookieCipher, value: &str, now: u64) -> Option<PendingLogin> {
    use base64::Engine;
    let sealed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()?;
    let plain = cipher.decrypt(&sealed, LOGIN_AAD).ok()?;
    let pending: PendingLogin = serde_json::from_slice(&plain).ok()?;
    (pending.expires_at > now).then_some(pending)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use sesame_core::secret::SecretString;

    use super::*;

    const FAKE_APP: &str = include_str!("../../../descriptors/fake-app.yaml");

    #[test]
    fn return_to_is_limited_to_known_hosts() {
        let portal = Url::parse("https://sesame.localhost:8443/").unwrap();
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let check = |c: &str| safe_return_to(&portal, &ds, Some(c));
        let app = "https://fake-app.sesame.localhost:8443/account?x=1";
        assert_eq!(check(app), app);
        assert_eq!(
            check("https://sesame.localhost:8443/"),
            "https://sesame.localhost:8443/"
        );
        for bad in [
            "https://evil.example/",
            "http://fake-app.sesame.localhost:8443/",
            "https://fake-app.sesame.localhost/",
            "https://user@fake-app.sesame.localhost:8443/",
            "//evil.example/",
            "javascript:alert(1)",
            "/relative",
        ] {
            assert_eq!(check(bad), "https://sesame.localhost:8443/", "{bad}");
        }
        assert_eq!(
            safe_return_to(&portal, &ds, None),
            "https://sesame.localhost:8443/"
        );
    }

    #[test]
    fn login_state_is_sealed_and_expires() {
        let key = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        let cipher = CookieCipher::from_base64(&SecretString::from(key)).unwrap();
        let pending = PendingLogin {
            state: "st".into(),
            nonce: "no".into(),
            pkce_verifier: "verifier-secret".into(),
            return_to: "https://x/".into(),
            expires_at: 1_000,
        };
        let sealed = seal(&cipher, &pending).unwrap();
        assert!(!sealed.contains("verifier"));
        assert_eq!(unseal(&cipher, &sealed, 999).unwrap().state, "st");
        assert!(unseal(&cipher, &sealed, 1_000).is_none(), "expiré");
        let mut tampered = sealed.clone();
        tampered.replace_range(20..21, if &sealed[20..21] == "A" { "B" } else { "A" });
        assert!(unseal(&cipher, &tampered, 999).is_none(), "altéré");
    }

    #[test]
    fn constant_time_comparison() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
