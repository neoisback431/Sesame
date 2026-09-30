// SPDX-License-Identifier: Apache-2.0
//! Portail d'authentification Sesame.
//!
//! - `GET /` : page « Mes applications » (connexion OIDC si nécessaire) ;
//! - `GET /auth/login?return_to=…` : départ vers le fournisseur d'identité ;
//! - `GET /auth/callback` : retour OIDC, création de la session portail
//!   (`POST /auth/callback` : retour SAML, Assertion Consumer Service) ;
//!   `GET /saml/metadata` : métadonnées SP, seulement en protocole SAML ;
//! - `POST /auth/logout` : destruction de la session portail et des sessions applicatives,
//!   puis, si activée, déconnexion chez le fournisseur d'identité ;
//! - `GET /auth/logged-out` : page de confirmation (retour du fournisseur).
//!
//! - `GET /apps/<id>/request`, `POST /apps/<id>/request/{credentials,no-account}` : demandes
//!   d'accès depuis une tuile grisée (ADR 0029).
//!
//! Le portail n'accède jamais au coffre de secrets : les identifiants d'une demande sont relayés
//! au moteur de proxy (service interne), qui les vérifie et les écrit.

pub mod access;
#[cfg(test)]
mod access_tests;
pub mod catalog;
pub mod config;
pub mod idp;
pub mod oidc;
pub mod saml;

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::Deserialize;
use sesame_core::audit::{AuditAction, AuditEvent, AuditOutcome};
use sesame_core::cookies::{self, PortalCookie};
use sesame_core::crypto::{hash_token, new_token, CookieCipher};
use sesame_core::descriptor::AppDescriptor;
use sesame_core::html::error_page;
use sesame_core::identity::UserIdentity;
use sesame_core::ports::{AccessRequests, AccountRegistry, AuditSink, Notifier, PortalSession, SessionStore};
use sesame_core::secret::ExposeSecret;
use url::Url;

use crate::idp::{Callback, IdentityProvider, PendingLogin};

const LOGIN_COOKIE: &str = "sesame_oidc";
const LOGIN_TTL: Duration = Duration::from_secs(600);
const LOGIN_AAD: &[u8] = b"sesame-oidc-login";

pub struct Portal {
    pub public_url: Url,
    pub cookie: PortalCookie,
    pub session_ttl: Duration,
    /// Catalogue des applis, remplacé d'un bloc au rechargement à chaud.
    pub descriptors: RwLock<Arc<Vec<AppDescriptor>>>,
    pub idp: IdentityProvider,
    pub state_cipher: CookieCipher,
    pub sessions: Arc<dyn SessionStore>,
    pub accounts: Arc<dyn AccountRegistry>,
    /// Demandes d'accès (ADR 0029).
    pub access: Arc<dyn AccessRequests>,
    /// Signalement aux administrateurs (ADR 0030).
    pub notifier: Arc<dyn Notifier>,
    /// Service interne du proxy pour « j'ai déjà un compte » ; absent : option non proposée.
    pub proxy_internal: Option<access::ProxyInternal>,
    pub audit: Arc<dyn AuditSink>,
    /// Lien « Administration » sur la page « Mes applications », pour `admin_group`.
    pub admin_url: Option<Url>,
    pub admin_group: String,
}

type AppState = Arc<Portal>;

pub fn router(portal: Arc<Portal>) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback).post(saml_acs))
        .route("/saml/metadata", get(saml_metadata))
        .route("/auth/logout", post(logout))
        .route("/auth/logged-out", get(logged_out))
        .route("/apps/{app_id}/disconnect", post(disconnect_app))
        .route("/apps/{app_id}/request", get(access::form))
        .route(
            "/apps/{app_id}/request/credentials",
            post(access::submit_credentials),
        )
        .route(
            "/apps/{app_id}/request/no-account",
            post(access::submit_no_account),
        )
        .route("/static/{name}", get(static_asset))
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
    pub fn descriptors(&self) -> Arc<Vec<AppDescriptor>> {
        self.descriptors.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_descriptors(&self, descriptors: Vec<AppDescriptor>) {
        *self.descriptors.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(descriptors);
    }

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
        match self.idp.start(return_to, now_secs() + LOGIN_TTL.as_secs()) {
            Ok((url, pending)) => match seal(&self.state_cipher, &pending) {
                Some(sealed) => redirect(&url, &[self.login_cookie(&sealed, LOGIN_TTL.as_secs())]),
                None => self.error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Erreur",
                    "Connexion impossible.",
                    "-",
                ),
            },
            Err(e) => {
                tracing::error!(error = %e, "départ de connexion impossible");
                self.error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Erreur",
                    "Connexion impossible.",
                    "-",
                )
            }
        }
    }

    /// Session portail créée après vérification réussie de l'identité, quel que soit le
    /// protocole. Partagé par le retour OIDC (`callback`) et le retour SAML (`saml_acs`).
    async fn finish_login(&self, user: UserIdentity, return_to: &str, cid: &str) -> Response {
        let token = new_token();
        let now = SystemTime::now();
        let session = PortalSession {
            id: hash_token(token.expose_secret()),
            user: user.clone(),
            created_at: now,
            expires_at: now + self.session_ttl,
        };
        let event = AuditEvent::new(AuditAction::PortalLogin, AuditOutcome::Success)
            .actor(&user)
            .correlation(cid);
        // L'audit fait partie de l'opération : pas de session sans trace.
        let stored = async {
            self.audit.record(event).await?;
            self.sessions.create_portal_session(session).await
        };
        if let Err(e) = stored.await {
            tracing::error!(correlation_id = %cid, error = %e, "création de la session portail impossible");
            return self.error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service indisponible",
                "Réessayez dans quelques instants.",
                cid,
            );
        }
        tracing::info!(correlation_id = %cid, user = %user.user_key, "session portail créée");
        let set = self.cookie.set(token.expose_secret(), self.session_ttl.as_secs());
        redirect(return_to, &[set, self.login_cookie("", 0)])
    }

    async fn reject_login(&self, cid: &str, reason: &str) -> Response {
        let _ = self
            .audit
            .record(
                AuditEvent::new(AuditAction::PortalLogin, AuditOutcome::Failure)
                    .correlation(cid)
                    .reason(reason),
            )
            .await;
        let mut resp = self.error(
            StatusCode::UNAUTHORIZED,
            "Connexion refusée",
            "Votre identité n'a pas pu être vérifiée.",
            cid,
        );
        if let Ok(v) = HeaderValue::from_str(&self.login_cookie("", 0)) {
            resp.headers_mut().append(SET_COOKIE, v);
        }
        resp
    }
}

#[derive(Deserialize)]
struct HomeQuery {
    /// Code d'un message de retour d'une demande d'accès (liste fixe, voir `catalog::notice_text`).
    request: Option<String>,
}

async fn home(State(p): State<AppState>, headers: HeaderMap, Query(q): Query<HomeQuery>) -> Response {
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
    let requests = match p.access.open_for_user(&session.user.user_key).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, correlation_id = %cid, "demandes d'accès illisibles");
            Vec::new()
        }
    };
    let descriptors = p.descriptors();
    let tiles = catalog::tiles(&descriptors, &session.user, &accounts, &requests);
    let admin_url = p
        .admin_url
        .as_ref()
        .filter(|_| session.user.groups.contains(&p.admin_group))
        .map(Url::as_str);
    let html = catalog::render(
        &session.user,
        &tiles,
        p.public_url.scheme(),
        p.public_url.as_str(),
        admin_url,
        q.request.as_deref(),
    );
    ([(CACHE_CONTROL, "no-store")], Html(html)).into_response()
}

/// Force la déconnexion d'une seule appli depuis « Mes applications » : supprime la
/// session applicative stockée, sans appeler l'appli elle-même. Le prochain accès
/// déclenche un nouveau rejeu (même mécanisme qu'une session expirée).
async fn disconnect_app(
    State(p): State<AppState>,
    Path(app_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let cid = correlation_id(&headers);
    let Some(session) = p.current_session(&headers).await else {
        return p.start_login(p.public_url.to_string());
    };
    if !p.descriptors().iter().any(|d| d.metadata.id == app_id) {
        return p.error(
            StatusCode::NOT_FOUND,
            "Application inconnue",
            "Cette application n'existe pas.",
            &cid,
        );
    }
    let event = AuditEvent::new(AuditAction::AppLogout, AuditOutcome::Success)
        .actor(&session.user)
        .app(&app_id)
        .correlation(&cid)
        .reason("manual_from_portal");
    if let Err(e) = p.sessions.delete_app_session(&session.id, &app_id).await {
        tracing::error!(correlation_id = %cid, app_id = %app_id, error = %e, "déconnexion de l'appli impossible");
    } else if let Err(e) = p.audit.record(event).await {
        tracing::error!(correlation_id = %cid, error = %e, "audit de déconnexion d'appli impossible");
    }
    redirect("/", &[])
}

#[derive(Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
}

async fn login(State(p): State<AppState>, Query(q): Query<LoginQuery>) -> Response {
    p.start_login(safe_return_to(
        &p.public_url,
        &p.descriptors(),
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
    let values = headers.get_all(COOKIE).iter().filter_map(|v| v.to_str().ok());
    let pending = cookies::find(values, LOGIN_COOKIE).and_then(|v| unseal(&p.state_cipher, v, now_secs()));
    let state_ok = match (&pending, &q.state) {
        (Some(pending), Some(state)) => constant_time_eq(pending.csrf.as_bytes(), state.as_bytes()),
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
        if let Ok(v) = HeaderValue::from_str(&p.login_cookie("", 0)) {
            resp.headers_mut().append(SET_COOKIE, v);
        }
        return resp;
    };

    match p.idp.finish(Callback::Oidc { code }, &pending).await {
        Ok(user) => p.finish_login(user, &pending.return_to, &cid).await,
        Err(e) => {
            tracing::warn!(correlation_id = %cid, error = %e, "authentification OIDC échouée");
            p.reject_login(&cid, "oidc_error").await
        }
    }
}

#[derive(Deserialize)]
struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

/// Assertion Consumer Service : retour SAML (liaison HTTP-POST).
async fn saml_acs(State(p): State<AppState>, headers: HeaderMap, Form(form): Form<SamlAcsForm>) -> Response {
    let cid = correlation_id(&headers);
    let values = headers.get_all(COOKIE).iter().filter_map(|v| v.to_str().ok());
    let pending = cookies::find(values, LOGIN_COOKIE).and_then(|v| unseal(&p.state_cipher, v, now_secs()));
    let relay_ok = match (&pending, &form.relay_state) {
        (Some(pending), Some(relay)) => constant_time_eq(pending.csrf.as_bytes(), relay.as_bytes()),
        _ => false,
    };
    let Some(pending) = pending.filter(|_| relay_ok) else {
        tracing::warn!(correlation_id = %cid, "retour SAML refusé (RelayState invalide ou absent)");
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
        if let Ok(v) = HeaderValue::from_str(&p.login_cookie("", 0)) {
            resp.headers_mut().append(SET_COOKIE, v);
        }
        return resp;
    };

    match p
        .idp
        .finish(
            Callback::Saml {
                saml_response: form.saml_response,
            },
            &pending,
        )
        .await
    {
        Ok(user) => p.finish_login(user, &pending.return_to, &cid).await,
        Err(e) => {
            tracing::warn!(correlation_id = %cid, error = %e, "authentification SAML échouée");
            p.reject_login(&cid, "saml_error").await
        }
    }
}

/// Métadonnées SP à déclarer chez l'IdP, seulement en protocole SAML.
async fn saml_metadata(State(p): State<AppState>) -> Response {
    match p.idp.saml_metadata_xml() {
        Some(Ok(xml)) => ([(CONTENT_TYPE, "application/samlmetadata+xml")], xml).into_response(),
        Some(Err(e)) => {
            tracing::error!(error = %e, "génération des métadonnées SAML impossible");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn logout(State(p): State<AppState>, headers: HeaderMap) -> Response {
    let cid = correlation_id(&headers);
    let back = p
        .public_url
        .join("auth/logged-out")
        .map(|u| u.to_string())
        .unwrap_or_else(|_| p.public_url.to_string());
    let idp_logout = p.idp.logout_url(&back);
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

/// Logo, favicon, bannière : publics, mis en cache par le navigateur.
async fn static_asset(Path(name): Path<String>) -> Response {
    match sesame_core::html::asset(&name) {
        Some((mime, bytes)) => (
            [(CONTENT_TYPE, mime), (CACHE_CONTROL, "public, max-age=86400")],
            bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn logged_out(State(p): State<AppState>) -> Response {
    logged_out_page(&p, None)
}

fn logged_out_page(p: &Portal, clear_cookie: Option<String>) -> Response {
    let url = p.public_url.as_str();
    let html = sesame_core::html::page(
        "Déconnecté",
        &format!(
            "<div class=\"hero\"><img src=\"{}\" alt=\"Sesame : la clé d'un accès universel\" \
width=\"603\" height=\"359\"><h1>Vous êtes déconnecté</h1>\
<p><a class=\"button\" href=\"{}\">Se reconnecter</a></p></div>",
            sesame_core::html::escape(&sesame_core::html::asset_url(url, "banner.webp")),
            sesame_core::html::escape(url)
        ),
        url,
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
            csrf: "st".into(),
            return_to: "https://x/".into(),
            expires_at: 1_000,
            oidc: Some(crate::oidc::OidcPending {
                nonce: "no".into(),
                pkce_verifier: "verifier-secret".into(),
            }),
            saml: None,
        };
        let sealed = seal(&cipher, &pending).unwrap();
        assert!(!sealed.contains("verifier"));
        assert_eq!(unseal(&cipher, &sealed, 999).unwrap().csrf, "st");
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

    #[tokio::test]
    async fn static_assets_are_served_and_unknown_names_refused() {
        let resp = static_asset(Path("logo-64.png".into())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[CONTENT_TYPE], "image/png");
        assert_eq!(resp.headers()[CACHE_CONTROL], "public, max-age=86400");
        for name in ["inconnu.png", "../Cargo.toml", ""] {
            let resp = static_asset(Path(name.into())).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{name}");
        }
    }
}
