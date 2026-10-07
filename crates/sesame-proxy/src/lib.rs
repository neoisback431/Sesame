// SPDX-License-Identifier: Apache-2.0
//! Moteur de proxy Sesame.
//!
//! Pour chaque requête : appli choisie d'après `Host`, session portail vérifiée (sinon
//! redirection vers le portail pour une navigation, `401` pour une sous-ressource),
//! habilitation contrôlée, puis selon `spec.session.mode` :
//!
//! - **proxy** (défaut) : session applicative retrouvée ou obtenue par rejeu, requête relayée
//!   avec le jar de cookies côté serveur. Aucun cookie applicatif n'atteint le navigateur.
//! - **handoff** (ADR 0020) : à la première arrivée, rejeu puis remise de l'élément de session
//!   au navigateur (voir [`handoff`]) ; ensuite, relais où le navigateur porte la session.
//!
//! Dans les deux cas, les cookies propres à Sesame (portail, marqueur de remise) ne sont
//! jamais relayés à l'appli.

pub mod config;
pub mod diagnostic;
pub mod form;
pub mod handoff;
pub mod internal;
pub mod jar;
pub mod matcher;
pub mod replay;
pub mod rewrite;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Request, State};
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use regex::Regex;
use sesame_core::audit::{AuditAction, AuditEvent, AuditOutcome};
use sesame_core::cookies::{self, PortalCookie};
use sesame_core::crypto::hash_token;
use sesame_core::descriptor::{AppDescriptor, LogoutAction, SessionMode};
use sesame_core::html::error_page;
use sesame_core::ports::{AppSession, AuditSink, PortalSession, SessionStore};
use sesame_core::secret::ExposeSecret;
use url::Url;

use crate::jar::Jar;
use crate::matcher::ResponseView;
use crate::replay::{ReplayError, Replayer};

/// Délai minimal entre deux mises à jour de `last_used_at` d'une session applicative.
const TOUCH_INTERVAL: Duration = Duration::from_secs(30);

/// Appli exposée : descripteur et éléments précalculés.
pub struct App {
    pub descriptor: AppDescriptor,
    pub http: reqwest::Client,
    /// Origine interne (`http://app:8000`).
    pub internal_origin: String,
    /// Origine publique (`https://app.sesame.example`).
    pub public_origin: String,
    logout: Vec<Regex>,
}

impl App {
    pub fn new(descriptor: AppDescriptor, http: reqwest::Client, scheme: &str) -> Self {
        let logout = descriptor
            .spec
            .logout
            .paths
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();
        Self {
            internal_origin: rewrite::origin(&descriptor.spec.upstream.base_url).to_owned(),
            public_origin: format!("{scheme}://{}", descriptor.spec.public.host),
            descriptor,
            http,
            logout,
        }
    }

    fn id(&self) -> &str {
        &self.descriptor.metadata.id
    }
}

/// Client HTTP d'une appli : pas de redirection suivie, pas de proxy sortant.
pub fn build_client(d: &AppDescriptor, extra_ca: Option<&[u8]>) -> Result<reqwest::Client, String> {
    let tls = &d.spec.upstream.tls;
    let mut b = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(d.spec.upstream.timeout)
        .danger_accept_invalid_certs(!tls.verify);
    let mut pems = Vec::new();
    if let Some(ca) = extra_ca {
        pems.push(ca.to_vec());
    }
    if let Some(path) = &tls.ca_file {
        pems.push(std::fs::read(path).map_err(|e| format!("{path} : {e}"))?);
    }
    for pem in pems {
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| e.to_string())?;
        b = b.add_root_certificate(cert);
    }
    b.build().map_err(|e| e.to_string())
}

/// Verrou de rejeu d'un couple (session portail, appli).
type ReplayLock = Arc<tokio::sync::Mutex<()>>;

/// Applis par nom d'hôte public (`host[:port]`), remplacées d'un bloc au rechargement.
type AppMap = Arc<HashMap<String, Arc<App>>>;

pub struct Proxy {
    apps: RwLock<AppMap>,
    pub portal_url: Url,
    pub cookie: PortalCookie,
    pub sessions: Arc<dyn SessionStore>,
    pub audit: Arc<dyn AuditSink>,
    pub replayer: Replayer,
    pub max_body_bytes: usize,
    locks: Mutex<HashMap<(String, String), ReplayLock>>,
}

impl Proxy {
    pub fn new(
        apps: Vec<App>,
        portal_url: Url,
        cookie: PortalCookie,
        sessions: Arc<dyn SessionStore>,
        audit: Arc<dyn AuditSink>,
        replayer: Replayer,
        max_body_bytes: usize,
    ) -> Self {
        Self {
            apps: RwLock::new(index(apps)),
            portal_url,
            cookie,
            sessions,
            audit,
            replayer,
            max_body_bytes,
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Remplace le catalogue (rechargement à chaud). Les requêtes en cours gardent
    /// l'appli qu'elles ont déjà résolue.
    pub fn set_apps(&self, apps: Vec<App>) {
        *self.apps.write().unwrap_or_else(|e| e.into_inner()) = index(apps);
    }

    pub fn app(&self, host: &str) -> Option<Arc<App>> {
        self.apps
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(host)
            .cloned()
    }

    /// Appli par identifiant (service interne des demandes d'accès, ADR 0029).
    pub fn app_by_id(&self, id: &str) -> Option<Arc<App>> {
        self.apps
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find(|a| a.id() == id)
            .cloned()
    }

    pub fn app_count(&self) -> usize {
        self.apps.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

fn index(apps: Vec<App>) -> AppMap {
    Arc::new(
        apps.into_iter()
            .map(|a| (a.descriptor.spec.public.host.clone(), Arc::new(a)))
            .collect(),
    )
}

/// Construit les applis d'un catalogue ; une appli dont le client HTTP ne peut être
/// construit (CA illisible…) est écartée et signalée.
pub fn build_apps(
    descriptors: Vec<AppDescriptor>,
    extra_ca: Option<&[u8]>,
    scheme: &str,
) -> (Vec<App>, Vec<String>) {
    let mut apps = Vec::new();
    let mut rejected = Vec::new();
    for d in descriptors {
        match build_client(&d, extra_ca) {
            Ok(http) => apps.push(App::new(d, http, scheme)),
            Err(e) => rejected.push(format!("{} : client HTTP : {e}", d.metadata.id)),
        }
    }
    (apps, rejected)
}

pub fn router(proxy: Arc<Proxy>) -> Router {
    let health = |State(p): State<Arc<Proxy>>| async move {
        Json(serde_json::json!({ "status": "ok", "apps": p.app_count() }))
    };
    Router::new()
        .route("/.sesame/healthz", get(health))
        .route("/healthz", get(health))
        .fallback(handle)
        .with_state(proxy)
}

fn correlation_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 64 && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// En-têtes jamais relayés du navigateur vers l'appli.
const DROP_REQUEST: &[&str] = &[
    "host",
    "cookie",
    "authorization",
    "proxy-authorization",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    // Corps non compressé : nécessaire pour détecter l'expiration et réécrire les URLs.
    "accept-encoding",
];

/// En-têtes jamais relayés de l'appli vers le navigateur.
const DROP_RESPONSE: &[&str] = &[
    "set-cookie",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Comment la session applicative est fournie à l'appli lors du relais.
enum Injection<'a> {
    /// Mode proxy : cookies applicatifs côté serveur, Authorization du navigateur retiré.
    Server(&'a Jar),
    /// Mode handoff transparent : le navigateur porte la session ; ses cookies (hors cookie
    /// du portail) et son Authorization sont relayés, rien n'est injecté.
    Browser,
}

enum UpstreamBody {
    Full(Bytes),
    Stream(reqwest::Response),
}

struct Upstream {
    status: StatusCode,
    headers: HeaderMap,
    set_cookies: Vec<String>,
    body: UpstreamBody,
}

impl Upstream {
    fn location(&self) -> Option<&str> {
        self.headers.get(header::LOCATION).and_then(|v| v.to_str().ok())
    }

    fn content_type(&self) -> Option<&str> {
        self.headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
    }
}

struct Ctx<'a> {
    app: &'a App,
    session: &'a PortalSession,
    cid: String,
}

impl Proxy {
    fn page(&self, status: StatusCode, title: &str, message: &str, cid: &str) -> Response {
        let html = error_page(title, message, cid, self.portal_url.as_str());
        (status, [(header::CACHE_CONTROL, "no-store")], Html(html)).into_response()
    }

    fn event(&self, ctx: &Ctx<'_>, action: AuditAction, outcome: AuditOutcome) -> AuditEvent {
        AuditEvent::new(action, outcome)
            .actor(&ctx.session.user)
            .app(ctx.app.id())
            .correlation(&ctx.cid)
    }

    async fn portal_session(&self, headers: &HeaderMap) -> Result<Option<PortalSession>, ()> {
        let values = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok());
        let Some(token) = cookies::find(values, &self.cookie.name) else {
            return Ok(None);
        };
        self.sessions
            .get_portal_session(&hash_token(token))
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "magasin de sessions indisponible");
            })
    }

    /// Mode handoff (ADR 0020), première arrivée : rejeu côté serveur, remise de l'élément de
    /// session au navigateur (cookies en `Set-Cookie`, valeurs de stockage local via une page
    /// dédiée) et d'un marqueur, puis redirection vers `return_path`. Les requêtes suivantes
    /// (marqueur présent) sont relayées de façon transparente.
    async fn handoff(&self, ctx: &Ctx<'_>, return_path: &str) -> Response {
        let spec = &ctx.app.descriptor.spec;
        let handoff = match &spec.session.handoff {
            Some(h) => h,
            None => return self.unavailable(&ctx.cid), // écarté par validate()
        };
        let session = match self
            .replayer
            .replay(&ctx.app.http, &ctx.app.descriptor, &ctx.session.user, &ctx.cid)
            .await
        {
            Ok(s) => s,
            Err(e) => return self.replay_error(&e, &ctx.cid),
        };
        let values = match handoff::local_storage_values(handoff, session.login_body.as_deref()) {
            Ok(v) => v,
            Err(reason) => {
                tracing::warn!(app = ctx.app.id(), correlation_id = %ctx.cid, reason, "remise impossible");
                let _ = self
                    .audit
                    .record(
                        self.event(ctx, AuditAction::SessionHandoff, AuditOutcome::Failure)
                            .reason(reason),
                    )
                    .await;
                return self.page(
                    StatusCode::BAD_GATEWAY,
                    "Connexion impossible",
                    "La connexion automatique à l'application a échoué. Contactez votre administrateur.",
                    &ctx.cid,
                );
            }
        };

        let cookie_headers =
            handoff::set_cookie_headers(handoff, &session.jar, spec.session.max_ttl.as_secs());

        if self
            .audit
            .record(self.event(ctx, AuditAction::SessionHandoff, AuditOutcome::Success))
            .await
            .is_err()
        {
            return self.unavailable(&ctx.cid);
        }

        // Retour vers l'URL demandée (marqueur désormais présent → relais transparent).
        let target = format!("{}{}", ctx.app.public_origin, return_path);
        let mut resp = if values.is_empty() {
            let status = StatusCode::from_u16(handoff.redirect_status).unwrap_or(StatusCode::SEE_OTHER);
            redirect(status, &target)
        } else {
            let html = handoff::page(&values, return_path, self.portal_url.as_str());
            ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response()
        };
        for c in cookie_headers {
            if let Ok(v) = HeaderValue::from_str(&c) {
                resp.headers_mut().append(header::SET_COOKIE, v);
            }
        }
        resp
    }

    fn login_redirect(&self, app: &App, path_and_query: &str) -> Response {
        let return_to = format!("{}{}", app.public_origin, path_and_query);
        let mut url = self
            .portal_url
            .join("auth/login")
            .unwrap_or_else(|_| self.portal_url.clone());
        url.query_pairs_mut().append_pair("return_to", &return_to);
        redirect(StatusCode::FOUND, url.as_str())
    }

    fn replay_error(&self, err: &ReplayError, cid: &str) -> Response {
        match err {
            ReplayError::AccessDenied("account_pending") => self.page(
                StatusCode::FORBIDDEN,
                "Demande en cours",
                "Votre demande d'accès est en attente de validation par un administrateur.",
                cid,
            ),
            ReplayError::AccessDenied(_) => self.page(
                StatusCode::FORBIDDEN,
                "Accès refusé",
                "Vous n'avez pas de compte actif pour cette application.",
                cid,
            ),
            ReplayError::Rejected(_) => self.page(
                StatusCode::BAD_GATEWAY,
                "Connexion impossible",
                "La connexion automatique à l'application a échoué. Contactez votre administrateur.",
                cid,
            ),
            ReplayError::Upstream => self.page(
                StatusCode::BAD_GATEWAY,
                "Application indisponible",
                "L'application ne répond pas. Réessayez dans quelques instants.",
                cid,
            ),
            ReplayError::SecretUnavailable | ReplayError::Audit => self.page(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service indisponible",
                "Réessayez dans quelques instants.",
                cid,
            ),
        }
    }

    fn unavailable(&self, cid: &str) -> Response {
        self.page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service indisponible",
            "Réessayez dans quelques instants.",
            cid,
        )
    }

    /// Session applicative existante, ou rejeu (un seul à la fois par couple session / appli).
    async fn app_session(&self, ctx: &Ctx<'_>) -> Result<AppSession, Response> {
        if let Some(s) = self.fresh_app_session(ctx).await? {
            return Ok(s);
        }
        let key = (ctx.session.id.clone(), ctx.app.id().to_owned());
        let lock = self
            .locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_default()
            .clone();
        let result = async {
            let _guard = lock.lock().await;
            // Une requête concurrente a peut-être déjà rejoué pendant l'attente.
            if let Some(s) = self.fresh_app_session(ctx).await? {
                return Ok(s);
            }
            let jar = self
                .replayer
                .replay(&ctx.app.http, &ctx.app.descriptor, &ctx.session.user, &ctx.cid)
                .await
                .map_err(|e| self.replay_error(&e, &ctx.cid))?
                .jar;
            let now = SystemTime::now();
            let max = now + ctx.app.descriptor.spec.session.max_ttl;
            let session = AppSession {
                portal_session_id: ctx.session.id.clone(),
                app_id: ctx.app.id().to_owned(),
                cookies: jar.into_cookies(),
                created_at: now,
                last_used_at: now,
                expires_at: max.min(ctx.session.expires_at),
            };
            self.sessions.put_app_session(session.clone()).await.map_err(|e| {
                tracing::error!(error = %e, correlation_id = %ctx.cid, "enregistrement de la session applicative impossible");
                self.unavailable(&ctx.cid)
            })?;
            Ok(session)
        }
        .await;
        let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
        if Arc::strong_count(&lock) <= 2 {
            locks.remove(&key);
        }
        result
    }

    async fn fresh_app_session(&self, ctx: &Ctx<'_>) -> Result<Option<AppSession>, Response> {
        let (sid, app_id) = (&ctx.session.id, ctx.app.id());
        let found = self.sessions.get_app_session(sid, app_id).await.map_err(|e| {
            tracing::error!(error = %e, correlation_id = %ctx.cid, "lecture de la session applicative impossible");
            self.unavailable(&ctx.cid)
        })?;
        let Some(s) = found else { return Ok(None) };
        // Un rejeu réussi garantit la présence de tous les `session.cookies` (replay.rs). Si l'un
        // manque, l'appli l'a effacé (`Set-Cookie` vide ou expiré) : c'est une déconnexion faite
        // dans l'appli elle-même, hors des chemins `spec.logout`. La session est morte : sans
        // cela, les requêtes partiraient sans cookie et l'utilisateur resterait sur la page de
        // login de l'appli, sans moyen de se reconnecter.
        let required = &ctx.app.descriptor.spec.session.cookies;
        if !required
            .iter()
            .all(|name| s.cookies.iter().any(|c| &c.name == name))
        {
            tracing::info!(
                app = ctx.app.id(),
                correlation_id = %ctx.cid,
                "cookie de session effacé par l'appli : nouvelle connexion"
            );
            let _ = self.sessions.delete_app_session(sid, app_id).await;
            return Ok(None);
        }
        let now = SystemTime::now();
        let idle = ctx.app.descriptor.spec.session.idle_ttl;
        if s.last_used_at + idle <= now {
            let _ = self.sessions.delete_app_session(sid, app_id).await;
            return Ok(None);
        }
        if now.duration_since(s.last_used_at).unwrap_or_default() >= TOUCH_INTERVAL {
            let _ = self.sessions.touch_app_session(sid, app_id, now).await;
        }
        Ok(Some(s))
    }

    /// Relaie la requête à l'appli. `check_expiry` : le corps est lu en entier si les
    /// conditions d'expiration en ont besoin (sinon il est diffusé tel quel).
    async fn forward(
        &self,
        app: &App,
        parts: &Parts,
        body: &Bytes,
        inject: Injection<'_>,
        check_expiry: bool,
    ) -> Result<Upstream, reqwest::Error> {
        let spec = &app.descriptor.spec;
        let url = format!("{}{}", app.internal_origin, path_and_query(parts));
        let mut req = app.http.request(parts.method.clone(), url);
        // En mode handoff, le navigateur porte lui-même la session : ses cookies (hors cookies
        // propres à Sesame) et son en-tête Authorization sont relayés tels quels.
        let passthrough = matches!(inject, Injection::Browser);
        let own_cookies = [self.cookie.name.as_str(), handoff::MARKER];
        for (name, value) in &parts.headers {
            let drop = DROP_REQUEST.contains(&name.as_str())
                && !(passthrough && (name == header::COOKIE || name == header::AUTHORIZATION));
            if drop {
                continue;
            }
            if name == header::COOKIE {
                if let Some(v) = value
                    .to_str()
                    .ok()
                    .and_then(|c| cookies::without(c, &own_cookies))
                    .and_then(|c| HeaderValue::from_str(&c).ok())
                {
                    req = req.header(header::COOKIE, v);
                }
                continue;
            }
            req = req.header(name, value);
        }
        if let Some(h) = &spec.upstream.host_header {
            req = req.header(header::HOST, h);
        }
        if let Injection::Server(jar) = inject {
            if let Some(c) = jar.header() {
                req = req.header(header::COOKIE, c.expose_secret());
            }
        }
        if !body.is_empty() {
            req = req.body(body.clone());
        }
        let resp = req.send().await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let set_cookies = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        let mut upstream = Upstream {
            status,
            headers,
            set_cookies,
            body: UpstreamBody::Stream(resp),
        };
        let rw = &spec.rewrite;
        let needs_body = (check_expiry && matcher::needs_body(&spec.expiry))
            || (rw.body_absolute_urls
                && rewrite::content_type_matches(upstream.content_type(), &rw.content_types));
        if needs_body {
            if let UpstreamBody::Stream(resp) =
                std::mem::replace(&mut upstream.body, UpstreamBody::Full(Bytes::new()))
            {
                upstream.body = UpstreamBody::Full(resp.bytes().await?);
            }
        }
        Ok(upstream)
    }

    fn expired(&self, app: &App, upstream: &Upstream, jar_names: &[String]) -> bool {
        let body = match &upstream.body {
            UpstreamBody::Full(b) => std::str::from_utf8(b).ok(),
            UpstreamBody::Stream(_) => None,
        };
        let view = ResponseView {
            status: upstream.status.as_u16(),
            location: upstream.location(),
            set_cookie_names: jar_names,
            body,
        };
        matcher::any(&app.descriptor.spec.expiry, &view)
    }

    /// `keep_set_cookie` : en mode handoff transparent, les `Set-Cookie` de l'appli sont
    /// relayés au navigateur (il porte lui-même la session) ; sinon ils sont retenus.
    fn to_browser(&self, app: &App, upstream: Upstream, keep_set_cookie: bool) -> Response {
        let rw = &app.descriptor.spec.rewrite;
        let mut headers = HeaderMap::new();
        for (name, value) in &upstream.headers {
            if DROP_RESPONSE.contains(&name.as_str()) && !(keep_set_cookie && name == header::SET_COOKIE) {
                continue;
            }
            if name == header::LOCATION && rw.location {
                if let Some(v) = value
                    .to_str()
                    .ok()
                    .and_then(|l| rewrite::location(l, &app.internal_origin, &app.public_origin))
                    .and_then(|l| HeaderValue::from_str(&l).ok())
                {
                    headers.append(name, v);
                    continue;
                }
            }
            headers.append(name, value.clone());
        }
        let body = match upstream.body {
            UpstreamBody::Full(bytes) => {
                let rewritten = (rw.body_absolute_urls
                    && rewrite::content_type_matches(
                        upstream
                            .headers
                            .get(header::CONTENT_TYPE)
                            .and_then(|v| v.to_str().ok()),
                        &rw.content_types,
                    ))
                .then(|| std::str::from_utf8(&bytes).ok())
                .flatten()
                .and_then(|text| rewrite::body(text, &app.internal_origin, &app.public_origin));
                if rewritten.is_some() {
                    headers.remove(header::CONTENT_LENGTH);
                }
                Body::from(rewritten.map(Bytes::from).unwrap_or(bytes))
            }
            UpstreamBody::Stream(resp) => Body::from_stream(resp.bytes_stream()),
        };
        let mut resp = Response::new(body);
        *resp.status_mut() = upstream.status;
        *resp.headers_mut() = headers;
        resp
    }

    /// Met à jour le jar avec les `Set-Cookie` de l'appli (jamais transmis au navigateur).
    async fn absorb_cookies(&self, ctx: &Ctx<'_>, session: &mut AppSession, set_cookies: &[String]) {
        if set_cookies.is_empty() {
            return;
        }
        let mut jar = Jar::from_cookies(std::mem::take(&mut session.cookies));
        let (_, changed) = jar.apply(set_cookies.iter().map(String::as_str));
        session.cookies = jar.into_cookies();
        if changed {
            session.last_used_at = SystemTime::now();
            if let Err(e) = self.sessions.put_app_session(session.clone()).await {
                tracing::warn!(error = %e, correlation_id = %ctx.cid, "jar de cookies non mis à jour");
            }
        }
    }
}

fn path_and_query(parts: &Parts) -> &str {
    parts.uri.path_and_query().map_or("/", |pq| pq.as_str())
}

/// Noms des cookies posés par une réponse de l'appli (pour les conditions `cookie_set`).
fn set_cookie_names(upstream: &Upstream) -> Vec<String> {
    Jar::default()
        .apply(upstream.set_cookies.iter().map(String::as_str))
        .0
}

/// La requête est-elle une navigation de premier niveau (barre d'adresse, clic sur un lien) ?
/// `Sec-Fetch-Mode: navigate` le dit ; à défaut (vieux navigateur), on retombe sur un `Accept`
/// qui demande du HTML. Les sous-ressources (`cors`, `no-cors`, images, fetch) ne le sont pas.
fn is_navigation(headers: &HeaderMap) -> bool {
    match headers.get("sec-fetch-mode").and_then(|v| v.to_str().ok()) {
        Some(mode) => mode.eq_ignore_ascii_case("navigate"),
        None => headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("text/html")),
    }
}

fn redirect(status: StatusCode, to: &str) -> Response {
    let mut resp = status.into_response();
    if let Ok(v) = HeaderValue::from_str(to) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn idempotent(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

async fn handle(State(p): State<Arc<Proxy>>, req: Request) -> Response {
    let cid = correlation_id(req.headers());
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let Some(app) = p.app(&host) else {
        return p.page(
            StatusCode::NOT_FOUND,
            "Application inconnue",
            "Cette adresse ne correspond à aucune application.",
            &cid,
        );
    };
    let (parts, body) = req.into_parts();

    let session = match p.portal_session(&parts.headers).await {
        Ok(Some(s)) => s,
        // Rediriger vers le login n'a de sens que pour une navigation. Une sous-ressource
        // (manifest, image, fetch/XHR) recevrait une redirection cross-origin que le
        // navigateur bloque en CORS : on répond 401, sans redirection.
        Ok(None) if is_navigation(&parts.headers) => {
            return p.login_redirect(&app, path_and_query(&parts));
        }
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::CACHE_CONTROL, "no-store")],
                "authentication required",
            )
                .into_response();
        }
        Err(()) => return p.unavailable(&cid),
    };
    let ctx = Ctx {
        app: &app,
        session: &session,
        cid,
    };

    if !app
        .descriptor
        .spec
        .access
        .allows(&session.user.user_key, &session.user.groups)
    {
        let event = p
            .event(&ctx, AuditAction::AccessDenied, AuditOutcome::Failure)
            .reason("not_authorized");
        if p.audit.record(event).await.is_err() {
            return p.unavailable(&ctx.cid);
        }
        return p.page(
            StatusCode::FORBIDDEN,
            "Accès refusé",
            "Vous n'êtes pas habilité à utiliser cette application.",
            &ctx.cid,
        );
    }

    let Ok(body) = to_bytes(body, p.max_body_bytes).await else {
        return p.page(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Requête trop volumineuse",
            "La requête dépasse la taille autorisée.",
            &ctx.cid,
        );
    };

    match app.descriptor.spec.session.mode {
        SessionMode::Proxy => p.serve_proxy(&ctx, &parts, &body).await,
        SessionMode::Handoff => p.serve_handoff(&ctx, &parts, &body).await,
    }
}

impl Proxy {
    fn upstream_error(&self, ctx: &Ctx<'_>, e: reqwest::Error) -> Response {
        tracing::warn!(
            app = ctx.app.id(),
            correlation_id = %ctx.cid,
            error = %replay::describe_upstream_error(e),
            "appli injoignable"
        );
        self.replay_error(&ReplayError::Upstream, &ctx.cid)
    }

    /// Mode handoff (ADR 0020), sans chemin dédié. Sans marqueur : remise (rejeu, élément de
    /// session et marqueur posés au navigateur, retour à l'URL demandée). Avec marqueur :
    /// relais où le navigateur porte la session. Si l'appli signale alors une session expirée
    /// sur une navigation, nouvelle remise (reconnexion automatique).
    async fn serve_handoff(&self, ctx: &Ctx<'_>, parts: &Parts, body: &Bytes) -> Response {
        let renew = is_navigation(&parts.headers) && idempotent(&parts.method);
        // Marqueur présent mais cookie remis effacé par l'appli (déconnexion faite dans l'appli) :
        // sur une navigation, nouvelle remise, sans règle `expiry` à écrire.
        let cookies_gone = renew
            && ctx
                .app
                .descriptor
                .spec
                .session
                .handoff
                .as_ref()
                .is_some_and(|h| !handoff::cookies_present(&parts.headers, h));
        if !handoff::done(&parts.headers) || cookies_gone {
            if cookies_gone {
                tracing::info!(app = ctx.app.id(), correlation_id = %ctx.cid, "cookie remis effacé par l'appli : nouvelle remise");
            }
            return self.handoff(ctx, path_and_query(parts)).await;
        }
        let upstream = match self
            .forward(ctx.app, parts, body, Injection::Browser, renew)
            .await
        {
            Ok(u) => u,
            Err(e) => return self.upstream_error(ctx, e),
        };
        if renew && self.expired(ctx.app, &upstream, &set_cookie_names(&upstream)) {
            tracing::info!(app = ctx.app.id(), correlation_id = %ctx.cid, "session remise expirée");
            if self
                .audit
                .record(self.event(ctx, AuditAction::AppSessionExpired, AuditOutcome::Success))
                .await
                .is_err()
            {
                return self.unavailable(&ctx.cid);
            }
            return self.handoff(ctx, path_and_query(parts)).await;
        }
        self.to_browser(ctx.app, upstream, true)
    }

    /// Mode proxy : session applicative côté serveur, rejeu à la demande, expiration détectée
    /// sur les réponses relayées (rejeu puis répétition si la requête est idempotente).
    async fn serve_proxy(&self, ctx: &Ctx<'_>, parts: &Parts, body: &Bytes) -> Response {
        let app = ctx.app;
        let session = ctx.session;
        let mut app_session = match self.app_session(ctx).await {
            Ok(s) => s,
            Err(resp) => return resp,
        };

        let jar = Jar::from_cookies(app_session.cookies.clone());
        let mut upstream = match self
            .forward(app, parts, body, Injection::Server(&jar), true)
            .await
        {
            Ok(u) => u,
            Err(e) => return self.upstream_error(ctx, e),
        };

        if app.logout.iter().any(|r| r.is_match(parts.uri.path())) {
            let _ = self.sessions.delete_app_session(&session.id, app.id()).await;
            let _ = self
                .audit
                .record(self.event(ctx, AuditAction::AppLogout, AuditOutcome::Success))
                .await;
            if app.descriptor.spec.logout.action == LogoutAction::PortalLogout {
                let _ = self.sessions.delete_portal_session(&session.id).await;
                let _ = self
                    .audit
                    .record(self.event(ctx, AuditAction::PortalLogout, AuditOutcome::Success))
                    .await;
                let mut resp = redirect(StatusCode::FOUND, self.portal_url.as_str());
                if let Ok(v) = HeaderValue::from_str(&self.cookie.clear()) {
                    resp.headers_mut().append(header::SET_COOKIE, v);
                }
                return resp;
            }
            return self.to_browser(app, upstream, false);
        }

        if self.expired(app, &upstream, &set_cookie_names(&upstream)) {
            tracing::info!(app = app.id(), correlation_id = %ctx.cid, "session applicative expirée");
            let _ = self.sessions.delete_app_session(&session.id, app.id()).await;
            if self
                .audit
                .record(self.event(ctx, AuditAction::AppSessionExpired, AuditOutcome::Success))
                .await
                .is_err()
            {
                return self.unavailable(&ctx.cid);
            }
            app_session = match self.app_session(ctx).await {
                Ok(s) => s,
                Err(resp) => return resp,
            };
            if !idempotent(&parts.method) {
                // Pas de nouvelle soumission : retour à la page d'origine.
                let back = parts
                    .headers
                    .get(header::REFERER)
                    .and_then(|r| r.to_str().ok())
                    .filter(|r| r.starts_with(&format!("{}/", app.public_origin)))
                    .map_or_else(|| format!("{}/", app.public_origin), str::to_owned);
                return redirect(StatusCode::SEE_OTHER, &back);
            }
            let jar = Jar::from_cookies(app_session.cookies.clone());
            upstream = match self
                .forward(app, parts, body, Injection::Server(&jar), true)
                .await
            {
                Ok(u) => u,
                Err(e) => return self.upstream_error(ctx, e),
            };
            if self.expired(app, &upstream, &set_cookie_names(&upstream)) {
                tracing::warn!(app = app.id(), correlation_id = %ctx.cid, "session expirée juste après le rejeu");
                let _ = self.sessions.delete_app_session(&session.id, app.id()).await;
                return self.replay_error(&ReplayError::Rejected("expired_after_replay"), &ctx.cid);
            }
        }

        let set_cookies = std::mem::take(&mut upstream.set_cookies);
        self.absorb_cookies(ctx, &mut app_session, &set_cookies).await;
        self.to_browser(app, upstream, false)
    }
}
