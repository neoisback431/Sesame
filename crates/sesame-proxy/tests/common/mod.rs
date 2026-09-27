// SPDX-License-Identifier: Apache-2.0
//! Banc de test commun : appli simulée (en processus) et proxy branché sur les
//! implémentations en mémoire.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::body::{to_bytes, Body};
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use sesame_core::audit::AuditAction;
use sesame_core::cookies::PortalCookie;
use sesame_core::crypto::hash_token;
use sesame_core::descriptor::AppDescriptor;
use sesame_core::identity::UserIdentity;
use sesame_core::memory::{
    MemoryAccountRegistry, MemoryAuditSink, MemoryDiagnosticStore, MemorySecretStore, MemorySessionStore,
};
use sesame_core::ports::{DiagnosticStore, PortalSession, SessionStore};
use sesame_proxy::replay::Replayer;
use sesame_proxy::{build_client, router, App, Proxy};
use tower::ServiceExt;
use url::Url;

pub const APP_PASSWORD: &str = "Pw-TOP-SECRET-4242";
pub const PORTAL_TOKEN: &str = "portal-token-alice";
pub const PUBLIC_HOST: &str = "app.sesame.test";

// ---------------------------------------------------------------------------
// Appli simulée : formulaire de login avec CSRF, session serveur.

#[derive(Default)]
pub struct MockApp {
    pub csrf: Mutex<HashMap<String, String>>,
    pub sessions: Mutex<HashSet<String>>,
    pub counter: AtomicU32,
    pub logins: AtomicU32,
    /// En-têtes `Cookie` / `Authorization` reçus sur /echo.
    pub seen: Mutex<Vec<String>>,
}

pub type Mock = Arc<MockApp>;

pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    sesame_core::cookies::find(
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok()),
        name,
    )
}

pub fn authed(m: &MockApp, headers: &HeaderMap) -> bool {
    cookie(headers, "APPSESS").is_some_and(|s| m.sessions.lock().unwrap().contains(s))
}

pub async fn login_page(State(m): State<Mock>) -> Response {
    let n = m.counter.fetch_add(1, Ordering::SeqCst);
    let (pre, token) = (format!("pre-{n}"), format!("csrf-{n}"));
    m.csrf.lock().unwrap().insert(pre.clone(), token.clone());
    let html = format!(
        r#"<form id="login" action="/login" method="post">
<input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="lang" value="fr">
<input name="username"><input type="password" name="password"></form>"#
    );
    ([(header::SET_COOKIE, format!("PRE={pre}; HttpOnly"))], Html(html)).into_response()
}

pub async fn login_post(
    State(m): State<Mock>,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let expected = cookie(&headers, "PRE").and_then(|p| m.csrf.lock().unwrap().remove(p));
    if expected.is_none() || expected.as_deref() != f.get("csrf_token").map(String::as_str) {
        return (StatusCode::FORBIDDEN, "csrf").into_response();
    }
    if f.get("lang").map(String::as_str) != Some("fr") {
        return (StatusCode::BAD_REQUEST, "hidden field missing").into_response();
    }
    m.logins.fetch_add(1, Ordering::SeqCst);
    if f.get("username").map(String::as_str) != Some("amartin")
        || f.get("password").map(String::as_str) != Some(APP_PASSWORD)
    {
        // Page d'erreur qui recopie la saisie, comme certaines applis anciennes.
        let body = format!("Identifiants invalides pour {:?}", f.get("password"));
        return (StatusCode::UNAUTHORIZED, Html(body)).into_response();
    }
    let sid = format!("sess-{}", m.counter.fetch_add(1, Ordering::SeqCst));
    m.sessions.lock().unwrap().insert(sid.clone());
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, "/".to_string()),
            (header::SET_COOKIE, format!("APPSESS={sid}; HttpOnly; Path=/")),
        ],
    )
        .into_response()
}

pub fn internal(m: &MockApp) -> String {
    let _ = m;
    INTERNAL.with(|i| i.borrow().clone())
}

thread_local! {
    static INTERNAL: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

pub async fn home(State(m): State<Mock>, headers: HeaderMap) -> Response {
    if !authed(&m, &headers) {
        return Redirect::to("/login").into_response();
    }
    let origin = headers
        .get("x-test-internal")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| internal(&m));
    Html(format!(
        r#"<h1>Bonjour amartin</h1><a href="{origin}/account">compte</a>"#
    ))
    .into_response()
}

pub async fn submit(State(m): State<Mock>, headers: HeaderMap) -> Response {
    if !authed(&m, &headers) {
        return Redirect::to("/login").into_response();
    }
    "submitted".into_response()
}

pub async fn pref(State(m): State<Mock>, headers: HeaderMap) -> Response {
    if !authed(&m, &headers) {
        return Redirect::to("/login").into_response();
    }
    let got = cookie(&headers, "PREF").unwrap_or("none").to_owned();
    ([(header::SET_COOKIE, "PREF=dark; Path=/".to_string())], got).into_response()
}

pub async fn echo(State(m): State<Mock>, headers: HeaderMap) -> Response {
    let mut seen = m.seen.lock().unwrap();
    for name in [header::COOKIE, header::AUTHORIZATION] {
        for v in headers.get_all(&name) {
            seen.push(format!("{name}: {}", v.to_str().unwrap_or("")));
        }
    }
    "ok".into_response()
}

pub async fn logout(State(m): State<Mock>, headers: HeaderMap) -> Response {
    if let Some(s) = cookie(&headers, "APPSESS") {
        m.sessions.lock().unwrap().remove(s);
    }
    Redirect::to("/login").into_response()
}

pub async fn redirect_abs(headers: HeaderMap) -> Response {
    let origin = headers
        .get("x-test-internal")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    (
        StatusCode::FOUND,
        [(header::LOCATION, format!("{origin}/account"))],
    )
        .into_response()
}

/// Jeton de la session en cours, comme une API qu'appellerait le JavaScript de la page.
pub async fn csrf_endpoint(State(m): State<Mock>, headers: HeaderMap) -> Response {
    let token = cookie(&headers, "PRE").and_then(|p| m.csrf.lock().unwrap().get(p).cloned());
    match token {
        Some(t) => axum::Json(serde_json::json!({ "data": { "token": t } })).into_response(),
        None => StatusCode::FORBIDDEN.into_response(),
    }
}

pub async fn spawn_mock() -> (Mock, String) {
    let mock = Mock::default();
    let app = Router::new()
        .route("/login", get(login_page).post(login_post))
        .route("/", get(home))
        .route("/submit", axum::routing::post(submit))
        .route("/pref", get(pref))
        .route("/echo", get(echo))
        .route("/logout", get(logout))
        .route("/redirect-abs", get(redirect_abs))
        .route("/api/csrf-token", get(csrf_endpoint))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (mock, format!("http://{addr}"))
}

// ---------------------------------------------------------------------------
// Banc de test : proxy avec implémentations en mémoire.

pub struct Bench {
    pub proxy: Router,
    /// Accès direct au moteur (rechargement à chaud du catalogue).
    pub engine: Arc<Proxy>,
    pub mock: Mock,
    pub internal: String,
    pub sessions: Arc<MemorySessionStore>,
    pub secrets: Arc<MemorySecretStore>,
    pub accounts: Arc<MemoryAccountRegistry>,
    pub audit: Arc<MemoryAuditSink>,
    pub diagnostics: Arc<MemoryDiagnosticStore>,
}

pub fn descriptor(internal: &str) -> AppDescriptor {
    let yaml = include_str!("../../../../descriptors/fake-app.yaml")
        .replace("http://fake-app:8000", internal)
        .replace("fake-app.sesame.localhost:8443", PUBLIC_HOST)
        .replace("form#login-form", "form#login")
        .replace("FAKEAPPSESSID", "APPSESS");
    AppDescriptor::from_yaml(&yaml).expect("descripteur de test valide")
}

pub fn alice(groups: &[&str]) -> UserIdentity {
    UserIdentity {
        issuer: "https://idp.test".into(),
        subject: "sub-alice".into(),
        user_key: "alice".into(),
        display_name: Some("Alice".into()),
        groups: groups.iter().map(|g| g.to_string()).collect(),
    }
}

pub async fn bench(groups: &[&str], password: &str, with_account: bool) -> Bench {
    bench_with(groups, password, with_account, false).await
}

/// `replay_debug` : diagnostics des rejeux en échec activés (`SESAME_REPLAY_DEBUG`).
pub async fn bench_with(groups: &[&str], password: &str, with_account: bool, replay_debug: bool) -> Bench {
    let (mock, internal) = spawn_mock().await;
    INTERNAL.with(|i| *i.borrow_mut() = internal.clone());
    let d = descriptor(&internal);
    let http = build_client(&d, None).unwrap();
    let sessions = Arc::new(MemorySessionStore::default());
    let secrets = Arc::new(MemorySecretStore::default());
    secrets.insert(
        "fake-app",
        "alice",
        &[("username", "amartin"), ("password", password)],
    );
    let accounts = Arc::new(if with_account {
        MemoryAccountRegistry::with_active(&[("fake-app", "alice")])
    } else {
        MemoryAccountRegistry::default()
    });
    let audit = Arc::new(MemoryAuditSink::default());
    let diagnostics = Arc::new(MemoryDiagnosticStore::default());
    let now = SystemTime::now();
    sessions
        .create_portal_session(PortalSession {
            id: hash_token(PORTAL_TOKEN),
            user: alice(groups),
            created_at: now,
            expires_at: now + Duration::from_secs(3600),
        })
        .await
        .unwrap();
    let proxy = Proxy::new(
        vec![App::new(d, http, "https")],
        Url::parse("https://sesame.test/").unwrap(),
        PortalCookie {
            name: "sesame_session".into(),
            domain: Some("sesame.test".into()),
            secure: true,
        },
        sessions.clone(),
        audit.clone(),
        Replayer {
            secrets: secrets.clone(),
            accounts: accounts.clone(),
            audit: audit.clone(),
            diagnostics: replay_debug.then(|| diagnostics.clone() as Arc<dyn DiagnosticStore>),
        },
        1024 * 1024,
    );
    let engine = Arc::new(proxy);
    Bench {
        proxy: router(engine.clone()),
        engine,
        mock,
        internal,
        sessions,
        secrets,
        accounts,
        audit,
        diagnostics,
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Bench {
    /// Relaie la requête et vérifie l'invariant de non-fuite (mode proxy).
    pub async fn send(&self, req: Request<Body>) -> Reply {
        let reply = self.send_raw(req).await;
        reply.assert_no_leak();
        reply
    }

    /// Comme `send`, sans l'invariant de non-fuite : le mode handoff remet délibérément
    /// l'élément de session au navigateur (ADR 0020).
    pub async fn send_raw(&self, req: Request<Body>) -> Reply {
        let resp = self.proxy.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body =
            String::from_utf8_lossy(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).into_owned();
        Reply {
            status,
            headers,
            body,
        }
    }

    pub async fn get_raw(&self, path: &str) -> Reply {
        self.send_raw(self.request("GET", path).body(Body::empty()).unwrap())
            .await
    }

    pub fn request(&self, method: &str, path: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, PUBLIC_HOST)
            .header(header::COOKIE, format!("sesame_session={PORTAL_TOKEN}; other=1"))
            .header("x-test-internal", &self.internal)
    }

    pub async fn get(&self, path: &str) -> Reply {
        self.send(self.request("GET", path).body(Body::empty()).unwrap())
            .await
    }

    pub fn actions(&self) -> Vec<AuditAction> {
        self.audit.events().iter().map(|e| e.action).collect()
    }
}

impl Reply {
    /// Aucun secret applicatif ni cookie applicatif ne doit atteindre le navigateur.
    pub fn assert_no_leak(&self) {
        assert!(!self.body.contains(APP_PASSWORD), "mot de passe dans le corps");
        assert!(self.headers.get(header::SET_COOKIE).is_none_or(|v| {
            let v = v.to_str().unwrap_or("");
            !v.contains("APPSESS") && !v.contains("PREF") && !v.contains("PRE=")
        }));
        for (name, value) in &self.headers {
            let v = value.to_str().unwrap_or("");
            assert!(!v.contains(APP_PASSWORD), "mot de passe dans l'en-tête {name}");
            assert!(!v.contains("sess-"), "cookie applicatif dans l'en-tête {name}");
        }
    }
}
