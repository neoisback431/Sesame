// SPDX-License-Identifier: Apache-2.0
//! Routes de demande d'accès du portail (ADR 0029), avec un faux service interne du proxy.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, LOCATION};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use sesame_core::audit::{AuditAction, AuditOutcome};
use sesame_core::cookies::PortalCookie;
use sesame_core::crypto::{hash_token, CookieCipher};
use sesame_core::descriptor::AppDescriptor;
use sesame_core::identity::UserIdentity;
use sesame_core::memory::{
    MemoryAccessRequests, MemoryAccountRegistry, MemoryAuditSink, MemoryNotifier, MemorySessionStore,
};
use sesame_core::ports::{
    AccessRequestKind, AccessRequests, AccountRegistry, AccountStatus, PortalSession, SessionStore,
};
use sesame_core::secret::SecretString;
use tower::ServiceExt;
use url::Url;

use crate::access::ProxyInternal;
use crate::idp::IdentityProvider;
use crate::{router, Portal};

const FAKE_APP: &str = include_str!("../../../descriptors/fake-app.yaml");
const TOKEN: &str = "portal-token-alice";
const INTERNAL_TOKEN: &str = "internal-token-XYZ";
const APP_PASSWORD: &str = "Pw-TOP-SECRET-4242";

/// Ce que le faux service interne a reçu, et ce qu'il répond.
#[derive(Default)]
struct FakeProxy {
    seen: Mutex<Vec<(Option<String>, serde_json::Value)>>,
    answer: Mutex<u16>,
}

async fn fake_internal(
    State(f): State<Arc<FakeProxy>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> StatusCode {
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    f.seen.lock().unwrap().push((auth, body));
    StatusCode::from_u16(*f.answer.lock().unwrap()).unwrap()
}

struct Bench {
    router: Router,
    fake: Arc<FakeProxy>,
    accounts: Arc<MemoryAccountRegistry>,
    requests: Arc<MemoryAccessRequests>,
    audit: Arc<MemoryAuditSink>,
    notifier: Arc<MemoryNotifier>,
}

fn alice(groups: &[&str]) -> UserIdentity {
    UserIdentity {
        issuer: "https://idp.test".into(),
        subject: "sub-alice".into(),
        user_key: "alice".into(),
        display_name: Some("Alice".into()),
        groups: groups.iter().map(|g| g.to_string()).collect(),
    }
}

async fn bench(groups: &[&str], with_internal: bool) -> Bench {
    let fake = Arc::new(FakeProxy::default());
    *fake.answer.lock().unwrap() = 200;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/internal/access-requests", post(fake_internal))
        .with_state(fake.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let sessions = Arc::new(MemorySessionStore::default());
    let now = SystemTime::now();
    sessions
        .create_portal_session(PortalSession {
            id: hash_token(TOKEN),
            user: alice(groups),
            created_at: now,
            expires_at: now + Duration::from_secs(3600),
        })
        .await
        .unwrap();
    let accounts = Arc::new(MemoryAccountRegistry::default());
    let requests = Arc::new(MemoryAccessRequests::new(accounts.clone()));
    let audit = Arc::new(MemoryAuditSink::default());
    let notifier = Arc::new(MemoryNotifier::default());
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
    let portal = Portal {
        public_url: Url::parse("https://sesame.test/").unwrap(),
        cookie: PortalCookie {
            name: "sesame_session".into(),
            domain: None,
            secure: true,
        },
        session_ttl: Duration::from_secs(3600),
        descriptors: RwLock::new(Arc::new(vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()])),
        idp: IdentityProvider::Saml(crate::saml::tests::setup().saml),
        state_cipher: CookieCipher::from_base64(&SecretString::from(key)).unwrap(),
        sessions,
        accounts: accounts.clone(),
        access: requests.clone(),
        notifier: notifier.clone(),
        proxy_internal: with_internal.then(|| ProxyInternal {
            url: Url::parse(&format!("http://{addr}/")).unwrap(),
            token: SecretString::from(INTERNAL_TOKEN),
            http: crate::access::internal_client().unwrap(),
        }),
        audit: audit.clone(),
        admin_url: None,
        admin_group: "sesame-admins".into(),
    };
    Bench {
        router: router(Arc::new(portal)),
        fake,
        accounts,
        requests,
        audit,
        notifier,
    }
}

struct Reply {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

impl Bench {
    async fn call(&self, method: &str, path: &str, form: Option<&str>, logged_in: bool) -> Reply {
        let mut req = Request::builder().method(method).uri(path);
        if logged_in {
            req = req.header(COOKIE, format!("sesame_session={TOKEN}"));
        }
        let body = match form {
            Some(f) => {
                req = req.header(CONTENT_TYPE, "application/x-www-form-urlencoded");
                Body::from(f.to_owned())
            }
            None => Body::empty(),
        };
        let resp = self
            .router
            .clone()
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();
        Reply {
            status: resp.status(),
            location: resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            body: String::from_utf8_lossy(&to_bytes(resp.into_body(), usize::MAX).await.unwrap())
                .into_owned(),
        }
    }
}

const GROUPS: &[&str] = &["fake-app-users"];

#[tokio::test]
async fn form_offers_both_options_only_when_the_proxy_relay_exists() {
    let b = bench(GROUPS, true).await;
    let r = b.call("GET", "/apps/fake-app/request", None, true).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("J&#39;ai déjà un compte") || r.body.contains("J'ai déjà un compte"));
    assert!(r.body.contains("action=\"/apps/fake-app/request/credentials\""));
    assert!(r.body.contains("name=\"username\" type=\"text\""));
    assert!(r.body.contains("name=\"password\" type=\"password\""));
    assert!(r.body.contains("action=\"/apps/fake-app/request/no-account\""));

    let b = bench(GROUPS, false).await;
    let r = b.call("GET", "/apps/fake-app/request", None, true).await;
    assert!(
        !r.body.contains("/request/credentials"),
        "option masquée sans relais interne"
    );
    assert!(r.body.contains("/request/no-account"));
}

#[tokio::test]
async fn requests_need_a_session_and_an_entitled_user() {
    let b = bench(GROUPS, true).await;
    for (method, path) in [
        ("GET", "/apps/fake-app/request"),
        ("POST", "/apps/fake-app/request/credentials"),
        ("POST", "/apps/fake-app/request/no-account"),
    ] {
        let r = b.call(method, path, Some("username=a&password=b"), false).await;
        assert_eq!(r.status, StatusCode::FOUND, "{method} {path}");
        assert!(
            r.location.unwrap().contains("idp.example"),
            "renvoi vers le fournisseur d'identité"
        );
    }
    assert!(b.fake.seen.lock().unwrap().is_empty());

    // Non habilité : l'appli n'existe pas pour lui, même réponse qu'une appli inconnue.
    let b = bench(&["autre"], true).await;
    for path in ["/apps/fake-app/request", "/apps/inconnue/request"] {
        assert_eq!(
            b.call("GET", path, None, true).await.status,
            StatusCode::NOT_FOUND
        );
    }
    let r = b
        .call(
            "POST",
            "/apps/fake-app/request/credentials",
            Some("username=a&password=b"),
            true,
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(b.fake.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn credentials_are_relayed_to_the_proxy_and_never_echoed() {
    let b = bench(GROUPS, true).await;
    let form = format!("username=amartin&password={APP_PASSWORD}&admin=oui");
    let r = b
        .call("POST", "/apps/fake-app/request/credentials", Some(&form), true)
        .await;
    assert_eq!(
        (r.status, r.location.as_deref()),
        (StatusCode::FOUND, Some("/?request=credentials"))
    );
    assert!(!r.body.contains(APP_PASSWORD));

    let (auth, body) = {
        let seen = b.fake.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        seen[0].clone()
    };
    assert_eq!(auth.as_deref(), Some(format!("Bearer {INTERNAL_TOKEN}").as_str()));
    assert_eq!(body["app_id"], "fake-app");
    assert_eq!(body["user"]["user_key"], "alice");
    // Seules les clés du descripteur sont transmises.
    assert_eq!(
        body["fields"],
        serde_json::json!({ "username": "amartin", "password": APP_PASSWORD })
    );
    // Le portail n'écrit ni compte ni secret : c'est le proxy qui le fait.
    assert!(b
        .accounts
        .get_account("fake-app", "alice")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn proxy_answers_are_mapped_without_echoing_the_input() {
    for (answer, status, needle) in [
        (422, StatusCode::UNPROCESSABLE_ENTITY, "refusé ces identifiants"),
        (502, StatusCode::BAD_GATEWAY, "injoignable"),
        (501, StatusCode::NOT_IMPLEMENTED, "pas disponible"),
        (500, StatusCode::SERVICE_UNAVAILABLE, "Réessayez"),
    ] {
        let b = bench(GROUPS, true).await;
        *b.fake.answer.lock().unwrap() = answer;
        let form = format!("username=amartin&password={APP_PASSWORD}");
        let r = b
            .call("POST", "/apps/fake-app/request/credentials", Some(&form), true)
            .await;
        assert_eq!(r.status, status, "{answer}");
        assert!(r.body.contains(needle), "{answer} : {}", r.body);
        for leaked in [APP_PASSWORD, "amartin", INTERNAL_TOKEN] {
            assert!(!r.body.contains(leaked), "{leaked} renvoyé au navigateur");
        }
    }
    let b = bench(GROUPS, true).await;
    *b.fake.answer.lock().unwrap() = 409;
    let r = b
        .call(
            "POST",
            "/apps/fake-app/request/credentials",
            Some("username=a&password=b"),
            true,
        )
        .await;
    assert_eq!(r.location.as_deref(), Some("/?request=exists"));
}

#[tokio::test]
async fn missing_fields_are_refused_before_any_relay() {
    let b = bench(GROUPS, true).await;
    for form in ["username=amartin", "username=amartin&password=", ""] {
        let r = b
            .call("POST", "/apps/fake-app/request/credentials", Some(form), true)
            .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{form:?}");
        assert!(r.body.contains("Renseignez tous les champs"));
    }
    assert!(b.fake.seen.lock().unwrap().is_empty());

    // Sans relais interne configuré : option indisponible.
    let b = bench(GROUPS, false).await;
    let r = b
        .call(
            "POST",
            "/apps/fake-app/request/credentials",
            Some("username=a&password=b"),
            true,
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn no_account_request_is_recorded_and_audited() {
    let b = bench(GROUPS, true).await;
    let r = b
        .call(
            "POST",
            "/apps/fake-app/request/no-account",
            Some("note=besoin+du+CRM%00+urgent"),
            true,
        )
        .await;
    assert_eq!(
        (r.status, r.location.as_deref()),
        (StatusCode::FOUND, Some("/?request=no_account"))
    );
    let open = b.requests.open_for_user("alice").await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].kind, AccessRequestKind::NoAccount);
    assert_eq!(
        open[0].note.as_deref(),
        Some("besoin du CRM urgent"),
        "caractère de contrôle retiré"
    );
    assert!(
        b.accounts
            .get_account("fake-app", "alice")
            .await
            .unwrap()
            .is_none(),
        "aucun compte créé"
    );
    let events = b.audit.events();
    let e = events
        .iter()
        .find(|e| e.action == AuditAction::AccessRequested)
        .unwrap();
    assert_eq!(e.outcome, AuditOutcome::Success);
    assert_eq!(e.app_id.as_deref(), Some("fake-app"));
    assert!(e.actor.as_deref().unwrap().contains("sub-alice"));
    // Signalement aux administrateurs : événement, appli, utilisateur, code court.
    assert_eq!(
        b.notifier.events(),
        vec![(
            sesame_core::ports::NotificationEvent::AccessRequested,
            "fake-app".to_owned(),
            Some("alice".to_owned()),
            "no_account".to_owned()
        )]
    );

    // « Mes applications » : tuile grisée « demande envoyée », plus de bouton.
    let home = b.call("GET", "/?request=no_account", None, true).await;
    assert!(home.body.contains("Demande envoyée"));
    assert!(home.body.contains("Votre demande est transmise"));
    assert!(!home.body.contains("action=\"/apps/fake-app/request\""));
    // Le formulaire reste accessible : une nouvelle demande remplace l'ancienne.
    let r = b
        .call("POST", "/apps/fake-app/request/no-account", Some("note="), true)
        .await;
    assert_eq!(r.location.as_deref(), Some("/?request=no_account"));
    assert_eq!(b.requests.open_for_user("alice").await.unwrap().len(), 1);
}

#[tokio::test]
async fn existing_accounts_short_circuit_every_request_route() {
    for status in [
        AccountStatus::Active,
        AccountStatus::Failed,
        AccountStatus::Disabled,
    ] {
        let b = bench(GROUPS, true).await;
        b.accounts.upsert(sesame_core::ports::AppAccount {
            app_id: "fake-app".into(),
            user_key: "alice".into(),
            status,
            status_reason: None,
            last_login_at: None,
        });
        for (method, path) in [
            ("GET", "/apps/fake-app/request"),
            ("POST", "/apps/fake-app/request/credentials"),
            ("POST", "/apps/fake-app/request/no-account"),
        ] {
            let r = b
                .call(method, path, Some("username=a&password=b&note=x"), true)
                .await;
            assert_eq!(
                r.location.as_deref(),
                Some("/?request=exists"),
                "{status:?} {method} {path}"
            );
        }
        assert!(b.fake.seen.lock().unwrap().is_empty(), "rien n'est relayé");
        assert!(b.requests.open_for_user("alice").await.unwrap().is_empty());
    }
    // Un compte déjà en attente : retour à l'accueil, sans nouvelle demande.
    let b = bench(GROUPS, true).await;
    b.accounts.upsert(sesame_core::ports::AppAccount {
        app_id: "fake-app".into(),
        user_key: "alice".into(),
        status: AccountStatus::Pending,
        status_reason: None,
        last_login_at: None,
    });
    let r = b.call("GET", "/apps/fake-app/request", None, true).await;
    assert_eq!(r.location.as_deref(), Some("/"));
    let home = b.call("GET", "/", None, true).await;
    assert!(home.body.contains("Demande en cours"));
}
