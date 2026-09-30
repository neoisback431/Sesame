// SPDX-License-Identifier: Apache-2.0
//! Tests d'intégration du moteur de proxy contre une appli simulée :
//! rejeu, injection de session, expiration, habilitations, registre des comptes,
//! hygiène des en-têtes, rejeu unique en cas de requêtes concurrentes.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use common::*;
use sesame_core::audit::AuditAction;
use sesame_core::crypto::hash_token;
use sesame_core::ports::{AccountRegistry, AccountStatus, DiagnosticStore, SessionStore};

// ---------------------------------------------------------------------------

#[tokio::test]
async fn redirects_to_portal_without_session() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let req = Request::builder()
        .uri("/account?x=1")
        .header(header::HOST, PUBLIC_HOST)
        .header("sec-fetch-mode", "navigate")
        .body(Body::empty())
        .unwrap();
    let r = b.send(req).await;
    assert_eq!(r.status, StatusCode::FOUND);
    let loc = r.headers[header::LOCATION].to_str().unwrap();
    assert!(
        loc.starts_with("https://sesame.test/auth/login?return_to="),
        "{loc}"
    );
    assert!(
        loc.contains("https%3A%2F%2Fapp.sesame.test%2Faccount%3Fx%3D1"),
        "{loc}"
    );
    assert_eq!(b.secrets.reads(), 0);
}

#[tokio::test]
async fn unauthenticated_subresource_gets_401_not_a_cors_breaking_redirect() {
    // Sans session, une sous-ressource (manifest, image, fetch) ne doit pas être redirigée
    // vers le login : la redirection cross-origin serait bloquée en CORS. On répond 401.
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let req = Request::builder()
        .uri("/images/site.webmanifest")
        .header(header::HOST, PUBLIC_HOST)
        .header("sec-fetch-mode", "cors")
        .body(Body::empty())
        .unwrap();
    let r = b.send(req).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(!r.headers.contains_key(header::LOCATION));
    assert_eq!(b.secrets.reads(), 0);
}

#[tokio::test]
async fn unknown_host_is_rejected() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let req = Request::builder()
        .uri("/")
        .header(header::HOST, "other.sesame.test")
        .body(Body::empty())
        .unwrap();
    assert_eq!(b.send(req).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn replays_login_and_injects_session() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("Bonjour amartin"));
    assert_eq!(b.secrets.reads(), 1);
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 1);

    // Session réutilisée : ni nouvelle lecture du coffre, ni nouveau rejeu.
    assert!(b.get("/").await.body.contains("Bonjour"));
    assert_eq!(b.secrets.reads(), 1);
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 1);

    let actions = b.actions();
    assert_eq!(actions, [AuditAction::SecretRead, AuditAction::LoginReplay]);
    let a = b
        .accounts
        .get_account("fake-app", "alice")
        .await
        .unwrap()
        .unwrap();
    assert!(a.last_login_at.is_some());
}

#[tokio::test]
async fn rewrites_internal_urls() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let r = b.get("/").await;
    assert!(
        r.body.contains("href=\"https://app.sesame.test/account\""),
        "{}",
        r.body
    );
    assert!(!r.body.contains(&b.internal));
    let r = b.get("/redirect-abs").await;
    assert_eq!(r.headers[header::LOCATION], "https://app.sesame.test/account");
}

#[tokio::test]
async fn replays_transparently_after_expiry() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    b.get("/").await;
    b.mock.sessions.lock().unwrap().clear(); // l'appli oublie ses sessions
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Bonjour amartin"));
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 2);
    assert_eq!(b.secrets.reads(), 2);
    assert!(b.actions().contains(&AuditAction::AppSessionExpired));
}

#[tokio::test]
async fn post_after_expiry_redirects_without_resubmitting() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    b.get("/").await;
    b.mock.sessions.lock().unwrap().clear();
    let req = b
        .request("POST", "/submit")
        .header(header::REFERER, "https://app.sesame.test/form?id=3")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("a=1"))
        .unwrap();
    let r = b.send(req).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.headers[header::LOCATION], "https://app.sesame.test/form?id=3");
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 2, "rejeu effectué");

    // Referer étranger : retour à la racine de l'appli.
    b.mock.sessions.lock().unwrap().clear();
    let req = b
        .request("POST", "/submit")
        .header(header::REFERER, "https://evil.example/")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        b.send(req).await.headers[header::LOCATION],
        "https://app.sesame.test/"
    );
}

#[tokio::test]
async fn app_cookies_stay_server_side() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let r = b.get("/pref").await;
    assert_eq!(r.body, "none");
    assert!(r.headers.get(header::SET_COOKIE).is_none());
    // Le cookie posé par l'appli est renvoyé par le proxy, pas par le navigateur.
    assert_eq!(b.get("/pref").await.body, "dark");
}

#[tokio::test]
async fn portal_cookie_and_authorization_never_reach_the_app() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let req = b
        .request("GET", "/echo")
        .header(header::AUTHORIZATION, "Bearer browser-token")
        .body(Body::empty())
        .unwrap();
    b.send(req).await;
    let seen = b.mock.seen.lock().unwrap().join("\n");
    assert!(seen.contains("APPSESS=sess-"), "{seen}");
    for forbidden in [
        "sesame_session",
        PORTAL_TOKEN,
        "other=1",
        "authorization",
        "browser-token",
    ] {
        assert!(!seen.contains(forbidden), "{forbidden} relayé : {seen}");
    }
}

#[tokio::test]
async fn not_authorized_user_is_denied_without_reading_secrets() {
    let b = bench(&["autre-groupe"], APP_PASSWORD, true).await;
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(b.secrets.reads(), 0);
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 0);
    let e = &b.audit.events()[0];
    assert_eq!(
        (e.action, e.reason.as_deref()),
        (AuditAction::AccessDenied, Some("not_authorized"))
    );
}

#[tokio::test]
async fn no_account_is_denied_without_reading_secrets() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, false).await;
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(b.secrets.reads(), 0);
    assert_eq!(b.audit.events()[0].reason.as_deref(), Some("no_account"));
}

#[tokio::test]
async fn rejected_login_marks_account_failed_and_blocks_retries() {
    let b = bench(&["fake-app-users"], "wrong-password", true).await;
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    assert!(
        !r.body.contains("Identifiants invalides"),
        "contenu de l'appli relayé"
    );
    let a = b
        .accounts
        .get_account("fake-app", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.status, AccountStatus::Failed);
    assert_eq!(a.status_reason.as_deref(), Some("login_rejected"));

    // Compte en échec : plus de lecture du coffre ni de rejeu (pas de verrouillage).
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(b.secrets.reads(), 1);
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 1);
    assert!(b.actions().contains(&AuditAction::AccountStatusChanged));
}

#[tokio::test]
async fn failed_replay_leaves_a_masked_diagnostic_when_enabled() {
    let b = bench_with(&["fake-app-users"], "wrong-password", true, true).await;
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    assert!(
        !r.body.contains("Identifiants invalides"),
        "rien de l'appli vers le navigateur"
    );
    let d = b
        .diagnostics
        .get_diagnostic("fake-app", "alice")
        .await
        .unwrap()
        .expect("diagnostic enregistré");
    assert_eq!(
        (d.reason.as_str(), d.step.as_str()),
        ("login_rejected", "login_submit")
    );
    assert_eq!((d.method.as_str(), d.status), ("POST", Some(401)));
    assert!(
        d.body.contains("Identifiants invalides"),
        "réponse réelle de l'appli : {}",
        d.body
    );
    assert!(d.sent_fields.iter().any(|f| f == "password") && d.sent_fields.iter().any(|f| f == "csrf_token"));
    // L'appli recopie la saisie : les valeurs du coffre sont masquées.
    let all = format!("{d:?}");
    assert!(
        !all.contains("wrong-password") && !all.contains("amartin"),
        "{all}"
    );
    assert!(d.body.contains("***"));
}

#[tokio::test]
async fn failed_login_page_diagnostic_masks_cookie_values() {
    let b = bench_with(&["fake-app-users"], APP_PASSWORD, true, true).await;
    // Sélecteur introuvable : l'échec a lieu sur la page de login.
    let mut d = descriptor(&b.internal);
    d.spec.login.form_selector = "form#absent".into();
    let (apps, rejected) = sesame_proxy::build_apps(vec![d], None, "https");
    assert!(rejected.is_empty());
    b.engine.set_apps(apps);
    b.get("/").await;
    let diag = b
        .diagnostics
        .get_diagnostic("fake-app", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (diag.reason.as_str(), diag.step.as_str()),
        ("login_form_not_found", "login_page")
    );
    assert!(diag.body.contains("<form id=\"login\""));
    let cookie = diag
        .headers
        .iter()
        .find(|(n, _)| n == "set-cookie")
        .map(|(_, v)| v.as_str());
    assert_eq!(cookie, Some("PRE=***; HttpOnly"));
}

#[tokio::test]
async fn csrf_token_from_an_api_endpoint() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let mut d = descriptor(&b.internal);
    d.spec.login.include_hidden_inputs = false;
    // Page de login lue pour ses cookies ; jeton obtenu par l'API, comme le ferait le JavaScript.
    let token: sesame_core::descriptor::CsrfToken = serde_json::from_value(serde_json::json!({
        "source": "endpoint", "name": "data.token", "url": "/api/csrf-token",
        "send_as": { "field": "csrf_token" }
    }))
    .unwrap();
    d.spec.login.csrf = vec![token];
    d.spec.login.fields.insert(
        "lang".into(),
        sesame_core::descriptor::FormField::Value("fr".into()),
    );
    let (apps, rejected) = sesame_proxy::build_apps(vec![d], None, "https");
    assert!(rejected.is_empty(), "{rejected:?}");
    b.engine.set_apps(apps);
    let r = b.get("/").await;
    assert!(r.body.contains("Bonjour amartin"), "{}", r.body);
}

#[tokio::test]
async fn login_without_form_posts_directly_to_the_action() {
    // Page de login sans formulaire exploitable (construite en JavaScript) : la requête part
    // directement, avec les cookies de la page et le jeton lu par regex dans son HTML.
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let mut d = descriptor(&b.internal);
    d.spec.login.use_form = false;
    d.spec.login.form_selector = "form#absent".into();
    d.spec.login.action = Some("/login".into());
    d.spec.login.csrf = vec![serde_json::from_value(serde_json::json!({
        "source": "regex", "name": "csrf_token",
        "pattern": "name=\"csrf_token\" value=\"([^\"]+)\""
    }))
    .unwrap()];
    d.spec.login.fields.insert(
        "lang".into(),
        sesame_core::descriptor::FormField::Value("fr".into()),
    );
    let (apps, rejected) = sesame_proxy::build_apps(vec![d], None, "https");
    assert!(rejected.is_empty(), "{rejected:?}");
    b.engine.set_apps(apps);
    let r = b.get("/").await;
    assert!(r.body.contains("Bonjour amartin"), "{}", r.body);
}

/// Banc avec l'appli simulée en mode handoff (cookie APPSESS remis au navigateur).
async fn handoff_bench() -> Bench {
    use sesame_core::descriptor::{Handoff, SessionMode};

    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let mut d = descriptor(&b.internal);
    d.spec.session.mode = SessionMode::Handoff;
    d.spec.session.handoff = Some(Handoff {
        set_cookies: vec!["APPSESS".into()],
        local_storage: Vec::new(),
        redirect_status: 303,
    });
    let (apps, rejected) = sesame_proxy::build_apps(vec![d], None, "https");
    assert!(rejected.is_empty(), "{rejected:?}");
    b.engine.set_apps(apps);
    b
}

/// Valeur d'un cookie posé par la réponse (`Set-Cookie: name=valeur; …`).
fn set_cookie_value(r: &Reply, name: &str) -> Option<String> {
    r.headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            c.strip_prefix(&format!("{name}="))
                .map(|v| v.split(';').next().unwrap().to_owned())
        })
}

fn navigate(b: &Bench, path: &str, cookie: &str) -> Request<Body> {
    b.request("GET", path)
        .header("sec-fetch-mode", "navigate")
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn handoff_mode_hands_the_cookie_to_the_browser() {
    let b = handoff_bench().await;

    // Première arrivée (pas de marqueur) : rejeu côté serveur, cookie + marqueur posés au
    // navigateur, redirection transparente vers l'URL demandée.
    let r = b.get_raw("/dashboard").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let location = r.headers[header::LOCATION].to_str().unwrap();
    assert!(location.ends_with("/dashboard"), "{location}");
    let appsess = set_cookie_value(&r, "APPSESS").expect("cookie applicatif remis");
    assert!(appsess.starts_with("sess-"));
    assert_eq!(set_cookie_value(&r, "__sesame_handoff").as_deref(), Some("1"));
    assert!(b.actions().contains(&AuditAction::SessionHandoff));

    // Requête suivante (marqueur + cookie applicatif portés par le navigateur) : relais
    // transparent, aucun nouveau rejeu.
    let logins = b.mock.logins.load(Ordering::SeqCst);
    let r = b
        .send_raw(navigate(
            &b,
            "/",
            &format!("__sesame_handoff=1; APPSESS={appsess}"),
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Bonjour amartin"), "{}", r.body);
    assert_eq!(
        b.mock.logins.load(Ordering::SeqCst),
        logins,
        "pas de rejeu au relais"
    );
}

#[tokio::test]
async fn handoff_relay_keeps_sesame_cookies_away_from_the_app() {
    // Le navigateur porte la session : ses cookies applicatifs et son Authorization sont
    // relayés, mais ni le cookie du portail ni le marqueur de remise.
    let b = handoff_bench().await;
    let req = b
        .request("GET", "/echo")
        .header(header::COOKIE, "__sesame_handoff=1; APPSESS=sess-x")
        .header(header::AUTHORIZATION, "Bearer jeton-appli")
        .body(Body::empty())
        .unwrap();
    assert_eq!(b.send_raw(req).await.status, StatusCode::OK);
    let seen = b.mock.seen.lock().unwrap().join("\n");
    assert!(
        seen.contains("APPSESS=sess-x") && seen.contains("other=1"),
        "{seen}"
    );
    assert!(seen.contains("authorization: Bearer jeton-appli"), "{seen}");
    assert!(
        !seen.contains("__sesame_handoff") && !seen.contains("sesame_session"),
        "{seen}"
    );
}

#[tokio::test]
async fn expired_handed_off_session_is_handed_off_again() {
    // Cookie remis périmé côté appli (redirection vers /login) sur une navigation :
    // nouvelle remise, sans que l'utilisateur ne voie le formulaire de l'appli.
    let b = handoff_bench().await;
    let logins = b.mock.logins.load(Ordering::SeqCst);
    let r = b
        .send_raw(navigate(&b, "/", "__sesame_handoff=1; APPSESS=perime"))
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert!(set_cookie_value(&r, "APPSESS").is_some_and(|v| v.starts_with("sess-")));
    assert_eq!(
        b.mock.logins.load(Ordering::SeqCst),
        logins + 1,
        "un nouveau rejeu"
    );
    assert!(b.actions().contains(&AuditAction::AppSessionExpired));
}

#[tokio::test]
async fn no_diagnostic_is_kept_by_default() {
    let b = bench(&["fake-app-users"], "wrong-password", true).await;
    b.get("/").await;
    assert!(b
        .diagnostics
        .get_diagnostic("fake-app", "alice")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn app_logout_forgets_the_session() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    b.get("/").await;
    b.get("/logout").await;
    assert!(b
        .sessions
        .get_app_session(&hash_token(PORTAL_TOKEN), "fake-app")
        .await
        .unwrap()
        .is_none());
    assert!(b.actions().contains(&AuditAction::AppLogout));
    // Prochaine visite : nouveau rejeu.
    assert!(b.get("/").await.body.contains("Bonjour"));
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn concurrent_requests_trigger_a_single_replay() {
    let b = Arc::new(bench(&["fake-app-users"], APP_PASSWORD, true).await);
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let b = b.clone();
            tokio::spawn(async move { b.get("/").await.status })
        })
        .collect();
    for t in tasks {
        assert_eq!(t.await.unwrap(), StatusCode::OK);
    }
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 1);
    assert_eq!(b.secrets.reads(), 1);
}

#[tokio::test]
async fn catalog_hot_reload_adds_and_removes_apps() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    assert_eq!(b.get("/").await.status, StatusCode::OK);

    // Catalogue vidé : l'hôte n'est plus servi, sans redémarrage.
    b.engine.set_apps(Vec::new());
    assert_eq!(b.engine.app_count(), 0);
    assert_eq!(b.get("/").await.status, StatusCode::NOT_FOUND);

    // Appli rajoutée (comme après une création dans l'UI d'admin) : de nouveau servie.
    let d = descriptor(&b.internal);
    let (apps, rejected) = sesame_proxy::build_apps(vec![d], None, "https");
    assert!(rejected.is_empty());
    b.engine.set_apps(apps);
    assert!(b.get("/").await.body.contains("Bonjour amartin"));
}

#[tokio::test]
async fn failures_are_signalled_to_administrators_once_per_window() {
    use sesame_core::ports::NotificationEvent::{AccountFailed, UpstreamUnreachable};

    // Compte en échec : un signalement, sans aucun contenu de l'appli.
    let b = bench(&["fake-app-users"], "wrong-password", true).await;
    b.get("/").await;
    assert_eq!(
        b.notifier.events(),
        vec![(
            AccountFailed,
            "fake-app".to_owned(),
            Some("alice".to_owned()),
            "login_rejected".to_owned()
        )]
    );
    assert!(!format!("{:?}", b.notifier.events()).contains("wrong-password"));

    // Appli injoignable : signalement par appli, sans changement d'état du compte.
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let d = descriptor("http://127.0.0.1:9");
    let http = sesame_proxy::build_client(&d, None).unwrap();
    b.engine.set_apps(vec![sesame_proxy::App::new(d, http, "https")]);
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        b.notifier.events(),
        vec![(
            UpstreamUnreachable,
            "fake-app".to_owned(),
            None,
            "upstream_unreachable".to_owned()
        )]
    );
    let a = b
        .accounts
        .get_account("fake-app", "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.status, AccountStatus::Active);
}
