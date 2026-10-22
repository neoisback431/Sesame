// SPDX-License-Identifier: Apache-2.0
//! Connexion automatique suspendue après « Déconnecter » (ADR 0033) : tant que la suspension
//! dure, ni rejeu ni lecture du coffre ; la requête est relayée telle quelle (le navigateur
//! porte ses propres cookies, l'utilisateur peut se connecter à la main avec un autre compte) ;
//! le chemin réservé `/.sesame/disconnect` efface ce que le navigateur porte pour l'appli.

mod common;

use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use common::*;
use sesame_core::audit::AuditAction;
use sesame_core::descriptor::{Handoff, SessionMode};
use sesame_core::ports::{AccountRegistry, AccountStatus, SessionStore};

async fn suspend(b: &Bench) {
    b.sessions.suspend_app("alice", "fake-app").await.unwrap();
}

fn count(b: &Bench, action: AuditAction) -> usize {
    b.actions().iter().filter(|a| **a == action).count()
}

fn set_cookie_lines(r: &Reply) -> Vec<String> {
    r.headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect()
}

fn navigate(b: &Bench, path: &str, cookie: &str) -> Request<Body> {
    b.request("GET", path)
        .header("sec-fetch-mode", "navigate")
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn suspended_proxy_mode_neither_replays_nor_reads_the_vault() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    assert!(b.get("/").await.body.contains("Bonjour"));
    assert_eq!(b.secrets.reads(), 1);

    // « Déconnecter » : la session applicative disparaît, et rien ne la recrée.
    suspend(&b).await;
    assert!(b
        .sessions
        .get_app_session(&hash_portal(), "fake-app")
        .await
        .unwrap()
        .is_none());
    let r = b.get_raw("/").await;
    assert!(
        r.status.is_redirection(),
        "l'appli renvoie sa propre page de login : {} {}",
        r.status,
        r.body
    );
    let r = b.get_raw("/login").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(
        r.body.contains("name=\"password\""),
        "formulaire de l'appli : {}",
        r.body
    );
    assert!(
        set_cookie_lines(&r).iter().any(|c| c.starts_with("PRE=")),
        "les Set-Cookie de l'appli reviennent au navigateur : il porte lui-même sa session"
    );
    assert_eq!(b.secrets.reads(), 1, "aucune lecture du coffre");
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 1, "aucun rejeu");
    assert_eq!(count(&b, AuditAction::SecretRead), 1);
    assert_eq!(count(&b, AuditAction::LoginReplay), 1);

    // Un clic sur la tuile lève la suspension : le rejeu reprend, transparent.
    assert!(b.sessions.resume_app("alice", "fake-app").await.unwrap());
    assert!(b.get("/").await.body.contains("Bonjour amartin"));
    assert_eq!(b.secrets.reads(), 2);
}

#[tokio::test]
async fn suspended_relays_the_browser_cookies_but_never_the_portal_cookie() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    suspend(&b).await;
    let req = b
        .request("GET", "/echo")
        .header(header::COOKIE, "APPSESS=saisie-manuelle")
        .header(header::AUTHORIZATION, "Bearer jeton-saisi")
        .body(Body::empty())
        .unwrap();
    assert_eq!(b.send_raw(req).await.status, StatusCode::OK);
    let seen = b.mock.seen.lock().unwrap().join("\n");
    assert!(seen.contains("APPSESS=saisie-manuelle"), "{seen}");
    assert!(seen.contains("authorization: Bearer jeton-saisi"), "{seen}");
    assert!(
        !seen.contains("sesame_session"),
        "cookie du portail relayé : {seen}"
    );
    assert_eq!(b.secrets.reads(), 0);
}

#[tokio::test]
async fn suspension_is_per_user_and_per_app() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    b.sessions.suspend_app("bob", "fake-app").await.unwrap();
    b.sessions.suspend_app("alice", "autre-appli").await.unwrap();
    assert!(b.get("/").await.body.contains("Bonjour amartin"));
    assert_eq!(b.secrets.reads(), 1);
}

#[tokio::test]
async fn suspended_handoff_mode_shows_the_app_login_without_handing_off() {
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

    suspend(&b).await;
    // Sans marqueur de remise : ni rejeu ni remise, la page de l'appli est montrée telle quelle.
    let r = b.send_raw(navigate(&b, "/login", "other=1")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("name=\"password\""), "{}", r.body);
    assert!(!set_cookie_lines(&r)
        .iter()
        .any(|c| c.starts_with("__sesame_handoff")));
    assert_eq!(b.secrets.reads(), 0);
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 0);
    assert_eq!(count(&b, AuditAction::SessionHandoff), 0);

    // Même chose si le cookie remis a été effacé alors que le marqueur subsiste.
    let r = b.send_raw(navigate(&b, "/login", "__sesame_handoff=1")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(b.secrets.reads(), 0);

    // Suspension levée : la remise reprend.
    b.sessions.resume_app("alice", "fake-app").await.unwrap();
    let r = b.send_raw(navigate(&b, "/", "other=1")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(count(&b, AuditAction::SessionHandoff), 1);
}

#[tokio::test]
async fn suspended_does_not_bypass_an_account_disabled_by_an_administrator() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    suspend(&b).await;
    b.accounts
        .set_status("fake-app", "alice", AccountStatus::Disabled, None)
        .await
        .unwrap();
    let r = b.get_raw("/echo").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    assert!(b.mock.seen.lock().unwrap().is_empty(), "rien relayé à l'appli");
    assert!(b.actions().contains(&AuditAction::AccessDenied));
}

#[tokio::test]
async fn disconnect_path_does_nothing_unless_the_user_disconnected_from_the_portal() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    let r = b
        .send_raw(navigate(
            &b,
            "/.sesame/disconnect",
            "APPSESS=sess-x; __sesame_handoff=1",
        ))
        .await;
    assert_eq!(r.status, StatusCode::FOUND, "{}", r.body);
    assert_eq!(r.headers[header::LOCATION], "https://sesame.test/");
    assert!(
        set_cookie_lines(&r).is_empty(),
        "aucun cookie touché sans suspension"
    );
    assert!(b.mock.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn disconnect_path_clears_what_the_browser_carries_for_the_app() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    suspend(&b).await;
    let r = b
        .send_raw(navigate(
            &b,
            "/.sesame/disconnect",
            "APPSESS=sess-x; __sesame_handoff=1; lang=fr",
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let cleared = set_cookie_lines(&r);
    for name in ["APPSESS", "__sesame_handoff", "lang", "other"] {
        assert!(
            cleared.iter().any(|c| c.starts_with(&format!("{name}=;"))
                && c.contains("Max-Age=0")
                && c.contains("Secure")),
            "{name} non effacé : {cleared:?}"
        );
    }
    assert!(
        !cleared.iter().any(|c| c.starts_with("sesame_session")),
        "le cookie du portail n'est pas touché : {cleared:?}"
    );
    assert!(r.body.contains("localStorage.clear()"));
    assert!(
        r.body.contains("https://sesame.test/"),
        "retour au portail : {}",
        r.body
    );
    assert!(!r.body.contains(APP_PASSWORD));
    assert!(b.mock.seen.lock().unwrap().is_empty(), "rien relayé à l'appli");
    assert_eq!(b.secrets.reads(), 0);
}

/// Empreinte de la session portail de test (clé du magasin de sessions).
fn hash_portal() -> String {
    sesame_core::crypto::hash_token(PORTAL_TOKEN)
}
