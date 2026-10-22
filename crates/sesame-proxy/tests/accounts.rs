// SPDX-License-Identifier: Apache-2.0
//! Plusieurs comptes par couple (appli, utilisateur) (ADR 0034) : le proxy rejoue avec le
//! compte choisi par l'utilisateur, sinon son compte par défaut ; l'échec d'un compte
//! n'affecte pas les autres ; en mode handoff, un changement de compte refait la remise.

mod common;

use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use common::*;
use sesame_core::audit::{AuditAction, AuditOutcome};
use sesame_core::crypto::hash_token;
use sesame_core::descriptor::{Handoff, SessionMode};
use sesame_core::ports::{
    AccountKey, AccountRegistry, AccountStatus, AppAccount, DiagnosticStore, SessionStore,
};

const ADMIN_PASSWORD: &str = "Adm-PW-ADMIN-7373";

fn admin_key() -> AccountKey {
    AccountKey::new("fake-app", "alice", "admin")
}

/// Ajoute à alice un compte « admin », actif, avec ces identifiants.
fn add_admin(b: &Bench, password: &str) {
    let mut account = AppAccount::new(&admin_key(), AccountStatus::Active, false);
    account.label = Some("Admin".into());
    b.accounts.upsert(account);
    b.secrets
        .insert_account(&admin_key(), &[("username", "amartin"), ("password", password)]);
}

/// Événements d'audit d'une action, avec leur compte.
fn accounts_of(b: &Bench, action: AuditAction) -> Vec<Option<String>> {
    b.audit
        .events()
        .into_iter()
        .filter(|e| e.action == action)
        .map(|e| e.account_id)
        .collect()
}

#[tokio::test]
async fn replays_with_the_default_account_until_another_is_selected() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    add_admin(&b, APP_PASSWORD);

    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let sid = hash_token(PORTAL_TOKEN);
    let s = b
        .sessions
        .get_app_session(&sid, "fake-app")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.account_id, "default");
    assert_eq!(
        accounts_of(&b, AuditAction::SecretRead),
        [Some("default".to_owned())]
    );

    // Choix du compte « admin » : le portail détruit la session ouverte avec l'autre compte.
    b.accounts.select_account(&admin_key()).await.unwrap();
    b.sessions.delete_app_session(&sid, "fake-app").await.unwrap();
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let s = b
        .sessions
        .get_app_session(&sid, "fake-app")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.account_id, "admin");
    let reads = accounts_of(&b, AuditAction::SecretRead);
    assert_eq!(reads.last().unwrap().as_deref(), Some("admin"));
    let replays = accounts_of(&b, AuditAction::LoginReplay);
    assert_eq!(replays.last().unwrap().as_deref(), Some("admin"));
    let a = b.accounts.get_account(&admin_key()).await.unwrap().unwrap();
    assert!(a.last_login_at.is_some());
}

#[tokio::test]
async fn disabled_selected_account_falls_back_to_the_default_account() {
    let b = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    add_admin(&b, APP_PASSWORD);
    b.accounts.select_account(&admin_key()).await.unwrap();
    b.accounts
        .set_status(&admin_key(), AccountStatus::Disabled, None)
        .await
        .unwrap();

    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let s = b
        .sessions
        .get_app_session(&hash_token(PORTAL_TOKEN), "fake-app")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.account_id, "default");
}

#[tokio::test]
async fn failure_of_one_account_leaves_the_others_untouched_and_leaks_nothing() {
    let b = bench_with(&["fake-app-users"], APP_PASSWORD, true, true).await;
    add_admin(&b, ADMIN_PASSWORD); // refusé par l'appli
    b.accounts.select_account(&admin_key()).await.unwrap();

    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    assert!(!r.body.contains(ADMIN_PASSWORD) && !r.body.contains("Identifiants invalides"));
    for (name, value) in &r.headers {
        assert!(
            !value.to_str().unwrap_or("").contains(ADMIN_PASSWORD),
            "mot de passe dans l'en-tête {name}"
        );
    }

    let admin = b.accounts.get_account(&admin_key()).await.unwrap().unwrap();
    assert_eq!(admin.status, AccountStatus::Failed);
    let default = b
        .accounts
        .get_account(&AccountKey::default_of("fake-app", "alice"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(default.status, AccountStatus::Active, "autre compte intact");

    // Diagnostic rangé sous le compte en échec, valeur du coffre masquée.
    let d = b.diagnostics.get_diagnostic(&admin_key()).await.unwrap().unwrap();
    assert_eq!(d.account_id, "admin");
    assert!(!d.body.contains(ADMIN_PASSWORD));
    assert!(b
        .diagnostics
        .get_diagnostic(&AccountKey::default_of("fake-app", "alice"))
        .await
        .unwrap()
        .is_none());

    let failed = b
        .audit
        .events()
        .into_iter()
        .find(|e| e.action == AuditAction::AccountStatusChanged)
        .expect("changement d'état audité");
    assert_eq!(failed.account_id.as_deref(), Some("admin"));
    let (event, _, user, _) = b.notifier.events().pop().expect("notification");
    assert_eq!(
        (event, user.as_deref()),
        (
            sesame_core::ports::NotificationEvent::AccountFailed,
            Some("alice")
        )
    );

    // Retour au compte par défaut : connexion normale.
    b.accounts
        .select_account(&AccountKey::default_of("fake-app", "alice"))
        .await
        .unwrap();
    let r = b.get("/").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(b
        .audit
        .events()
        .iter()
        .any(|e| e.action == AuditAction::LoginReplay
            && e.outcome == AuditOutcome::Success
            && e.account_id.as_deref() == Some("default")));
}

async fn handoff_bench() -> Bench {
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

fn navigate(b: &Bench, path: &str, cookie: &str) -> Request<Body> {
    b.request("GET", path)
        .header("sec-fetch-mode", "navigate")
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

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

fn marker(r: &Reply) -> Option<String> {
    set_cookie_value(r, "__sesame_handoff")
}

#[tokio::test]
async fn handoff_is_redone_when_another_account_is_selected() {
    let b = handoff_bench().await;
    add_admin(&b, APP_PASSWORD);

    let r = b.get_raw("/dashboard").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(marker(&r).as_deref(), Some("default"));
    let cookies = format!(
        "__sesame_handoff=default; APPSESS={}",
        set_cookie_value(&r, "APPSESS").expect("cookie remis")
    );

    // Même compte : relais transparent, aucun nouveau rejeu.
    let logins = b.mock.logins.load(Ordering::SeqCst);
    let r = b.send_raw(navigate(&b, "/", &cookies)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), logins);

    // Autre compte choisi : la navigation suivante refait la remise avec ce compte.
    b.accounts.select_account(&admin_key()).await.unwrap();
    let r = b.send_raw(navigate(&b, "/", &cookies)).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(marker(&r).as_deref(), Some("admin"));
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), logins + 1);
    let handoffs = accounts_of(&b, AuditAction::SessionHandoff);
    assert_eq!(handoffs.last().unwrap().as_deref(), Some("admin"));

    // Sous-ressource (pas une navigation) : relayée sans nouvelle remise.
    let logins = b.mock.logins.load(Ordering::SeqCst);
    let req = b
        .request("GET", "/")
        .header(header::COOKIE, &cookies)
        .body(Body::empty())
        .unwrap();
    let _ = b.send_raw(req).await;
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), logins);
}
