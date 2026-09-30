// SPDX-License-Identifier: Apache-2.0
//! Demandes d'accès avec identifiants fournis par l'utilisateur (ADR 0029) : service interne.

mod common;

use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use common::access::*;
use common::*;
use sesame_core::audit::{AuditAction, AuditOutcome};
use sesame_core::ports::{AccessRequestKind, AccessRequests, AccountRegistry, AccountStatus, SecretStore};
use sesame_core::secret::ExposeSecret;

fn good() -> serde_json::Value {
    serde_json::json!({ "username": "amartin", "password": APP_PASSWORD })
}

const GROUPS: &[&str] = &["fake-app-users"];

#[tokio::test]
async fn valid_credentials_are_verified_stored_and_left_pending() {
    let b = bench(GROUPS, APP_PASSWORD, false).await;
    let a = access_bench(&b, true);
    let (status, body) = post_access(&a.router, Some(INTERNAL_TOKEN), &bob(GROUPS), good()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.contains(APP_PASSWORD) && !body.contains("amartin"));

    let account = b.accounts.get_account("fake-app", "bob").await.unwrap().unwrap();
    assert_eq!(account.status, AccountStatus::Pending);
    let cred = b.secrets.get_credential("fake-app", "bob").await.unwrap();
    assert_eq!(cred.get("password").unwrap().expose_secret(), APP_PASSWORD);
    let open = a.requests.open_for_user("bob").await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].kind, AccessRequestKind::Credentials);

    let actions = b.actions();
    for expected in [
        AuditAction::LoginReplay,
        AuditAction::CredentialWritten,
        AuditAction::AccessRequested,
    ] {
        assert!(actions.contains(&expected), "audit manquant : {expected:?}");
    }
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 1, "une seule tentative");
}

#[tokio::test]
async fn wrong_credentials_store_nothing_and_leak_nothing() {
    let b = bench(GROUPS, APP_PASSWORD, false).await;
    let a = access_bench(&b, true);
    let wrong = serde_json::json!({ "username": "amartin", "password": "Mauvais-MDP-777" });
    let (status, body) = post_access(&a.router, Some(INTERNAL_TOKEN), &bob(GROUPS), wrong).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    // L'appli recopie la saisie dans sa page d'erreur : rien ne doit revenir.
    assert!(!body.contains("Mauvais-MDP-777") && !body.contains("Identifiants invalides"));
    assert!(b.accounts.get_account("fake-app", "bob").await.unwrap().is_none());
    assert!(b.secrets.get_credential("fake-app", "bob").await.is_err());
    assert!(a.requests.open_for_user("bob").await.unwrap().is_empty());
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 1, "pas de nouvel essai");
    let events = b.audit.events();
    assert!(events
        .iter()
        .any(|e| e.action == AuditAction::AccessRequested && e.outcome == AuditOutcome::Failure));
    assert!(!serde_json::to_string(&events)
        .unwrap()
        .contains("Mauvais-MDP-777"));
}

#[tokio::test]
async fn token_is_required_and_checked_before_anything() {
    let b = bench(GROUPS, APP_PASSWORD, false).await;
    let a = access_bench(&b, true);
    for token in [None, Some("mauvais"), Some("")] {
        let (status, _) = post_access(&a.router, token, &bob(GROUPS), good()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
    }
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 0);
    assert!(b.accounts.get_account("fake-app", "bob").await.unwrap().is_none());
}

#[tokio::test]
async fn existing_accounts_are_never_overwritten() {
    for status in [
        AccountStatus::Active,
        AccountStatus::Failed,
        AccountStatus::Disabled,
    ] {
        let b = bench(GROUPS, APP_PASSWORD, true).await;
        let a = access_bench(&b, true);
        b.accounts
            .set_status("fake-app", "alice", status, None)
            .await
            .unwrap();
        let (code, _) = post_access(&a.router, Some(INTERNAL_TOKEN), &alice(GROUPS), good()).await;
        assert_eq!(code, StatusCode::CONFLICT, "{status:?}");
        assert_eq!(b.mock.logins.load(Ordering::SeqCst), 0, "aucun rejeu");
        let cred = b.secrets.get_credential("fake-app", "alice").await.unwrap();
        assert_eq!(
            cred.get("username").unwrap().expose_secret(),
            "amartin",
            "secret intact"
        );
        assert_eq!(
            b.accounts
                .get_account("fake-app", "alice")
                .await
                .unwrap()
                .unwrap()
                .status,
            status
        );
    }
}

#[tokio::test]
async fn resubmission_replaces_a_pending_request() {
    let b = bench(GROUPS, APP_PASSWORD, false).await;
    let a = access_bench(&b, true);
    for _ in 0..2 {
        let (status, _) = post_access(&a.router, Some(INTERNAL_TOKEN), &bob(GROUPS), good()).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(a.requests.open_for_user("bob").await.unwrap().len(), 1);
}

#[tokio::test]
async fn pending_account_blocks_the_replay() {
    let b = bench(GROUPS, APP_PASSWORD, false).await;
    let a = access_bench(&b, true);
    // alice a un secret (banc) : sa demande crée un compte en attente.
    let (status, _) = post_access(&a.router, Some(INTERNAL_TOKEN), &alice(GROUPS), good()).await;
    assert_eq!(status, StatusCode::OK);
    let logins = b.mock.logins.load(Ordering::SeqCst);
    let reply = b.get("/").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(reply.body.contains("en attente de validation"));
    assert_eq!(
        b.mock.logins.load(Ordering::SeqCst),
        logins,
        "aucun rejeu tant que pending"
    );
}

#[tokio::test]
async fn invalid_requests_are_refused() {
    let b = bench(GROUPS, APP_PASSWORD, false).await;
    let a = access_bench(&b, true);

    // Non habilité (spec.access : groupe requis).
    assert_eq!(
        post_access(&a.router, Some(INTERNAL_TOKEN), &bob(&["autre"]), good())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    // Champ manquant, en trop, vide.
    let missing = serde_json::json!({ "username": "amartin" });
    assert_eq!(
        post_access(&a.router, Some(INTERNAL_TOKEN), &bob(GROUPS), missing)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let extra = serde_json::json!({ "username": "a", "password": "b", "admin": "x" });
    assert_eq!(
        post_access(&a.router, Some(INTERNAL_TOKEN), &bob(GROUPS), extra)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let empty = serde_json::json!({ "username": "amartin", "password": "" });
    assert_eq!(
        post_access(&a.router, Some(INTERNAL_TOKEN), &bob(GROUPS), empty)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    // Clé utilisateur dangereuse.
    let mut evil = bob(GROUPS);
    evil.user_key = "../alice".into();
    assert_eq!(
        post_access(&a.router, Some(INTERNAL_TOKEN), &evil, good())
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        b.mock.logins.load(Ordering::SeqCst),
        0,
        "aucun rejeu pour une demande invalide"
    );
    assert!(b.accounts.get_account("fake-app", "bob").await.unwrap().is_none());
}

#[tokio::test]
async fn read_only_secret_store_answers_unsupported() {
    let b = bench(GROUPS, APP_PASSWORD, false).await;
    let a = access_bench(&b, false);
    let (status, _) = post_access(&a.router, Some(INTERNAL_TOKEN), &bob(GROUPS), good()).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(b.mock.logins.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn accepted_request_notifies_administrators_without_secrets() {
    use sesame_core::ports::NotificationEvent::AccessRequested;
    let b = bench(GROUPS, APP_PASSWORD, false).await;
    let a = access_bench(&b, true);
    let wrong = serde_json::json!({ "username": "amartin", "password": "Mauvais-MDP-777" });
    post_access(&a.router, Some(INTERNAL_TOKEN), &bob(GROUPS), wrong).await;
    assert!(
        b.notifier.events().is_empty(),
        "rien tant que la vérification échoue"
    );
    post_access(&a.router, Some(INTERNAL_TOKEN), &bob(GROUPS), good()).await;
    let events = b.notifier.events();
    assert_eq!(
        events,
        vec![(
            AccessRequested,
            "fake-app".to_owned(),
            Some("bob".to_owned()),
            "credentials".to_owned()
        )]
    );
    assert!(!format!("{events:?}").contains(APP_PASSWORD));
}
