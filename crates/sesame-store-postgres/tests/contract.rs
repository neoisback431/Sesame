// SPDX-License-Identifier: Apache-2.0
//! Tests de contrat sur une vraie base. Ignorés si `SESAME_TEST_DATABASE_URL` est absente.

use base64::Engine;
use sesame_core::contract;
use sesame_core::crypto::CookieCipher;
use sesame_core::secret::{ExposeSecret, SecretString};
use sesame_store_postgres::PgStore;

async fn store() -> Option<PgStore> {
    let url = std::env::var("SESAME_TEST_DATABASE_URL").ok()?;
    let key = base64::engine::general_purpose::STANDARD.encode([42u8; 32]);
    let cipher = CookieCipher::from_base64(&SecretString::from(key)).unwrap();
    let store = PgStore::connect(&SecretString::from(url), Some(cipher))
        .await
        .unwrap();
    store.migrate().await.unwrap();
    Some(store)
}

fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

#[tokio::test]
async fn postgres_session_store() {
    let Some(store) = store().await else {
        eprintln!("SESAME_TEST_DATABASE_URL absente : test ignoré");
        return;
    };
    contract::session_store(&store, &unique("pg")).await;
}

#[tokio::test]
async fn postgres_account_registry() {
    let Some(store) = store().await else {
        eprintln!("SESAME_TEST_DATABASE_URL absente : test ignoré");
        return;
    };
    let user = unique("alice");
    store.seed_account("app1", &user).await.unwrap();
    contract::account_registry(&store, "app1", &user).await;
}

#[tokio::test]
async fn postgres_descriptor_store() {
    let Some(store) = store().await else {
        eprintln!("SESAME_TEST_DATABASE_URL absente : test ignoré");
        return;
    };
    contract::descriptor_store(&store, &unique("pg")).await;
}

#[tokio::test]
async fn diagnostic_store_contract() {
    let Some(store) = store().await else {
        eprintln!("SESAME_TEST_DATABASE_URL absente : test ignoré");
        return;
    };
    let user = unique("diag");
    store.seed_account("app1", &user).await.unwrap();
    contract::diagnostic_store(&store, "app1", &user).await;
}

#[tokio::test]
async fn user_directory_contract() {
    let Some(store) = store().await else {
        eprintln!("SESAME_TEST_DATABASE_URL absente : test ignoré");
        return;
    };
    contract::user_directory(&store, &unique("annuaire")).await;
}

#[tokio::test]
async fn access_requests_contract() {
    let Some(store) = store().await else {
        eprintln!("SESAME_TEST_DATABASE_URL absente : test ignoré");
        return;
    };
    let (fresh, existing) = (unique("nouveau"), unique("titulaire"));
    store.seed_account("app1", &existing).await.unwrap();
    contract::access_requests(&store, &store, "app1", &fresh, &existing).await;
}

// Coffre de secrets PostgreSQL (ADR 0021). SecretStore n'expose que la lecture (seul
// le proxy le lit) : le seed passe par `put_credential`, réservé aux tests et au dev.
#[tokio::test]
async fn postgres_secret_store() {
    use sesame_core::ports::{PortError, SecretStore};
    let Some(store) = store().await else {
        eprintln!("SESAME_TEST_DATABASE_URL absente : test ignoré");
        return;
    };
    let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let secrets = store.secrets(CookieCipher::from_base64(&SecretString::from(key)).unwrap());
    let user = unique("secret-user");

    assert!(matches!(
        secrets.get_credential("app1", &user).await,
        Err(PortError::NotFound)
    ));

    let fields = std::collections::BTreeMap::from([
        ("username".to_string(), "amartin".to_string()),
        ("password".to_string(), "s3cret-pw".to_string()),
    ]);
    secrets.put_credential("app1", &user, &fields).await.unwrap();
    let cred = secrets.get_credential("app1", &user).await.unwrap();
    assert_eq!(cred.get("username").unwrap().expose_secret(), "amartin");
    assert_eq!(cred.get("password").unwrap().expose_secret(), "s3cret-pw");

    // Remplace l'ensemble des champs (comme un PUT KV v2) : « username » disparaît.
    let fields2 = std::collections::BTreeMap::from([("password".to_string(), "new-pw".to_string())]);
    secrets.put_credential("app1", &user, &fields2).await.unwrap();
    let cred2 = secrets.get_credential("app1", &user).await.unwrap();
    assert!(cred2.get("username").is_none());
    assert_eq!(cred2.get("password").unwrap().expose_secret(), "new-pw");

    secrets.delete_credential("app1", &user).await.unwrap();
    assert!(matches!(
        secrets.get_credential("app1", &user).await,
        Err(PortError::NotFound)
    ));
}

#[tokio::test]
async fn notifier_groups_repeated_events() {
    use sesame_core::ports::{NotificationEvent, Notifier};
    let Some(store) = store().await else {
        eprintln!("SESAME_TEST_DATABASE_URL absente : test ignoré");
        return;
    };
    let app = unique("notif");
    for _ in 0..3 {
        store
            .notify(
                NotificationEvent::UpstreamUnreachable,
                &app,
                None,
                "upstream_unreachable",
            )
            .await;
    }
    store
        .notify(
            NotificationEvent::AccountFailed,
            &app,
            Some("alice"),
            "login_rejected",
        )
        .await;
    store
        .notify(
            NotificationEvent::AccountFailed,
            &app,
            Some("bob"),
            "login_rejected",
        )
        .await;
    store
        .notify(
            NotificationEvent::AccountFailed,
            &app,
            Some("bob"),
            "login_rejected",
        )
        .await;
    let n = store.count_notifications(&app).await;
    assert_eq!(n, 3, "une par (événement, appli, utilisateur) sur la fenêtre");
}
