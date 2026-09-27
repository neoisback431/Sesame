// SPDX-License-Identifier: Apache-2.0
//! Tests de contrat sur une vraie base. Ignorés si `SESAME_TEST_DATABASE_URL` est absente.

use base64::Engine;
use sesame_core::contract;
use sesame_core::crypto::CookieCipher;
use sesame_core::secret::SecretString;
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
