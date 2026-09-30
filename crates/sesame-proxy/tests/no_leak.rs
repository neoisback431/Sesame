// SPDX-License-Identifier: Apache-2.0
//! Absence de fuite de secrets dans les logs et l'audit. Binaire de test séparé :
//! l'abonné `tracing` de test ne doit pas être concurrencé par d'autres tests.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::*;

/// Écrivain de logs partagé, pour inspecter tout ce qui a été journalisé.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn secrets_never_appear_in_logs_or_audit() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let ok = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    ok.get("/").await;
    ok.mock.sessions.lock().unwrap().clear();
    ok.get("/").await;
    // Échec de rejeu : l'appli recopie le mot de passe dans sa page d'erreur.
    let ko = bench(&["fake-app-users"], APP_PASSWORD, true).await;
    ko.secrets.insert(
        "fake-app",
        "alice",
        &[("username", "amartin"), ("password", "wrong-Pw-TOP-SECRET-4242")],
    );
    ko.get("/").await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("rejeu réussi") && logs.contains("rejeu en échec"),
        "logs capturés : {logs}"
    );
    let audit = serde_json::to_string(&[ok.audit.events(), ko.audit.events()]).unwrap();
    for text in [&logs, &audit] {
        assert!(!text.contains(APP_PASSWORD), "mot de passe journalisé");
        assert!(!text.contains("sess-"), "cookie applicatif journalisé");
        assert!(!text.contains(PORTAL_TOKEN), "jeton portail journalisé");
    }
}

#[tokio::test]
async fn access_request_secrets_never_appear_in_logs_or_audit() {
    use common::access::*;
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let b = bench(&["fake-app-users"], APP_PASSWORD, false).await;
    let a = access_bench(&b, true);
    let bad = serde_json::json!({ "username": "amartin", "password": "Mauvais-MDP-777" });
    let good = serde_json::json!({ "username": "amartin", "password": APP_PASSWORD });
    let user = bob(&["fake-app-users"]);
    let mut bodies = Vec::new();
    for fields in [bad, good] {
        bodies.push(
            post_access(&a.router, Some(INTERNAL_TOKEN), &user, fields)
                .await
                .1,
        );
    }

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("demande d'accès"), "logs capturés : {logs}");
    let audit = serde_json::to_string(&b.audit.events()).unwrap();
    for text in bodies.iter().chain([&logs, &audit]) {
        assert!(!text.contains(APP_PASSWORD), "mot de passe divulgué");
        assert!(!text.contains("Mauvais-MDP-777"), "saisie erronée divulguée");
        assert!(!text.contains(INTERNAL_TOKEN), "jeton interne divulgué");
        assert!(!text.contains("sess-"), "cookie applicatif divulgué");
    }
}
