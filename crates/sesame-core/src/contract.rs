// SPDX-License-Identifier: Apache-2.0
//! Tests de contrat partagés : toute implémentation d'une interface doit les passer.
//!
//! Activés par la feature `contract` (dev-dependency des crates d'implémentation).

use std::time::{Duration, SystemTime};

use crate::identity::UserIdentity;
use crate::memory::cookie_value;
use crate::ports::{AccountRegistry, AccountStatus, AppSession, PortError, PortalSession, SessionStore};
use crate::secret::AppCookie;

fn portal_session(id: &str, ttl: Duration) -> PortalSession {
    let now = SystemTime::now();
    PortalSession {
        id: id.into(),
        user: UserIdentity {
            issuer: "https://idp.example".into(),
            subject: "sub-1".into(),
            user_key: "alice".into(),
            display_name: Some("Alice".into()),
            groups: vec!["g1".into(), "g2".into()],
        },
        created_at: now,
        expires_at: now + ttl,
    }
}

fn app_session(portal: &str, app: &str, value: &str, ttl: Duration) -> AppSession {
    let now = SystemTime::now();
    AppSession {
        portal_session_id: portal.into(),
        app_id: app.into(),
        cookies: vec![AppCookie::new("SESSID", value), AppCookie::new("lang", "fr")],
        created_at: now,
        last_used_at: now,
        expires_at: now + ttl,
    }
}

/// `prefix` isole les données d'un test à l'autre sur un backend partagé.
pub async fn session_store(store: &dyn SessionStore, prefix: &str) {
    let hour = Duration::from_secs(3600);
    let id = format!("{prefix}-s1");
    let other = format!("{prefix}-s2");

    store
        .create_portal_session(portal_session(&id, hour))
        .await
        .unwrap();
    store
        .create_portal_session(portal_session(&other, hour))
        .await
        .unwrap();
    let got = store
        .get_portal_session(&id)
        .await
        .unwrap()
        .expect("session portail");
    assert_eq!(got.user.user_key, "alice");
    assert_eq!(got.user.groups, ["g1", "g2"]);
    assert!(store
        .get_portal_session(&format!("{prefix}-absent"))
        .await
        .unwrap()
        .is_none());

    // Session portail expirée : invisible.
    let expired = format!("{prefix}-expired");
    let mut s = portal_session(&expired, hour);
    s.expires_at = SystemTime::now() - Duration::from_secs(1);
    store.create_portal_session(s).await.unwrap();
    assert!(store.get_portal_session(&expired).await.unwrap().is_none());

    // Sessions applicatives : écriture, lecture, remplacement.
    store
        .put_app_session(app_session(&id, "app1", "v1", hour))
        .await
        .unwrap();
    store
        .put_app_session(app_session(&other, "app1", "other", hour))
        .await
        .unwrap();
    let a = store
        .get_app_session(&id, "app1")
        .await
        .unwrap()
        .expect("session applicative");
    assert_eq!(cookie_value(&a, "SESSID").as_deref(), Some("v1"));
    assert_eq!(cookie_value(&a, "lang").as_deref(), Some("fr"));
    store
        .put_app_session(app_session(&id, "app1", "v2", hour))
        .await
        .unwrap();
    let a = store.get_app_session(&id, "app1").await.unwrap().unwrap();
    assert_eq!(cookie_value(&a, "SESSID").as_deref(), Some("v2"));
    assert!(store.get_app_session(&id, "app2").await.unwrap().is_none());

    store
        .touch_app_session(&id, "app1", SystemTime::now())
        .await
        .unwrap();

    // Session applicative expirée : invisible.
    store
        .put_app_session(app_session(&id, "app-expired", "x", Duration::ZERO))
        .await
        .unwrap();
    assert!(store.get_app_session(&id, "app-expired").await.unwrap().is_none());

    store.delete_app_session(&id, "app1").await.unwrap();
    assert!(store.get_app_session(&id, "app1").await.unwrap().is_none());

    // Déconnexion du portail : sessions applicatives détruites, autres sessions intactes.
    store
        .put_app_session(app_session(&id, "app1", "v3", hour))
        .await
        .unwrap();
    store.delete_portal_session(&id).await.unwrap();
    assert!(store.get_portal_session(&id).await.unwrap().is_none());
    assert!(store.get_app_session(&id, "app1").await.unwrap().is_none());
    assert!(store.get_app_session(&other, "app1").await.unwrap().is_some());

    let purged = store.purge_expired(SystemTime::now()).await.unwrap();
    assert!(purged >= 1, "la session portail expirée doit être purgée");
    store.delete_portal_session(&other).await.unwrap();
}

/// `seed` crée le compte actif (app, user) : la création relève de l'admin, hors interface.
pub async fn account_registry(registry: &dyn AccountRegistry, app: &str, user: &str) {
    let a = registry.get_account(app, user).await.unwrap().expect("compte");
    assert_eq!(a.status, AccountStatus::Active);
    assert!(registry
        .list_accounts(user)
        .await
        .unwrap()
        .iter()
        .any(|a| a.app_id == app));
    assert!(registry.list_accounts("personne").await.unwrap().is_empty());

    registry
        .set_status(app, user, AccountStatus::Failed, Some("login_rejected"))
        .await
        .unwrap();
    let a = registry.get_account(app, user).await.unwrap().unwrap();
    assert_eq!(a.status, AccountStatus::Failed);
    assert_eq!(a.status_reason.as_deref(), Some("login_rejected"));

    registry
        .set_status(app, user, AccountStatus::Active, None)
        .await
        .unwrap();
    registry.record_login(app, user, SystemTime::now()).await.unwrap();
    let a = registry.get_account(app, user).await.unwrap().unwrap();
    assert_eq!(a.status, AccountStatus::Active);
    assert!(a.status_reason.is_none() && a.last_login_at.is_some());

    assert!(matches!(
        registry
            .set_status(app, "personne", AccountStatus::Disabled, None)
            .await,
        Err(PortError::NotFound)
    ));
    assert!(registry.get_account(app, "personne").await.unwrap().is_none());
}

#[cfg(test)]
mod tests {
    use crate::memory::{MemoryAccountRegistry, MemorySessionStore};

    #[tokio::test]
    async fn memory_session_store() {
        super::session_store(&MemorySessionStore::default(), "t").await;
    }

    #[tokio::test]
    async fn memory_account_registry() {
        let r = MemoryAccountRegistry::with_active(&[("app1", "alice")]);
        super::account_registry(&r, "app1", "alice").await;
    }
}
