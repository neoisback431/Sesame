// SPDX-License-Identifier: Apache-2.0
//! Tests de contrat partagés : toute implémentation d'une interface doit les passer.
//!
//! Activés par la feature `contract` (dev-dependency des crates d'implémentation).

use std::time::{Duration, SystemTime};

use crate::identity::UserIdentity;
use crate::memory::cookie_value;
use crate::ports::{
    AccessRequests, AccountKey, AccountRegistry, AccountStatus, AppSession, DescriptorStore, DiagnosticStore,
    PortError, PortalSession, ReplayDiagnostic, SessionStore, UserDirectory,
};
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
            email: None,
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
        account_id: "default".into(),
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
    assert_eq!(a.account_id, "default");
    assert!(store.get_app_session(&id, "app2").await.unwrap().is_none());
    // Le compte de la session est conservé (comptes multiples, ADR 0034).
    let mut admin = app_session(&id, "app1", "v-admin", hour);
    admin.account_id = "admin".into();
    store.put_app_session(admin).await.unwrap();
    let a = store.get_app_session(&id, "app1").await.unwrap().unwrap();
    assert_eq!(
        (a.account_id.as_str(), cookie_value(&a, "SESSID").as_deref()),
        ("admin", Some("v-admin"))
    );

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

    // Changement de compte (ADR 0034) : sessions de l'utilisateur sur l'appli détruites dans
    // toutes ses sessions portail, autres applis épargnées.
    let (capp, capp2) = (format!("{prefix}-cpt"), format!("{prefix}-cpt2"));
    for (portal, app) in [(&id, &capp), (&other, &capp), (&id, &capp2)] {
        store
            .put_app_session(app_session(portal, app, "v", hour))
            .await
            .unwrap();
    }
    store.delete_user_app_sessions("alice", &capp).await.unwrap();
    assert!(store.get_app_session(&id, &capp).await.unwrap().is_none());
    assert!(store.get_app_session(&other, &capp).await.unwrap().is_none());
    assert!(store.get_app_session(&id, &capp2).await.unwrap().is_some());
    store.delete_user_app_sessions("bob", &capp2).await.unwrap();
    assert!(store.get_app_session(&id, &capp2).await.unwrap().is_some());
    store.delete_app_session(&id, &capp2).await.unwrap();

    // Suspension (ADR 0033) : par utilisateur et par appli, détruit les sessions applicatives de
    // toutes ses sessions portail, épargne les autres applis et les autres utilisateurs.
    let user = "alice";
    // Applis propres à ce test : la suspension vise tout l'utilisateur, sur un backend partagé.
    let (sapp, sapp2) = (format!("{prefix}-susp"), format!("{prefix}-susp2"));
    assert!(!store.is_app_suspended(user, &sapp).await.unwrap());
    store
        .put_app_session(app_session(&id, &sapp, "v1", hour))
        .await
        .unwrap();
    store
        .put_app_session(app_session(&other, &sapp, "other", hour))
        .await
        .unwrap();
    store
        .put_app_session(app_session(&id, &sapp2, "keep", hour))
        .await
        .unwrap();
    store.suspend_app(user, &sapp).await.unwrap();
    assert!(store.is_app_suspended(user, &sapp).await.unwrap());
    assert!(!store.is_app_suspended(user, &sapp2).await.unwrap());
    assert!(!store.is_app_suspended("bob", &sapp).await.unwrap());
    assert!(store.get_app_session(&id, &sapp).await.unwrap().is_none());
    assert!(store.get_app_session(&other, &sapp).await.unwrap().is_none());
    assert!(store.get_app_session(&id, &sapp2).await.unwrap().is_some());
    assert!(store.suspended_apps(user).await.unwrap().contains(&sapp));
    store.suspend_app(user, &sapp).await.unwrap(); // idempotent
    assert!(store.resume_app(user, &sapp).await.unwrap());
    assert!(!store.resume_app(user, &sapp).await.unwrap(), "déjà levée");
    assert!(!store.is_app_suspended(user, &sapp).await.unwrap());
    store.delete_app_session(&id, &sapp2).await.unwrap();

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

/// Le seed (hors interface : la création relève de l'admin) crée pour (`app`, `user`) le
/// compte `default` actif, par défaut, et un compte supplémentaire `extra` actif.
pub async fn account_registry(registry: &dyn AccountRegistry, app: &str, user: &str, extra: &str) {
    let key = AccountKey::default_of(app, user);
    let extra_key = AccountKey::new(app, user, extra);
    let a = registry.get_account(&key).await.unwrap().expect("compte");
    assert_eq!(a.status, AccountStatus::Active);
    assert!(a.is_default);
    let b = registry
        .get_account(&extra_key)
        .await
        .unwrap()
        .expect("compte supplémentaire");
    assert!(!b.is_default);
    let listed: Vec<String> = registry
        .app_accounts(app, user)
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.account_id)
        .collect();
    assert_eq!(listed, ["default", extra], "compte par défaut en tête");
    assert!(registry.list_accounts("personne").await.unwrap().is_empty());

    registry
        .set_status(&key, AccountStatus::Failed, Some("login_rejected"))
        .await
        .unwrap();
    let a = registry.get_account(&key).await.unwrap().unwrap();
    assert_eq!(a.status, AccountStatus::Failed);
    assert_eq!(a.status_reason.as_deref(), Some("login_rejected"));
    // L'état d'un compte n'affecte pas les autres comptes du couple.
    let b = registry.get_account(&extra_key).await.unwrap().unwrap();
    assert_eq!(b.status, AccountStatus::Active);

    registry
        .set_status(&key, AccountStatus::Active, None)
        .await
        .unwrap();
    registry.record_login(&key, SystemTime::now()).await.unwrap();
    let a = registry.get_account(&key).await.unwrap().unwrap();
    assert_eq!(a.status, AccountStatus::Active);
    assert!(a.status_reason.is_none() && a.last_login_at.is_some());
    assert!(registry
        .get_account(&extra_key)
        .await
        .unwrap()
        .unwrap()
        .last_login_at
        .is_none());

    // Choix du compte (ADR 0034) : par utilisateur et par appli.
    assert_eq!(registry.selected_account(app, user).await.unwrap(), None);
    assert_eq!(
        registry
            .effective_account(app, user)
            .await
            .unwrap()
            .map(|a| a.account_id)
            .as_deref(),
        Some("default")
    );
    registry.select_account(&extra_key).await.unwrap();
    assert_eq!(
        registry.selected_account(app, user).await.unwrap().as_deref(),
        Some(extra)
    );
    assert_eq!(
        registry.selected_accounts(user).await.unwrap(),
        [(app.to_owned(), extra.to_owned())]
    );
    assert!(registry.selected_accounts("personne").await.unwrap().is_empty());
    assert_eq!(
        registry
            .effective_account(app, user)
            .await
            .unwrap()
            .map(|a| a.account_id)
            .as_deref(),
        Some(extra)
    );
    assert_eq!(registry.selected_account(app, "personne").await.unwrap(), None);
    assert!(matches!(
        registry
            .select_account(&AccountKey::new(app, user, "inconnu"))
            .await,
        Err(PortError::NotFound)
    ));
    registry.select_account(&key).await.unwrap();
    assert_eq!(
        registry.selected_account(app, user).await.unwrap().as_deref(),
        Some("default")
    );

    let nobody = AccountKey::default_of(app, "personne");
    assert!(matches!(
        registry.set_status(&nobody, AccountStatus::Disabled, None).await,
        Err(PortError::NotFound)
    ));
    assert!(registry.get_account(&nobody).await.unwrap().is_none());
}

/// `user` ne doit pas encore figurer dans l'annuaire.
pub async fn user_directory(directory: &dyn UserDirectory, user: &str) {
    use crate::ports::UserProfile;

    assert!(directory.get_user(user).await.unwrap().is_none());
    let profile = |name: Option<&str>, email: Option<&str>| UserProfile {
        user_key: user.into(),
        display_name: name.map(str::to_owned),
        email: email.map(str::to_owned),
    };
    directory
        .upsert_user(&profile(Some("Alice Martin"), Some("alice@example.org")))
        .await
        .unwrap();
    assert_eq!(
        directory.get_user(user).await.unwrap(),
        Some(profile(Some("Alice Martin"), Some("alice@example.org")))
    );
    // Un champ absent ne remplace pas la valeur connue ; un champ fourni la met à jour.
    directory
        .upsert_user(&profile(None, Some("alice.martin@example.org")))
        .await
        .unwrap();
    assert_eq!(
        directory.get_user(user).await.unwrap(),
        Some(profile(Some("Alice Martin"), Some("alice.martin@example.org")))
    );
    directory
        .upsert_user(&profile(Some("Alice Dupont"), None))
        .await
        .unwrap();
    assert_eq!(
        directory.get_user(user).await.unwrap(),
        Some(profile(Some("Alice Dupont"), Some("alice.martin@example.org")))
    );
}

/// `fresh` n'a aucun compte ; `existing` a un compte `default` actif ; `extra_only` n'a qu'un
/// compte actif autre que `default` (créés par le seed, hors interface).
pub async fn access_requests(
    requests: &dyn AccessRequests,
    registry: &dyn AccountRegistry,
    app: &str,
    fresh: &str,
    existing: &str,
    extra_only: &str,
) {
    use crate::ports::{AccessRequestKind::*, SubmitOutcome::*};

    // Un autre compte que `default` suffit : pas de demande d'accès (ADR 0034).
    for kind in [Credentials, NoAccount] {
        assert_eq!(
            requests.submit(app, extra_only, kind, None).await.unwrap(),
            AccountExists
        );
    }
    assert!(registry
        .get_account(&AccountKey::default_of(app, extra_only))
        .await
        .unwrap()
        .is_none());

    // Sans compte : « pas de compte » enregistre la demande, sans créer de compte.
    assert_eq!(
        requests
            .submit(app, fresh, NoAccount, Some("besoin"))
            .await
            .unwrap(),
        Recorded
    );
    let fresh_key = AccountKey::default_of(app, fresh);
    let existing_key = AccountKey::default_of(app, existing);
    assert!(registry.get_account(&fresh_key).await.unwrap().is_none());
    let open = requests.open_for_user(fresh).await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(
        (open[0].kind, open[0].note.as_deref()),
        (NoAccount, Some("besoin"))
    );

    // Identifiants fournis : la demande est remplacée et le compte passe en attente.
    assert_eq!(
        requests.submit(app, fresh, Credentials, None).await.unwrap(),
        Recorded
    );
    let open = requests.open_for_user(fresh).await.unwrap();
    assert_eq!(open.len(), 1, "une seule demande par couple");
    assert_eq!(open[0].kind, Credentials);
    let a = registry.get_account(&fresh_key).await.unwrap().unwrap();
    assert_eq!(a.status, AccountStatus::Pending);
    assert!(
        a.is_default,
        "le compte d'une demande d'accès est le compte par défaut"
    );
    // Nouvelle soumission tant que le compte est en attente : remplacement permis.
    assert_eq!(
        requests.submit(app, fresh, Credentials, None).await.unwrap(),
        Recorded
    );

    // Retrait : ni demande ni compte en attente.
    requests.withdraw(app, fresh).await.unwrap();
    assert!(requests.open_for_user(fresh).await.unwrap().is_empty());
    assert!(registry.get_account(&fresh_key).await.unwrap().is_none());

    // Un compte existant (actif, échec, désactivé) n'est jamais modifié.
    for status in [
        AccountStatus::Active,
        AccountStatus::Failed,
        AccountStatus::Disabled,
    ] {
        registry.set_status(&existing_key, status, None).await.unwrap();
        for kind in [Credentials, NoAccount] {
            assert_eq!(
                requests.submit(app, existing, kind, None).await.unwrap(),
                AccountExists
            );
            let a = registry.get_account(&existing_key).await.unwrap().unwrap();
            assert_eq!(a.status, status);
        }
    }
    assert!(requests.open_for_user(existing).await.unwrap().is_empty());
    registry
        .set_status(&existing_key, AccountStatus::Active, None)
        .await
        .unwrap();
    // `withdraw` ne supprime jamais un compte qui n'est pas en attente.
    requests.withdraw(app, existing).await.unwrap();
    assert!(registry.get_account(&existing_key).await.unwrap().is_some());
}

/// Les comptes `default` et `extra` de (`app`, `user`) doivent exister dans le registre (clé
/// étrangère côté base).
pub async fn diagnostic_store(store: &dyn DiagnosticStore, app: &str, user: &str, extra: &str) {
    let key = AccountKey::default_of(app, user);
    let extra_key = AccountKey::new(app, user, extra);
    assert!(store.get_diagnostic(&key).await.unwrap().is_none());
    let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut d = ReplayDiagnostic {
        app_id: app.into(),
        user_key: user.into(),
        account_id: "default".into(),
        correlation_id: "cid-1".into(),
        reason: "login_unexpected_response".into(),
        step: "login_submit".into(),
        method: "POST".into(),
        url: "http://app/login".into(),
        sent_fields: vec!["username".into(), "password".into()],
        status: Some(200),
        headers: vec![("set-cookie".into(), "sid=***; Path=/".into())],
        body: "<h1>Erreur</h1> é".into(),
        body_truncated: false,
        at,
    };
    store.put_diagnostic(d.clone()).await.unwrap();
    assert_eq!(store.get_diagnostic(&key).await.unwrap(), Some(d.clone()));
    assert!(store.get_diagnostic(&extra_key).await.unwrap().is_none());
    // Un diagnostic par compte.
    let mut e = d.clone();
    e.account_id = extra.into();
    e.correlation_id = "cid-extra".into();
    store.put_diagnostic(e.clone()).await.unwrap();
    assert_eq!(store.get_diagnostic(&extra_key).await.unwrap(), Some(e));
    // Seul le dernier diagnostic est conservé.
    d.correlation_id = "cid-2".into();
    d.status = None;
    store.put_diagnostic(d.clone()).await.unwrap();
    assert_eq!(store.get_diagnostic(&key).await.unwrap(), Some(d));
    assert!(store
        .get_diagnostic(&AccountKey::default_of(app, "personne"))
        .await
        .unwrap()
        .is_none());
}

/// `prefix` isole les données d'un test à l'autre sur un backend partagé.
pub async fn descriptor_store(store: &dyn DescriptorStore, prefix: &str) {
    let id = format!("{prefix}-app");
    let v0 = store.version().await.unwrap();
    let doc = serde_json::json!({"metadata": {"id": id, "name": "A"}});

    assert_eq!(
        store
            .put_descriptor(&id, doc.clone(), Some("admin"))
            .await
            .unwrap(),
        1
    );
    let v1 = store.version().await.unwrap();
    assert!(v1 > v0);
    let mut changed = doc.clone();
    changed["metadata"]["name"] = "B".into();
    assert_eq!(store.put_descriptor(&id, changed, None).await.unwrap(), 2);
    assert!(store.version().await.unwrap() > v1);

    let found = store.list_descriptors().await.unwrap();
    let d = found.iter().find(|d| d.app_id == id).expect("descripteur");
    assert_eq!(d.revision, 2);
    assert_eq!(d.document["metadata"]["name"], "B");
    assert!(d.updated_by.is_none());

    let v2 = store.version().await.unwrap();
    store.delete_descriptor(&id, Some("admin")).await.unwrap();
    assert!(store.version().await.unwrap() > v2);
    assert!(!store
        .list_descriptors()
        .await
        .unwrap()
        .iter()
        .any(|d| d.app_id == id));
    assert!(matches!(
        store.delete_descriptor(&id, None).await,
        Err(PortError::NotFound)
    ));
    // Recréé après suppression : l'historique continue, la révision repart de 1.
    assert_eq!(store.put_descriptor(&id, doc, None).await.unwrap(), 1);
    store.delete_descriptor(&id, None).await.unwrap();
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::memory::{MemoryAccessRequests, MemoryAccountRegistry, MemorySessionStore};

    #[tokio::test]
    async fn memory_session_store() {
        super::session_store(&MemorySessionStore::default(), "t").await;
    }

    #[tokio::test]
    async fn memory_descriptor_store() {
        super::descriptor_store(&crate::memory::MemoryDescriptorStore::default(), "t").await;
    }

    #[tokio::test]
    async fn memory_diagnostic_store() {
        super::diagnostic_store(
            &crate::memory::MemoryDiagnosticStore::default(),
            "app1",
            "alice",
            "admin",
        )
        .await;
    }

    #[tokio::test]
    async fn memory_account_registry() {
        use crate::ports::{AccountKey, AccountStatus, AppAccount};
        let r = MemoryAccountRegistry::with_active(&[("app1", "alice")]);
        r.upsert(AppAccount::new(
            &AccountKey::new("app1", "alice", "admin"),
            AccountStatus::Active,
            false,
        ));
        super::account_registry(&r, "app1", "alice", "admin").await;
    }

    #[tokio::test]
    async fn memory_access_requests() {
        use crate::ports::{AccountKey, AccountStatus, AppAccount};
        let r = Arc::new(MemoryAccountRegistry::with_active(&[("app1", "alice")]));
        r.upsert(AppAccount::new(
            &AccountKey::new("app1", "carol", "admin"),
            AccountStatus::Active,
            true,
        ));
        super::access_requests(
            &MemoryAccessRequests::new(r.clone()),
            &*r,
            "app1",
            "nouveau",
            "alice",
            "carol",
        )
        .await;
    }
}
