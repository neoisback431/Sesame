// SPDX-License-Identifier: Apache-2.0
//! Implémentations en mémoire des interfaces, pour les tests et le dev local.
//! Aucune persistance, aucun chiffrement : ne pas utiliser en production.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;

use crate::audit::AuditEvent;
use crate::ports::{
    AccessRequest, AccessRequestKind, AccessRequests, AccountKey, AccountRegistry, AccountStatus, AppAccount,
    AppSession, AuditSink, DescriptorStore, DiagnosticStore, NotificationEvent, Notifier, PortError,
    PortResult, PortalSession, ReplayDiagnostic, SecretStore, SecretWriter, SessionStore, StoredDescriptor,
    SubmitOutcome, UserDirectory, UserProfile,
};
use crate::secret::{Credential, ExposeSecret, SecretString};

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Default)]
pub struct MemorySessionStore {
    portal: Mutex<HashMap<String, PortalSession>>,
    apps: Mutex<HashMap<(String, String), AppSession>>,
    /// (appli, utilisateur) dont la connexion automatique est suspendue.
    suspended: Mutex<std::collections::HashSet<(String, String)>>,
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn create_portal_session(&self, session: PortalSession) -> PortResult<()> {
        locked(&self.portal).insert(session.id.clone(), session);
        Ok(())
    }

    async fn get_portal_session(&self, id: &str) -> PortResult<Option<PortalSession>> {
        let now = SystemTime::now();
        Ok(locked(&self.portal)
            .get(id)
            .filter(|s| s.expires_at > now)
            .cloned())
    }

    async fn delete_portal_session(&self, id: &str) -> PortResult<()> {
        locked(&self.portal).remove(id);
        locked(&self.apps).retain(|(p, _), _| p != id);
        Ok(())
    }

    async fn put_app_session(&self, session: AppSession) -> PortResult<()> {
        let key = (session.portal_session_id.clone(), session.app_id.clone());
        locked(&self.apps).insert(key, session);
        Ok(())
    }

    async fn get_app_session(&self, portal_session_id: &str, app_id: &str) -> PortResult<Option<AppSession>> {
        let now = SystemTime::now();
        let key = (portal_session_id.to_owned(), app_id.to_owned());
        Ok(locked(&self.apps)
            .get(&key)
            .filter(|s| s.expires_at > now)
            .cloned())
    }

    async fn touch_app_session(
        &self,
        portal_session_id: &str,
        app_id: &str,
        at: SystemTime,
    ) -> PortResult<()> {
        let key = (portal_session_id.to_owned(), app_id.to_owned());
        if let Some(s) = locked(&self.apps).get_mut(&key) {
            s.last_used_at = at;
        }
        Ok(())
    }

    async fn delete_app_session(&self, portal_session_id: &str, app_id: &str) -> PortResult<()> {
        locked(&self.apps).remove(&(portal_session_id.to_owned(), app_id.to_owned()));
        Ok(())
    }

    async fn delete_user_app_sessions(&self, user_key: &str, app_id: &str) -> PortResult<()> {
        let portal = locked(&self.portal);
        locked(&self.apps)
            .retain(|(p, a), _| a != app_id || portal.get(p).is_none_or(|s| s.user.user_key != user_key));
        Ok(())
    }

    async fn suspend_app(&self, user_key: &str, app_id: &str) -> PortResult<()> {
        locked(&self.suspended).insert((app_id.to_owned(), user_key.to_owned()));
        self.delete_user_app_sessions(user_key, app_id).await
    }

    async fn resume_app(&self, user_key: &str, app_id: &str) -> PortResult<bool> {
        Ok(locked(&self.suspended).remove(&(app_id.to_owned(), user_key.to_owned())))
    }

    async fn is_app_suspended(&self, user_key: &str, app_id: &str) -> PortResult<bool> {
        Ok(locked(&self.suspended).contains(&(app_id.to_owned(), user_key.to_owned())))
    }

    async fn suspended_apps(&self, user_key: &str) -> PortResult<Vec<String>> {
        let mut out: Vec<String> = locked(&self.suspended)
            .iter()
            .filter(|(_, u)| u == user_key)
            .map(|(a, _)| a.clone())
            .collect();
        out.sort();
        Ok(out)
    }

    async fn purge_expired(&self, now: SystemTime) -> PortResult<u64> {
        let mut portal = locked(&self.portal);
        let mut apps = locked(&self.apps);
        let before = portal.len() + apps.len();
        portal.retain(|_, s| s.expires_at > now);
        apps.retain(|(p, _), s| s.expires_at > now && portal.contains_key(p));
        Ok((before - portal.len() - apps.len()) as u64)
    }
}

#[derive(Default)]
pub struct MemoryAccountRegistry {
    accounts: Mutex<HashMap<AccountKey, AppAccount>>,
    /// (appli, utilisateur) -> compte choisi.
    selected: Mutex<HashMap<(String, String), String>>,
}

impl MemoryAccountRegistry {
    /// Comptes `default` actifs.
    pub fn with_active(accounts: &[(&str, &str)]) -> Self {
        let registry = Self::default();
        for (app_id, user_key) in accounts {
            registry.upsert(AppAccount::new(
                &AccountKey::default_of(app_id, user_key),
                AccountStatus::Active,
                true,
            ));
        }
        registry
    }

    pub fn upsert(&self, account: AppAccount) {
        locked(&self.accounts).insert(account.key(), account);
    }

    fn remove(&self, key: &AccountKey) {
        locked(&self.accounts).remove(key);
    }
}

#[async_trait]
impl AccountRegistry for MemoryAccountRegistry {
    async fn get_account(&self, key: &AccountKey) -> PortResult<Option<AppAccount>> {
        Ok(locked(&self.accounts).get(key).cloned())
    }

    async fn list_accounts(&self, user_key: &str) -> PortResult<Vec<AppAccount>> {
        let mut out: Vec<_> = locked(&self.accounts)
            .values()
            .filter(|a| a.user_key == user_key)
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            (&a.app_id, !a.is_default, &a.account_id).cmp(&(&b.app_id, !b.is_default, &b.account_id))
        });
        Ok(out)
    }

    async fn set_status(
        &self,
        key: &AccountKey,
        status: AccountStatus,
        reason: Option<&str>,
    ) -> PortResult<()> {
        let mut accounts = locked(&self.accounts);
        let account = accounts.get_mut(key).ok_or(PortError::NotFound)?;
        account.status = status;
        account.status_reason = reason.map(str::to_owned);
        Ok(())
    }

    async fn record_login(&self, key: &AccountKey, at: SystemTime) -> PortResult<()> {
        let mut accounts = locked(&self.accounts);
        let account = accounts.get_mut(key).ok_or(PortError::NotFound)?;
        account.last_login_at = Some(at);
        Ok(())
    }

    async fn select_account(&self, key: &AccountKey) -> PortResult<()> {
        if !locked(&self.accounts).contains_key(key) {
            return Err(PortError::NotFound);
        }
        locked(&self.selected).insert((key.app_id.clone(), key.user_key.clone()), key.account_id.clone());
        Ok(())
    }

    async fn selected_account(&self, app_id: &str, user_key: &str) -> PortResult<Option<String>> {
        Ok(locked(&self.selected)
            .get(&(app_id.to_owned(), user_key.to_owned()))
            .cloned())
    }

    async fn selected_accounts(&self, user_key: &str) -> PortResult<Vec<(String, String)>> {
        let mut out: Vec<_> = locked(&self.selected)
            .iter()
            .filter(|((_, u), _)| u == user_key)
            .map(|((a, _), id)| (a.clone(), id.clone()))
            .collect();
        out.sort();
        Ok(out)
    }
}

/// Diagnostics de rejeu en mémoire : compte -> dernier diagnostic.
#[derive(Default)]
pub struct MemoryDiagnosticStore {
    entries: Mutex<HashMap<AccountKey, ReplayDiagnostic>>,
}

#[async_trait]
impl DiagnosticStore for MemoryDiagnosticStore {
    async fn put_diagnostic(&self, diagnostic: ReplayDiagnostic) -> PortResult<()> {
        locked(&self.entries).insert(diagnostic.key(), diagnostic);
        Ok(())
    }

    async fn get_diagnostic(&self, key: &AccountKey) -> PortResult<Option<ReplayDiagnostic>> {
        Ok(locked(&self.entries).get(key).cloned())
    }
}

/// Coffre en mémoire : compte -> champs.
#[derive(Default)]
pub struct MemorySecretStore {
    entries: Mutex<HashMap<AccountKey, BTreeMap<String, String>>>,
    reads: Mutex<u64>,
}

impl MemorySecretStore {
    /// Identifiants du compte `default`.
    pub fn insert(&self, app_id: &str, user_key: &str, fields: &[(&str, &str)]) {
        self.insert_account(&AccountKey::default_of(app_id, user_key), fields);
    }

    pub fn insert_account(&self, key: &AccountKey, fields: &[(&str, &str)]) {
        let fields = fields.iter().map(|(k, v)| ((*k).into(), (*v).into())).collect();
        locked(&self.entries).insert(key.clone(), fields);
    }

    /// Nombre de lectures effectuées (pour vérifier qu'un chemin ne lit pas le coffre).
    pub fn reads(&self) -> u64 {
        *locked(&self.reads)
    }
}

#[async_trait]
impl SecretStore for MemorySecretStore {
    async fn get_credential(&self, key: &AccountKey) -> PortResult<Credential> {
        *locked(&self.reads) += 1;
        let entries = locked(&self.entries);
        let fields = entries.get(key).ok_or(PortError::NotFound)?;
        Ok(Credential::new(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), SecretString::from(v.as_str())))
                .collect(),
        ))
    }
}

#[async_trait]
impl SecretWriter for MemorySecretStore {
    async fn put_credential(&self, key: &AccountKey, credential: &Credential) -> PortResult<()> {
        let fields = credential
            .keys()
            .filter_map(|k| {
                credential
                    .get(k)
                    .map(|v| (k.to_owned(), v.expose_secret().to_owned()))
            })
            .collect();
        locked(&self.entries).insert(key.clone(), fields);
        Ok(())
    }
}

/// Annuaire des utilisateurs en mémoire.
#[derive(Default)]
pub struct MemoryUserDirectory {
    users: Mutex<HashMap<String, UserProfile>>,
}

impl MemoryUserDirectory {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserDirectory for MemoryUserDirectory {
    async fn upsert_user(&self, profile: &UserProfile) -> PortResult<()> {
        let mut users = locked(&self.users);
        let entry = users
            .entry(profile.user_key.clone())
            .or_insert_with(|| UserProfile {
                user_key: profile.user_key.clone(),
                display_name: None,
                email: None,
            });
        if profile.display_name.is_some() {
            entry.display_name.clone_from(&profile.display_name);
        }
        if profile.email.is_some() {
            entry.email.clone_from(&profile.email);
        }
        Ok(())
    }

    async fn get_user(&self, user_key: &str) -> PortResult<Option<UserProfile>> {
        Ok(locked(&self.users).get(user_key).cloned())
    }
}

/// Demandes d'accès en mémoire, adossées au registre des comptes en mémoire.
pub struct MemoryAccessRequests {
    accounts: Arc<MemoryAccountRegistry>,
    requests: Mutex<HashMap<(String, String), AccessRequest>>,
}

impl MemoryAccessRequests {
    pub fn new(accounts: Arc<MemoryAccountRegistry>) -> Self {
        Self {
            accounts,
            requests: Mutex::default(),
        }
    }
}

#[async_trait]
impl AccessRequests for MemoryAccessRequests {
    async fn submit(
        &self,
        app_id: &str,
        user_key: &str,
        kind: AccessRequestKind,
        note: Option<&str>,
    ) -> PortResult<SubmitOutcome> {
        let key = AccountKey::default_of(app_id, user_key);
        let existing = self.accounts.app_accounts(app_id, user_key).await?;
        let only_pending_default = existing
            .iter()
            .all(|a| a.status == AccountStatus::Pending && a.account_id == key.account_id);
        match (existing.is_empty(), only_pending_default, kind) {
            (true, _, AccessRequestKind::NoAccount) => {}
            (_, true, AccessRequestKind::Credentials) => {
                let mut account = AppAccount::new(&key, AccountStatus::Pending, true);
                account.status_reason = Some("access_request".into());
                self.accounts.upsert(account);
            }
            _ => return Ok(SubmitOutcome::AccountExists),
        }
        locked(&self.requests).insert(
            (app_id.into(), user_key.into()),
            AccessRequest {
                app_id: app_id.into(),
                user_key: user_key.into(),
                kind,
                note: note.map(str::to_owned),
                created_at: SystemTime::now(),
            },
        );
        Ok(SubmitOutcome::Recorded)
    }

    async fn withdraw(&self, app_id: &str, user_key: &str) -> PortResult<()> {
        locked(&self.requests).remove(&(app_id.to_owned(), user_key.to_owned()));
        let key = AccountKey::default_of(app_id, user_key);
        if let Some(a) = self.accounts.get_account(&key).await? {
            if a.status == AccountStatus::Pending {
                self.accounts.remove(&key);
            }
        }
        Ok(())
    }

    async fn open_for_user(&self, user_key: &str) -> PortResult<Vec<AccessRequest>> {
        Ok(locked(&self.requests)
            .values()
            .filter(|r| r.user_key == user_key)
            .cloned()
            .collect())
    }
}

/// Événement déposé : (type, appli, utilisateur, motif).
pub type NotifiedEvent = (NotificationEvent, String, Option<String>, String);

/// Notifications en mémoire : événements déposés, sans regroupement.
#[derive(Default)]
pub struct MemoryNotifier {
    events: Mutex<Vec<NotifiedEvent>>,
}

impl MemoryNotifier {
    pub fn events(&self) -> Vec<NotifiedEvent> {
        locked(&self.events).clone()
    }
}

#[async_trait]
impl Notifier for MemoryNotifier {
    async fn notify(&self, event: NotificationEvent, app_id: &str, user_key: Option<&str>, reason: &str) {
        locked(&self.events).push((event, app_id.into(), user_key.map(str::to_owned), reason.into()));
    }
}

/// Journal d'audit en mémoire, consultable par les tests.
#[derive(Default)]
pub struct MemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemoryAuditSink {
    pub fn events(&self) -> Vec<AuditEvent> {
        locked(&self.events).clone()
    }
}

#[async_trait]
impl AuditSink for MemoryAuditSink {
    async fn record(&self, event: AuditEvent) -> PortResult<()> {
        locked(&self.events).push(event);
        Ok(())
    }
}

/// Descripteurs en mémoire.
#[derive(Default)]
pub struct MemoryDescriptorStore {
    entries: Mutex<BTreeMap<String, StoredDescriptor>>,
    version: Mutex<i64>,
}

#[async_trait]
impl DescriptorStore for MemoryDescriptorStore {
    async fn list_descriptors(&self) -> PortResult<Vec<StoredDescriptor>> {
        Ok(locked(&self.entries).values().cloned().collect())
    }

    async fn version(&self) -> PortResult<i64> {
        Ok(*locked(&self.version))
    }

    async fn put_descriptor(
        &self,
        app_id: &str,
        document: serde_json::Value,
        by: Option<&str>,
    ) -> PortResult<u32> {
        let mut entries = locked(&self.entries);
        let revision = entries.get(app_id).map_or(1, |d| d.revision + 1);
        entries.insert(
            app_id.to_owned(),
            StoredDescriptor {
                app_id: app_id.to_owned(),
                revision,
                document,
                updated_at: SystemTime::now(),
                updated_by: by.map(str::to_owned),
            },
        );
        *locked(&self.version) += 1;
        Ok(revision)
    }

    async fn delete_descriptor(&self, app_id: &str, _by: Option<&str>) -> PortResult<()> {
        locked(&self.entries).remove(app_id).ok_or(PortError::NotFound)?;
        *locked(&self.version) += 1;
        Ok(())
    }
}

/// Aide pour les tests : valeur exposée d'un cookie de session.
pub fn cookie_value(session: &AppSession, name: &str) -> Option<String> {
    session
        .cookies
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.value.expose_secret().to_owned())
}

#[cfg(test)]
mod effective_account_tests {
    use crate::ports::{effective_account, AccountKey, AccountStatus, AppAccount};

    fn acc(id: &str, status: AccountStatus, is_default: bool) -> AppAccount {
        AppAccount::new(&AccountKey::new("app", "alice", id), status, is_default)
    }

    fn pick(accounts: Vec<AppAccount>, selected: Option<&str>) -> Option<String> {
        effective_account(accounts, selected).map(|a| a.account_id)
    }

    #[test]
    fn selected_then_default_then_any_usable() {
        use AccountStatus::*;
        let all = || {
            vec![
                acc("default", Active, true),
                acc("admin", Active, false),
                acc("off", Disabled, false),
            ]
        };
        assert_eq!(pick(all(), None).as_deref(), Some("default"));
        assert_eq!(pick(all(), Some("admin")).as_deref(), Some("admin"));
        // Choix devenu invalide (supprimé ou désactivé) : compte par défaut.
        assert_eq!(pick(all(), Some("gone")).as_deref(), Some("default"));
        assert_eq!(pick(all(), Some("off")).as_deref(), Some("default"));
        // Compte par défaut désactivé : un autre compte utilisable.
        let v = vec![acc("default", Disabled, true), acc("admin", Failed, false)];
        assert_eq!(pick(v, None).as_deref(), Some("admin"));
        // Rien d'utilisable : le compte par défaut, pour tracer le refus.
        let v = vec![acc("x", Disabled, false), acc("default", Disabled, true)];
        assert_eq!(pick(v, None).as_deref(), Some("default"));
        assert_eq!(pick(vec![], Some("admin")), None);
    }
}

#[cfg(test)]
mod user_directory_tests {
    use super::MemoryUserDirectory;

    #[tokio::test]
    async fn memory_user_directory_honors_the_contract() {
        crate::contract::user_directory(&MemoryUserDirectory::new(), "alice").await;
    }
}
