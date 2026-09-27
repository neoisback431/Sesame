// SPDX-License-Identifier: Apache-2.0
//! Implémentations en mémoire des interfaces, pour les tests et le dev local.
//! Aucune persistance, aucun chiffrement : ne pas utiliser en production.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::SystemTime;

use async_trait::async_trait;

use crate::audit::AuditEvent;
use crate::ports::{
    AccountRegistry, AccountStatus, AppAccount, AppSession, AuditSink, DescriptorStore, DiagnosticStore,
    PortError, PortResult, PortalSession, ReplayDiagnostic, SecretStore, SessionStore, StoredDescriptor,
};
use crate::secret::{Credential, ExposeSecret, SecretString};

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Default)]
pub struct MemorySessionStore {
    portal: Mutex<HashMap<String, PortalSession>>,
    apps: Mutex<HashMap<(String, String), AppSession>>,
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
    accounts: Mutex<HashMap<(String, String), AppAccount>>,
}

impl MemoryAccountRegistry {
    pub fn with_active(accounts: &[(&str, &str)]) -> Self {
        let registry = Self::default();
        for (app_id, user_key) in accounts {
            registry.upsert(AppAccount {
                app_id: (*app_id).into(),
                user_key: (*user_key).into(),
                status: AccountStatus::Active,
                status_reason: None,
                last_login_at: None,
            });
        }
        registry
    }

    pub fn upsert(&self, account: AppAccount) {
        let key = (account.app_id.clone(), account.user_key.clone());
        locked(&self.accounts).insert(key, account);
    }
}

#[async_trait]
impl AccountRegistry for MemoryAccountRegistry {
    async fn get_account(&self, app_id: &str, user_key: &str) -> PortResult<Option<AppAccount>> {
        Ok(locked(&self.accounts)
            .get(&(app_id.to_owned(), user_key.to_owned()))
            .cloned())
    }

    async fn list_accounts(&self, user_key: &str) -> PortResult<Vec<AppAccount>> {
        let mut out: Vec<_> = locked(&self.accounts)
            .values()
            .filter(|a| a.user_key == user_key)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        Ok(out)
    }

    async fn set_status(
        &self,
        app_id: &str,
        user_key: &str,
        status: AccountStatus,
        reason: Option<&str>,
    ) -> PortResult<()> {
        let mut accounts = locked(&self.accounts);
        let account = accounts
            .get_mut(&(app_id.to_owned(), user_key.to_owned()))
            .ok_or(PortError::NotFound)?;
        account.status = status;
        account.status_reason = reason.map(str::to_owned);
        Ok(())
    }

    async fn record_login(&self, app_id: &str, user_key: &str, at: SystemTime) -> PortResult<()> {
        let mut accounts = locked(&self.accounts);
        let account = accounts
            .get_mut(&(app_id.to_owned(), user_key.to_owned()))
            .ok_or(PortError::NotFound)?;
        account.last_login_at = Some(at);
        Ok(())
    }
}

/// Diagnostics de rejeu en mémoire : (appli, utilisateur) -> dernier diagnostic.
#[derive(Default)]
pub struct MemoryDiagnosticStore {
    entries: Mutex<HashMap<(String, String), ReplayDiagnostic>>,
}

#[async_trait]
impl DiagnosticStore for MemoryDiagnosticStore {
    async fn put_diagnostic(&self, diagnostic: ReplayDiagnostic) -> PortResult<()> {
        let key = (diagnostic.app_id.clone(), diagnostic.user_key.clone());
        locked(&self.entries).insert(key, diagnostic);
        Ok(())
    }

    async fn get_diagnostic(&self, app_id: &str, user_key: &str) -> PortResult<Option<ReplayDiagnostic>> {
        Ok(locked(&self.entries)
            .get(&(app_id.to_owned(), user_key.to_owned()))
            .cloned())
    }
}

/// Coffre en mémoire : (appli, utilisateur) -> champs.
#[derive(Default)]
pub struct MemorySecretStore {
    entries: Mutex<HashMap<(String, String), BTreeMap<String, String>>>,
    reads: Mutex<u64>,
}

impl MemorySecretStore {
    pub fn insert(&self, app_id: &str, user_key: &str, fields: &[(&str, &str)]) {
        let fields = fields.iter().map(|(k, v)| ((*k).into(), (*v).into())).collect();
        locked(&self.entries).insert((app_id.into(), user_key.into()), fields);
    }

    /// Nombre de lectures effectuées (pour vérifier qu'un chemin ne lit pas le coffre).
    pub fn reads(&self) -> u64 {
        *locked(&self.reads)
    }
}

#[async_trait]
impl SecretStore for MemorySecretStore {
    async fn get_credential(&self, app_id: &str, user_key: &str) -> PortResult<Credential> {
        *locked(&self.reads) += 1;
        let entries = locked(&self.entries);
        let fields = entries
            .get(&(app_id.to_owned(), user_key.to_owned()))
            .ok_or(PortError::NotFound)?;
        Ok(Credential::new(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), SecretString::from(v.as_str())))
                .collect(),
        ))
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
