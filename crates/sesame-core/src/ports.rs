// SPDX-License-Identifier: Apache-2.0
//! Interfaces des briques externes.
//!
//! Chaque brique (coffre, magasin de sessions, journal d'audit) est un trait ;
//! les implémentations (OpenBao/Vault, PostgreSQL, fichier…) vivent dans leur
//! propre module et sont choisies par configuration. Aucun type propre à un
//! fournisseur n'apparaît ici.

use std::time::SystemTime;

use async_trait::async_trait;

use crate::audit::AuditEvent;
use crate::identity::UserIdentity;
use crate::secret::{AppCookie, Credential};

#[derive(Debug, thiserror::Error)]
pub enum PortError {
    #[error("introuvable")]
    NotFound,
    #[error("backend indisponible : {0}")]
    Unavailable(String),
    #[error("accès refusé par le backend")]
    Forbidden,
    /// Le message ne doit jamais contenir de secret.
    #[error("{0}")]
    Other(String),
}

pub type PortResult<T> = Result<T, PortError>;

/// Coffre de secrets. Seul le moteur de proxy l'utilise.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Lit les identifiants du couple (appli, utilisateur).
    /// L'appelant émet l'événement d'audit `SecretRead`, succès ou échec.
    async fn get_credential(&self, app_id: &str, user_key: &str) -> PortResult<Credential>;
}

/// Session portail, identifiée par un jeton opaque porté par le cookie du portail.
#[derive(Debug, Clone)]
pub struct PortalSession {
    pub id: String,
    pub user: UserIdentity,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

/// Session applicative rattachée à une session portail.
#[derive(Debug)]
pub struct AppSession {
    pub portal_session_id: String,
    pub app_id: String,
    pub cookies: Vec<AppCookie>,
    pub created_at: SystemTime,
    pub last_used_at: SystemTime,
    pub expires_at: SystemTime,
}

/// Magasin de sessions : session portail -> sessions applicatives.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_portal_session(&self, session: PortalSession) -> PortResult<()>;
    async fn get_portal_session(&self, id: &str) -> PortResult<Option<PortalSession>>;
    /// Supprime la session portail et toutes ses sessions applicatives.
    async fn delete_portal_session(&self, id: &str) -> PortResult<()>;

    async fn put_app_session(&self, session: AppSession) -> PortResult<()>;
    async fn get_app_session(&self, portal_session_id: &str, app_id: &str) -> PortResult<Option<AppSession>>;
    async fn touch_app_session(
        &self,
        portal_session_id: &str,
        app_id: &str,
        at: SystemTime,
    ) -> PortResult<()>;
    async fn delete_app_session(&self, portal_session_id: &str, app_id: &str) -> PortResult<()>;

    /// Purge les sessions expirées ; renvoie le nombre de sessions supprimées.
    async fn purge_expired(&self, now: SystemTime) -> PortResult<u64>;
}

/// Journal d'audit dédié.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Une erreur d'écriture d'audit doit faire échouer l'opération auditée.
    async fn record(&self, event: AuditEvent) -> PortResult<()>;
}
