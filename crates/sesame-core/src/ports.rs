// SPDX-License-Identifier: Apache-2.0
//! Interfaces des briques externes.
//!
//! Chaque brique (coffre, magasin de sessions, registre des comptes, journal
//! d'audit) est un trait ; les implémentations (OpenBao/Vault, PostgreSQL,
//! fichier…) vivent dans leur propre module et sont choisies par configuration. Aucun type propre à un
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

/// Session portail.
///
/// `id` est l'empreinte (`crypto::hash_token`) du jeton opaque porté par le
/// cookie du portail : le jeton lui-même n'est jamais stocké.
#[derive(Debug, Clone)]
pub struct PortalSession {
    pub id: String,
    pub user: UserIdentity,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

/// Session applicative rattachée à une session portail.
#[derive(Debug, Clone)]
pub struct AppSession {
    /// Empreinte du jeton de session portail.
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

/// État d'un compte applicatif dans le registre des comptes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    /// Compte provisionné : tuile affichée, rejeu autorisé.
    Active,
    /// Dernier rejeu en échec : tuile signalée, rejeu bloqué jusqu'à correction.
    Failed,
    /// Désactivé par un administrateur : tuile masquée, rejeu bloqué.
    Disabled,
}

/// Entrée du registre des comptes. Ne contient aucun secret.
#[derive(Debug, Clone)]
pub struct AppAccount {
    pub app_id: String,
    pub user_key: String,
    pub status: AccountStatus,
    /// Code court, jamais un contenu de réponse de l'appli.
    pub status_reason: Option<String>,
    pub last_login_at: Option<SystemTime>,
}

/// Registre des comptes : quelles applis ont un compte pour quel utilisateur.
///
/// Permet au portail d'afficher les applis sans accéder au coffre.
/// Alimenté par l'UI d'admin, mis à jour par le proxy après chaque rejeu.
#[async_trait]
pub trait AccountRegistry: Send + Sync {
    async fn get_account(&self, app_id: &str, user_key: &str) -> PortResult<Option<AppAccount>>;
    /// Comptes d'un utilisateur, tous états confondus.
    async fn list_accounts(&self, user_key: &str) -> PortResult<Vec<AppAccount>>;
    async fn set_status(
        &self,
        app_id: &str,
        user_key: &str,
        status: AccountStatus,
        reason: Option<&str>,
    ) -> PortResult<()>;
    async fn record_login(&self, app_id: &str, user_key: &str, at: SystemTime) -> PortResult<()>;
}

/// Journal d'audit dédié.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Une erreur d'écriture d'audit doit faire échouer l'opération auditée.
    async fn record(&self, event: AuditEvent) -> PortResult<()>;
}
