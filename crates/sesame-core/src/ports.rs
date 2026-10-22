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

/// Identifiant du compte créé en premier pour un couple (appli, utilisateur), y compris les
/// comptes antérieurs aux comptes multiples (ADR 0034) et ceux des demandes d'accès (ADR 0029).
pub const DEFAULT_ACCOUNT: &str = "default";

/// Désigne un compte applicatif : un utilisateur peut avoir plusieurs comptes sur une même
/// appli (ADR 0034), distingués par `account_id` (identifiant court, `[a-z0-9-]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountKey {
    pub app_id: String,
    pub user_key: String,
    pub account_id: String,
}

impl AccountKey {
    pub fn new(app_id: &str, user_key: &str, account_id: &str) -> Self {
        Self {
            app_id: app_id.to_owned(),
            user_key: user_key.to_owned(),
            account_id: account_id.to_owned(),
        }
    }

    /// Compte `default` du couple (appli, utilisateur).
    pub fn default_of(app_id: &str, user_key: &str) -> Self {
        Self::new(app_id, user_key, DEFAULT_ACCOUNT)
    }

    pub fn is_default_id(&self) -> bool {
        self.account_id == DEFAULT_ACCOUNT
    }
}

/// Identifiant de compte acceptable : 1 à 32 caractères `[a-z0-9-]`, sans tiret en tête.
pub fn account_id_ok(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Coffre de secrets. Seul le moteur de proxy l'utilise.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Lit les identifiants d'un compte.
    /// L'appelant émet l'événement d'audit `SecretRead`, succès ou échec.
    async fn get_credential(&self, key: &AccountKey) -> PortResult<Credential>;
}

/// Écriture d'un secret par le moteur de proxy, pour les demandes d'accès où l'utilisateur
/// fournit lui-même ses identifiants (ADR 0029). Distincte de `SecretStore` : toutes les
/// implémentations du coffre ne la fournissent pas (OpenBao/Vault : lecture seule pour le
/// proxy). Remplace l'ensemble des champs du compte.
#[async_trait]
pub trait SecretWriter: Send + Sync {
    async fn put_credential(&self, key: &AccountKey, credential: &Credential) -> PortResult<()>;
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
    /// Compte avec lequel la session a été ouverte (ADR 0034) : si l'utilisateur a choisi un
    /// autre compte depuis, la session est abandonnée et le login rejoué.
    pub account_id: String,
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
    /// Détruit les sessions applicatives de l'utilisateur sur cette appli, dans toutes ses
    /// sessions portail (changement de compte, ADR 0034).
    async fn delete_user_app_sessions(&self, user_key: &str, app_id: &str) -> PortResult<()>;

    /// Suspend la connexion automatique de l'utilisateur à l'appli (ADR 0033) et détruit ses
    /// sessions applicatives de **toutes** ses sessions portail (autre fenêtre, navigation
    /// privée). Tant que la suspension dure, le proxy ne rejoue pas le login : l'appli est
    /// atteinte telle quelle, l'utilisateur s'y connecte à la main (autre compte possible).
    async fn suspend_app(&self, user_key: &str, app_id: &str) -> PortResult<()>;
    /// Lève la suspension ; `true` si elle existait.
    async fn resume_app(&self, user_key: &str, app_id: &str) -> PortResult<bool>;
    async fn is_app_suspended(&self, user_key: &str, app_id: &str) -> PortResult<bool>;
    /// Applis dont la connexion automatique est suspendue pour cet utilisateur.
    async fn suspended_apps(&self, user_key: &str) -> PortResult<Vec<String>>;

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
    /// Identifiants fournis par l'utilisateur, en attente d'activation par un administrateur
    /// (ADR 0029) : tuile grisée « demande en cours », rejeu bloqué.
    Pending,
}

/// Entrée du registre des comptes. Ne contient aucun secret.
#[derive(Debug, Clone)]
pub struct AppAccount {
    pub app_id: String,
    pub user_key: String,
    pub account_id: String,
    /// Libellé choisi par l'administrateur (« Admin », « Support »…), jamais un secret.
    pub label: Option<String>,
    /// Compte utilisé tant que l'utilisateur n'en a pas choisi un autre ; un seul par couple.
    pub is_default: bool,
    pub status: AccountStatus,
    /// Code court, jamais un contenu de réponse de l'appli.
    pub status_reason: Option<String>,
    pub last_login_at: Option<SystemTime>,
}

impl AppAccount {
    /// Nouvelle entrée sans libellé ni connexion enregistrée.
    pub fn new(key: &AccountKey, status: AccountStatus, is_default: bool) -> Self {
        Self {
            app_id: key.app_id.clone(),
            user_key: key.user_key.clone(),
            account_id: key.account_id.clone(),
            label: None,
            is_default,
            status,
            status_reason: None,
            last_login_at: None,
        }
    }

    pub fn key(&self) -> AccountKey {
        AccountKey::new(&self.app_id, &self.user_key, &self.account_id)
    }

    /// Libellé affiché : celui de l'administrateur, à défaut l'identifiant du compte.
    pub fn display_label(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.account_id)
    }
}

/// Registre des comptes : quelles applis ont un compte pour quel utilisateur.
///
/// Permet au portail d'afficher les applis sans accéder au coffre.
/// Alimenté par l'UI d'admin, mis à jour par le proxy après chaque rejeu.
#[async_trait]
pub trait AccountRegistry: Send + Sync {
    async fn get_account(&self, key: &AccountKey) -> PortResult<Option<AppAccount>>;
    /// Comptes d'un utilisateur, tous états confondus, triés par appli, compte par défaut en
    /// tête, puis par identifiant de compte.
    async fn list_accounts(&self, user_key: &str) -> PortResult<Vec<AppAccount>>;
    async fn set_status(
        &self,
        key: &AccountKey,
        status: AccountStatus,
        reason: Option<&str>,
    ) -> PortResult<()>;
    async fn record_login(&self, key: &AccountKey, at: SystemTime) -> PortResult<()>;
    /// Mémorise le compte choisi par l'utilisateur pour cette appli (ADR 0034), valable dans
    /// toutes ses sessions portail et d'une connexion à l'autre. `NotFound` si le compte
    /// n'existe pas.
    async fn select_account(&self, key: &AccountKey) -> PortResult<()>;
    /// Compte choisi par l'utilisateur pour cette appli, s'il en a choisi un.
    async fn selected_account(&self, app_id: &str, user_key: &str) -> PortResult<Option<String>>;
    /// Comptes choisis par l'utilisateur : (appli, compte), une entrée par appli.
    async fn selected_accounts(&self, user_key: &str) -> PortResult<Vec<(String, String)>>;

    /// Comptes de l'utilisateur sur une appli (même ordre que `list_accounts`).
    async fn app_accounts(&self, app_id: &str, user_key: &str) -> PortResult<Vec<AppAccount>> {
        Ok(self
            .list_accounts(user_key)
            .await?
            .into_iter()
            .filter(|a| a.app_id == app_id)
            .collect())
    }

    /// Compte utilisé pour cette appli (voir [`effective_account`]).
    async fn effective_account(&self, app_id: &str, user_key: &str) -> PortResult<Option<AppAccount>> {
        let accounts = self.app_accounts(app_id, user_key).await?;
        let selected = self.selected_account(app_id, user_key).await?;
        Ok(effective_account(accounts, selected.as_deref()))
    }
}

/// Compte effectif parmi les comptes d'un couple (appli, utilisateur), dans l'ordre : compte
/// choisi, compte par défaut, premier compte, en écartant d'abord les comptes désactivés. Un
/// compte désactivé n'est retenu que s'il n'y a rien d'autre, pour que le refus soit tracé.
pub fn effective_account(accounts: Vec<AppAccount>, selected: Option<&str>) -> Option<AppAccount> {
    let usable = |a: &&AppAccount| a.status != AccountStatus::Disabled;
    accounts
        .iter()
        .filter(usable)
        .find(|a| Some(a.account_id.as_str()) == selected)
        .or_else(|| accounts.iter().filter(usable).find(|a| a.is_default))
        .or_else(|| accounts.iter().find(usable))
        .or_else(|| accounts.iter().find(|a| a.is_default))
        .or_else(|| accounts.first())
        .cloned()
}

/// Profil d'un utilisateur tel que déclaré par le fournisseur d'identité (ADR 0031).
/// Sert uniquement à afficher « Nom Prénom » dans l'administration : aucune autorisation
/// n'en dépend, la clé reste `user_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProfile {
    pub user_key: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
}

/// Annuaire des utilisateurs connus : écrit par le portail à chaque connexion, lu par
/// l'administration (qui n'en a pas besoin côté Rust, `get_user` sert aux tests de contrat).
#[async_trait]
pub trait UserDirectory: Send + Sync {
    /// Enregistre ou met à jour le profil. Un champ absent (`None`) ne remplace jamais une
    /// valeur déjà connue.
    async fn upsert_user(&self, profile: &UserProfile) -> PortResult<()>;
    async fn get_user(&self, user_key: &str) -> PortResult<Option<UserProfile>>;
}

/// Nature d'une demande d'accès (ADR 0029).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessRequestKind {
    /// L'utilisateur a fourni ses identifiants : l'administrateur n'a qu'à activer le compte.
    Credentials,
    /// L'utilisateur n'a pas de compte : l'administrateur doit le créer.
    NoAccount,
}

/// Demande d'accès ouverte. Ne contient aucun secret.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub app_id: String,
    pub user_key: String,
    pub kind: AccessRequestKind,
    /// Message libre de l'utilisateur, jamais un secret.
    pub note: Option<String>,
    pub created_at: SystemTime,
}

/// Résultat d'un dépôt de demande.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    Recorded,
    /// Un compte `active`, `failed` ou `disabled` existe déjà : rien n'est modifié.
    AccountExists,
}

/// Demandes d'accès : écrites par le portail et le proxy, traitées par l'administration.
/// Elles portent toujours sur le compte `default` (ADR 0034) : les comptes supplémentaires
/// sont créés par un administrateur. Un couple qui a déjà un compte, quel qu'il soit (hors
/// compte `default` en attente), est refusé (`AccountExists`).
#[async_trait]
pub trait AccessRequests: Send + Sync {
    /// Enregistre (ou remplace) la demande ouverte du couple. Pour `Credentials`, crée en
    /// même temps le compte `pending` (ou le laisse `pending`) ; un compte déjà `active`,
    /// `failed` ou `disabled` n'est jamais modifié (`AccountExists`), pour les deux types.
    async fn submit(
        &self,
        app_id: &str,
        user_key: &str,
        kind: AccessRequestKind,
        note: Option<&str>,
    ) -> PortResult<SubmitOutcome>;
    /// Retire une demande `Credentials` et son compte `pending` (écriture du secret échouée).
    async fn withdraw(&self, app_id: &str, user_key: &str) -> PortResult<()>;
    /// Demandes ouvertes d'un utilisateur.
    async fn open_for_user(&self, user_key: &str) -> PortResult<Vec<AccessRequest>>;
}

/// Diagnostic du dernier rejeu en échec d'un compte, pour corriger le descripteur depuis
/// l'administration. Enregistré seulement si l'exploitant l'active (`SESAME_REPLAY_DEBUG`,
/// ADR 0018). Le proxy y masque les valeurs du coffre (brutes et encodées) et les valeurs
/// des cookies avant de l'écrire : il reste lisible par les administrateurs.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReplayDiagnostic {
    pub app_id: String,
    pub user_key: String,
    #[serde(default = "default_account_id")]
    pub account_id: String,
    pub correlation_id: String,
    /// Code d'échec (`login_unexpected_response`…).
    pub reason: String,
    /// Étape de la dernière réponse observée : `login_page` (GET) ou `login_submit` (envoi).
    pub step: String,
    pub method: String,
    pub url: String,
    /// Noms des champs envoyés (jamais leurs valeurs).
    pub sent_fields: Vec<String>,
    pub status: Option<u16>,
    /// En-têtes de la réponse ; valeurs de `Set-Cookie` remplacées par `***`.
    pub headers: Vec<(String, String)>,
    /// Corps de la réponse, tronqué.
    pub body: String,
    pub body_truncated: bool,
    #[serde(with = "unix_secs")]
    pub at: SystemTime,
}

fn default_account_id() -> String {
    DEFAULT_ACCOUNT.to_owned()
}

impl ReplayDiagnostic {
    pub fn key(&self) -> AccountKey {
        AccountKey::new(&self.app_id, &self.user_key, &self.account_id)
    }
}

mod unix_secs {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn serialize<S: serde::Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let secs: u64 = serde::Deserialize::deserialize(d)?;
        Ok(UNIX_EPOCH + Duration::from_secs(secs))
    }
}

/// Diagnostics de rejeu : écrits par le proxy, lus par l'administration.
#[async_trait]
pub trait DiagnosticStore: Send + Sync {
    /// Remplace le diagnostic précédent du compte (seul le dernier est conservé).
    async fn put_diagnostic(&self, diagnostic: ReplayDiagnostic) -> PortResult<()>;
    async fn get_diagnostic(&self, key: &AccountKey) -> PortResult<Option<ReplayDiagnostic>>;
}

/// Descripteur stocké en base (créé ou modifié depuis l'UI d'administration).
#[derive(Debug, Clone)]
pub struct StoredDescriptor {
    pub app_id: String,
    pub revision: u32,
    /// Document conforme à `schemas/app-descriptor.schema.json`, non encore validé.
    pub document: serde_json::Value,
    pub updated_at: SystemTime,
    pub updated_by: Option<String>,
}

/// Descripteurs d'applis stockés en base, avec historique des révisions.
///
/// Portail et proxy lisent (`list_descriptors`, `version`) ; l'écriture vient de
/// l'UI d'administration. Les descripteurs en fichiers (Git) restent possibles,
/// en lecture seule, à côté.
#[async_trait]
pub trait DescriptorStore: Send + Sync {
    async fn list_descriptors(&self) -> PortResult<Vec<StoredDescriptor>>;
    /// Change à chaque création, modification ou suppression : sert au rechargement à chaud.
    async fn version(&self) -> PortResult<i64>;
    /// Crée ou remplace le descripteur ; la révision est incrémentée et historisée.
    async fn put_descriptor(
        &self,
        app_id: &str,
        document: serde_json::Value,
        by: Option<&str>,
    ) -> PortResult<u32>;
    async fn delete_descriptor(&self, app_id: &str, by: Option<&str>) -> PortResult<()>;
}

/// Événement à signaler par mail aux administrateurs (ADR 0030).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationEvent {
    /// Nouvelle demande d'accès (ADR 0029).
    AccessRequested,
    /// Un rejeu échoue : le compte passe à `failed` et le rejeu est bloqué.
    AccountFailed,
    /// Un rejeu échoue parce que l'appli est injoignable.
    UpstreamUnreachable,
}

impl NotificationEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessRequested => "access_requested",
            Self::AccountFailed => "account_failed",
            Self::UpstreamUnreachable => "upstream_unreachable",
        }
    }
}

/// Dépôt d'un événement dans la boîte d'envoi : l'administration l'expédie par SMTP.
///
/// Volontairement sans erreur : une notification n'est jamais une raison de faire échouer
/// une connexion, un rejeu ou une demande. L'implémentation journalise l'échec et
/// regroupe les répétitions (même événement, même appli, même utilisateur) sur une fenêtre
/// courte, pour qu'une appli en panne ne produise pas un mail par requête. `reason` est un
/// code court : jamais un secret ni un contenu de réponse.
#[async_trait]
pub trait Notifier: Send + Sync {
    async fn notify(&self, event: NotificationEvent, app_id: &str, user_key: Option<&str>, reason: &str);
}

/// Journal d'audit dédié.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Une erreur d'écriture d'audit doit faire échouer l'opération auditée.
    async fn record(&self, event: AuditEvent) -> PortResult<()>;
}
