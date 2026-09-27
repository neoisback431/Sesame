// SPDX-License-Identifier: Apache-2.0
//! Événements d'audit (exigence PCI-DSS : tout accès à un secret est tracé).

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    PortalLogin,
    PortalLogout,
    AccessDenied,
    SecretRead,
    LoginReplay,
    AppSessionExpired,
    AppLogout,
    AccountStatusChanged,
    /// Émis par l'UI d'administration.
    AdminLogin,
    CredentialWritten,
    CredentialDeleted,
    DescriptorCreated,
    DescriptorUpdated,
    DescriptorDeleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
}

/// Qui, quelle appli, quand, résultat. Ne contient jamais de secret :
/// `reason` est un code ou un libellé court, jamais un contenu de réponse.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Horodatage RFC 3339 (UTC).
    pub timestamp: String,
    pub action: AuditAction,
    pub outcome: AuditOutcome,
    /// `issuer` + `subject` de l'utilisateur, si connu.
    pub actor: Option<String>,
    pub app_id: Option<String>,
    /// Compte visé quand il diffère de l'acteur (actions d'administration).
    pub target_user: Option<String>,
    /// Identifiant de corrélation (trace / requête).
    pub correlation_id: Option<String>,
    pub reason: Option<String>,
}

impl AuditEvent {
    pub fn new(action: AuditAction, outcome: AuditOutcome) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            action,
            outcome,
            actor: None,
            app_id: None,
            target_user: None,
            correlation_id: None,
            reason: None,
        }
    }

    pub fn actor(mut self, user: &crate::identity::UserIdentity) -> Self {
        self.actor = Some(format!("{}|{}", user.issuer, user.subject));
        self
    }

    pub fn app(mut self, app_id: &str) -> Self {
        self.app_id = Some(app_id.to_owned());
        self
    }

    pub fn correlation(mut self, id: &str) -> Self {
        self.correlation_id = Some(id.to_owned());
        self
    }

    /// Code ou libellé court, jamais un contenu de réponse ni un secret.
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Journal d'audit en lignes JSON sur stdout, marquées `"log_type":"audit"`
/// pour être séparées des logs applicatifs par la chaîne de collecte.
#[derive(Debug, Default)]
pub struct StdoutAuditSink {
    lock: std::sync::Mutex<()>,
}

#[async_trait::async_trait]
impl crate::ports::AuditSink for StdoutAuditSink {
    async fn record(&self, event: AuditEvent) -> crate::ports::PortResult<()> {
        use std::io::Write;
        #[derive(Serialize)]
        struct Line<'a> {
            log_type: &'static str,
            #[serde(flatten)]
            event: &'a AuditEvent,
        }
        let mut line = serde_json::to_vec(&Line {
            log_type: "audit",
            event: &event,
        })
        .map_err(|e| crate::ports::PortError::Other(e.to_string()))?;
        line.push(b'\n');
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = std::io::stdout().lock();
        out.write_all(&line)
            .and_then(|_| out.flush())
            .map_err(|e| crate::ports::PortError::Unavailable(e.to_string()))
    }
}
