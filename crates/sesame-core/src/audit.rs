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
    /// Identifiant de corrélation (trace / requête).
    pub correlation_id: Option<String>,
    pub reason: Option<String>,
}
