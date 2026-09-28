// SPDX-License-Identifier: Apache-2.0
//! Fournisseur d'identité du portail : OIDC ou SAML, choisi par configuration
//! (`SESAME_IDP_PROTOCOL`). Un seul protocole actif par déploiement, le même pour le
//! portail et l'administration (ADR 0024).

use serde::{Deserialize, Serialize};
use sesame_core::identity::UserIdentity;

use crate::config::{IdpConfig, PortalConfig};
use crate::oidc::{Oidc, OidcError, OidcPending};
use crate::saml::{Saml, SamlError, SamlPending};

/// État d'une connexion en cours, conservé chiffré dans un cookie le temps de l'aller-retour
/// (le même mécanisme sert aux deux protocoles).
#[derive(Serialize, Deserialize)]
pub struct PendingLogin {
    /// Anti-CSRF : `state` OIDC ou jeton porté en `RelayState` SAML, comparé à la valeur
    /// reçue au retour.
    pub csrf: String,
    pub return_to: String,
    /// Échéance (secondes Unix).
    pub expires_at: u64,
    #[serde(default)]
    pub oidc: Option<OidcPending>,
    #[serde(default)]
    pub saml: Option<SamlPending>,
}

/// Charge utile reçue au retour du fournisseur, selon son protocole.
pub enum Callback {
    Oidc { code: String },
    Saml { saml_response: String },
}

#[derive(Debug, thiserror::Error)]
pub enum IdpError {
    #[error(transparent)]
    Oidc(#[from] OidcError),
    #[error(transparent)]
    Saml(#[from] SamlError),
    #[error("réponse d'un protocole inattendu")]
    ProtocolMismatch,
}

pub enum IdentityProvider {
    Oidc(Oidc),
    Saml(Saml),
}

impl IdentityProvider {
    pub async fn discover(
        cfg: &PortalConfig,
        redirect: String,
        http: reqwest::Client,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        match &cfg.idp {
            IdpConfig::Oidc(oidc_cfg) => Ok(Self::Oidc(Oidc::discover(oidc_cfg, redirect, http).await?)),
            IdpConfig::Saml(saml_cfg) => Ok(Self::Saml(Saml::new(saml_cfg, redirect)?)),
        }
    }

    /// URL vers laquelle rediriger l'utilisateur et état à conserver jusqu'au retour.
    pub fn start(&self, return_to: String, expires_at: u64) -> Result<(String, PendingLogin), IdpError> {
        match self {
            Self::Oidc(o) => Ok(o.start(return_to, expires_at)),
            Self::Saml(s) => Ok(s.start(return_to, expires_at)?),
        }
    }

    /// Vérifie la réponse du fournisseur et construit l'identité. `callback` doit correspondre
    /// au protocole actif : sinon, `ProtocolMismatch` (jamais un mélange des deux flux).
    pub async fn finish(&self, callback: Callback, pending: &PendingLogin) -> Result<UserIdentity, IdpError> {
        match (self, callback) {
            (Self::Oidc(o), Callback::Oidc { code }) => Ok(o.finish(code, pending).await?),
            (Self::Saml(s), Callback::Saml { saml_response }) => Ok(s.finish(&saml_response, pending)?),
            _ => Err(IdpError::ProtocolMismatch),
        }
    }

    /// Déconnexion chez le fournisseur (RP-Initiated Logout OIDC uniquement pour l'instant :
    /// le Single Logout SAML est hors périmètre initial).
    pub fn logout_url(&self, post_logout_redirect: &str) -> Option<String> {
        match self {
            Self::Oidc(o) => o.logout_url(post_logout_redirect),
            Self::Saml(_) => None,
        }
    }

    /// Métadonnées XML du fournisseur de service, à publier sur `/saml/metadata` pour
    /// l'enregistrer chez l'IdP. `None` hors protocole SAML.
    pub fn saml_metadata_xml(&self) -> Option<Result<String, SamlError>> {
        match self {
            Self::Oidc(_) => None,
            Self::Saml(s) => Some(s.metadata_xml()),
        }
    }
}
