// SPDX-License-Identifier: Apache-2.0
//! Configuration du portail (variables d'environnement `SESAME_*`).

use std::path::PathBuf;
use std::time::Duration;

use sesame_core::config::{self, ConfigError};
use sesame_core::cookies::PortalCookie;
use sesame_core::secret::SecretString;
use url::Url;

pub struct PortalConfig {
    pub listen: String,
    /// URL publique du portail (ex. `https://sesame.example`).
    pub public_url: Url,
    pub cookie: PortalCookie,
    pub session_ttl: Duration,
    pub descriptors_dir: PathBuf,
    /// Intervalle de vérification du catalogue en base (rechargement à chaud).
    pub reload_interval: std::time::Duration,
    pub database_url: SecretString,
    /// Clé (base64, 32 octets) chiffrant l'état OIDC temporaire porté par cookie.
    pub state_key: SecretString,
    pub ca_file: Option<PathBuf>,
    pub idp: IdpConfig,
    /// URL publique de l'UI d'administration, si elle existe : affiche un lien
    /// « Administration » sur la page « Mes applications » aux membres d'`admin_group`.
    pub admin_url: Option<Url>,
    pub admin_group: String,
    /// Service interne du proxy pour les demandes d'accès avec identifiants (ADR 0029) :
    /// `SESAME_PROXY_INTERNAL_URL` et `SESAME_INTERNAL_TOKEN`, ensemble ou pas du tout.
    pub proxy_internal: Option<ProxyInternalConfig>,
}

pub struct ProxyInternalConfig {
    pub url: Url,
    pub token: SecretString,
}

/// Un seul protocole actif par déploiement, choisi par `SESAME_IDP_PROTOCOL` (ADR 0024).
pub enum IdpConfig {
    Oidc(OidcConfig),
    Saml(SamlConfig),
}

pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: SecretString,
    pub scopes: Vec<String>,
    /// Claim servant de clé utilisateur (coffre, registre). Défaut : `sub`.
    pub user_key_claim: String,
    pub groups_claim: String,
    /// Déconnexion aussi chez le fournisseur d'identité (RP-initiated logout).
    pub idp_logout: bool,
}

/// SAML 2.0 générique (SP-initiated, liaison Redirect/POST). Pas de récupération dynamique
/// d'un document de métadonnées IdP : tout vient de variables d'environnement.
pub struct SamlConfig {
    /// `entityID` de l'IdP (`Issuer` attendu dans les réponses).
    pub idp_entity_id: String,
    /// URL du service de SSO de l'IdP (liaison HTTP-Redirect).
    pub idp_sso_url: String,
    /// Certificat de signature de l'IdP, au format PEM (avec ou sans en-têtes).
    pub idp_cert_pem: String,
    /// `entityID` de Sesame auprès de cet IdP.
    pub sp_entity_id: String,
    /// Attribut portant la clé utilisateur (coffre, registre). Absent : `NameID`.
    pub user_key_attribute: Option<String>,
    pub email_attribute: Option<String>,
    pub groups_attribute: Option<String>,
}

/// `SESAME_IDP_PROTOCOL` choisit le protocole ; `oidc` par défaut (compatibilité).
fn idp_config_from_env() -> Result<IdpConfig, ConfigError> {
    match config::or("SESAME_IDP_PROTOCOL", "oidc").as_str() {
        "oidc" => Ok(IdpConfig::Oidc(OidcConfig {
            issuer: config::required("SESAME_OIDC_ISSUER")?,
            client_id: config::required("SESAME_OIDC_CLIENT_ID")?,
            client_secret: config::secret("SESAME_OIDC_CLIENT_SECRET")?,
            scopes: config::or("SESAME_OIDC_SCOPES", "openid profile email")
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            user_key_claim: config::or("SESAME_OIDC_USER_KEY_CLAIM", "sub"),
            groups_claim: config::or("SESAME_OIDC_GROUPS_CLAIM", "groups"),
            idp_logout: config::flag("SESAME_OIDC_LOGOUT"),
        })),
        "saml" => {
            let cert_file = config::required("SESAME_SAML_IDP_CERT_FILE")?;
            let idp_cert_pem = std::fs::read_to_string(&cert_file)
                .map_err(|e| ConfigError(format!("SESAME_SAML_IDP_CERT_FILE ({cert_file}) : {e}")))?;
            Ok(IdpConfig::Saml(SamlConfig {
                idp_entity_id: config::required("SESAME_SAML_IDP_ENTITY_ID")?,
                idp_sso_url: config::required("SESAME_SAML_IDP_SSO_URL")?,
                idp_cert_pem,
                sp_entity_id: config::required("SESAME_SAML_SP_ENTITY_ID")?,
                user_key_attribute: config::optional("SESAME_SAML_USER_KEY_ATTRIBUTE"),
                email_attribute: config::optional("SESAME_SAML_EMAIL_ATTRIBUTE"),
                groups_attribute: config::optional("SESAME_SAML_GROUPS_ATTRIBUTE"),
            }))
        }
        other => Err(ConfigError(format!(
            "SESAME_IDP_PROTOCOL : « {other} » inconnu (oidc, saml)"
        ))),
    }
}

fn proxy_internal_from_env() -> Result<Option<ProxyInternalConfig>, ConfigError> {
    match (
        config::optional("SESAME_PROXY_INTERNAL_URL"),
        config::optional("SESAME_INTERNAL_TOKEN"),
    ) {
        (Some(url), Some(token)) => Ok(Some(ProxyInternalConfig {
            url: Url::parse(&url).map_err(|e| ConfigError(format!("SESAME_PROXY_INTERNAL_URL : {e}")))?,
            token: SecretString::from(token),
        })),
        (None, None) => Ok(None),
        _ => Err(ConfigError(
            "SESAME_PROXY_INTERNAL_URL et SESAME_INTERNAL_TOKEN vont ensemble".into(),
        )),
    }
}

impl PortalConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let public_url = Url::parse(&config::required("SESAME_PUBLIC_URL")?)
            .map_err(|e| ConfigError(format!("SESAME_PUBLIC_URL : {e}")))?;
        Ok(Self {
            listen: config::or("SESAME_PORTAL_LISTEN", "0.0.0.0:8080"),
            cookie: PortalCookie {
                name: config::or("SESAME_COOKIE_NAME", "sesame_session"),
                domain: config::optional("SESAME_COOKIE_DOMAIN"),
                secure: public_url.scheme() == "https",
            },
            public_url,
            session_ttl: config::duration("SESAME_SESSION_TTL", "8h")?,
            descriptors_dir: config::or("SESAME_DESCRIPTORS_DIR", "descriptors").into(),
            reload_interval: config::duration("SESAME_DESCRIPTORS_RELOAD", "10s")?,
            database_url: config::secret("SESAME_DATABASE_URL")?,
            state_key: config::secret("SESAME_PORTAL_STATE_KEY")?,
            ca_file: config::optional("SESAME_CA_FILE").map(PathBuf::from),
            idp: idp_config_from_env()?,
            admin_url: config::optional("SESAME_ADMIN_URL")
                .map(|s| Url::parse(&s).map_err(|e| ConfigError(format!("SESAME_ADMIN_URL : {e}"))))
                .transpose()?,
            admin_group: config::or("SESAME_ADMIN_GROUP", "sesame-admins"),
            proxy_internal: proxy_internal_from_env()?,
        })
    }
}
