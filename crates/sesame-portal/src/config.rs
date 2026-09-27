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
    pub database_url: SecretString,
    /// Clé (base64, 32 octets) chiffrant l'état OIDC temporaire porté par cookie.
    pub state_key: SecretString,
    pub ca_file: Option<PathBuf>,
    pub oidc: OidcConfig,
}

pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: SecretString,
    pub scopes: Vec<String>,
    /// Claim servant de clé utilisateur (coffre, registre). Défaut : `sub`.
    pub user_key_claim: String,
    pub groups_claim: String,
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
            database_url: config::secret("SESAME_DATABASE_URL")?,
            state_key: config::secret("SESAME_PORTAL_STATE_KEY")?,
            ca_file: config::optional("SESAME_CA_FILE").map(PathBuf::from),
            oidc: OidcConfig {
                issuer: config::required("SESAME_OIDC_ISSUER")?,
                client_id: config::required("SESAME_OIDC_CLIENT_ID")?,
                client_secret: config::secret("SESAME_OIDC_CLIENT_SECRET")?,
                scopes: config::or("SESAME_OIDC_SCOPES", "openid profile email")
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect(),
                user_key_claim: config::or("SESAME_OIDC_USER_KEY_CLAIM", "sub"),
                groups_claim: config::or("SESAME_OIDC_GROUPS_CLAIM", "groups"),
            },
        })
    }
}
