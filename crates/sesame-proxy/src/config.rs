// SPDX-License-Identifier: Apache-2.0
//! Configuration du moteur de proxy (variables d'environnement `SESAME_*`).

use std::path::PathBuf;

use sesame_core::config::{self, ConfigError};
use sesame_core::cookies::PortalCookie;
use sesame_core::secret::SecretString;
use url::Url;

pub struct ProxyConfig {
    pub listen: String,
    pub descriptors_dir: PathBuf,
    pub portal_url: Url,
    pub cookie: PortalCookie,
    pub database_url: SecretString,
    /// Clé (base64, 32 octets) de chiffrement des cookies applicatifs au repos.
    pub session_key: SecretString,
    pub ca_file: Option<PathBuf>,
    pub max_body_bytes: usize,
    pub secret_store: SecretStoreConfig,
}

pub enum SecretStoreConfig {
    OpenBao {
        addr: Url,
        mount: String,
        path_prefix: String,
        role_id: String,
        secret_id: SecretString,
        namespace: Option<String>,
    },
}

impl ProxyConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let portal_url = Url::parse(&config::required("SESAME_PORTAL_URL")?)
            .map_err(|e| ConfigError(format!("SESAME_PORTAL_URL : {e}")))?;
        let secret_store = match config::or("SESAME_SECRET_STORE", "openbao").as_str() {
            // Vault et OpenBao partagent la même API.
            "openbao" | "vault" => SecretStoreConfig::OpenBao {
                addr: Url::parse(&config::required("SESAME_OPENBAO_ADDR")?)
                    .map_err(|e| ConfigError(format!("SESAME_OPENBAO_ADDR : {e}")))?,
                mount: config::or("SESAME_OPENBAO_MOUNT", "secret"),
                path_prefix: config::or("SESAME_OPENBAO_PATH_PREFIX", "sesame/apps"),
                role_id: config::required("SESAME_OPENBAO_ROLE_ID")?,
                secret_id: config::secret("SESAME_OPENBAO_SECRET_ID")?,
                namespace: config::optional("SESAME_OPENBAO_NAMESPACE"),
            },
            other => return Err(ConfigError(format!("SESAME_SECRET_STORE inconnu : {other}"))),
        };
        Ok(Self {
            listen: config::or("SESAME_PROXY_LISTEN", "0.0.0.0:8081"),
            descriptors_dir: config::or("SESAME_DESCRIPTORS_DIR", "descriptors").into(),
            cookie: PortalCookie {
                name: config::or("SESAME_COOKIE_NAME", "sesame_session"),
                domain: config::optional("SESAME_COOKIE_DOMAIN"),
                secure: portal_url.scheme() == "https",
            },
            portal_url,
            database_url: config::secret("SESAME_DATABASE_URL")?,
            session_key: config::secret("SESAME_SESSION_ENCRYPTION_KEY")?,
            ca_file: config::optional("SESAME_CA_FILE").map(PathBuf::from),
            max_body_bytes: config::or("SESAME_MAX_BODY_BYTES", "33554432")
                .parse()
                .map_err(|_| ConfigError("SESAME_MAX_BODY_BYTES : entier attendu".into()))?,
            secret_store,
        })
    }
}
