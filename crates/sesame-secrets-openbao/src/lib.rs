// SPDX-License-Identifier: Apache-2.0
//! Coffre de secrets OpenBao / Vault : authentification AppRole, lecture KV v2.
//!
//! API HTTP commune à OpenBao et Vault, sans SDK. Chemin lu :
//! `<mount>/data/<path_prefix>/<app_id>/users/<user_key>`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sesame_core::identity::validate_user_key;
use sesame_core::ports::{PortError, PortResult, SecretStore};
use sesame_core::secret::Credential;
use tokio::sync::Mutex;
use url::Url;

pub struct OpenBaoConfig {
    pub addr: Url,
    pub mount: String,
    pub path_prefix: String,
    pub role_id: String,
    pub secret_id: SecretString,
    /// Espace de noms (Vault Enterprise / OpenBao), optionnel.
    pub namespace: Option<String>,
}

struct Token {
    value: SecretString,
    renew_after: Instant,
}

pub struct OpenBaoSecretStore {
    http: reqwest::Client,
    cfg: OpenBaoConfig,
    token: Mutex<Option<Token>>,
}

#[derive(Deserialize)]
struct LoginResponse {
    auth: LoginAuth,
}

#[derive(Deserialize)]
struct LoginAuth {
    client_token: SecretString,
    lease_duration: u64,
}

#[derive(Deserialize)]
struct KvResponse {
    data: KvData,
}

#[derive(Deserialize)]
struct KvData {
    data: BTreeMap<String, SecretString>,
}

fn unavailable(e: reqwest::Error) -> PortError {
    // Pas d'URL ni de corps dans le message : seulement la nature de l'erreur.
    PortError::Unavailable(format!("coffre injoignable ({})", e.without_url()))
}

fn segment_ok(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains('/')
}

impl OpenBaoSecretStore {
    pub fn new(cfg: OpenBaoConfig, http: reqwest::Client) -> PortResult<Self> {
        let prefix_ok = cfg.path_prefix.split('/').all(segment_ok);
        if !segment_ok(&cfg.mount) || !prefix_ok {
            return Err(PortError::Other(
                "mount ou préfixe de chemin du coffre invalide".into(),
            ));
        }
        Ok(Self {
            http,
            cfg,
            token: Mutex::new(None),
        })
    }

    fn url(&self, path: &str) -> PortResult<Url> {
        self.cfg
            .addr
            .join(path)
            .map_err(|_| PortError::Other("URL du coffre invalide".into()))
    }

    fn request(&self, method: reqwest::Method, url: Url) -> reqwest::RequestBuilder {
        let req = self.http.request(method, url);
        match &self.cfg.namespace {
            Some(ns) => req.header("X-Vault-Namespace", ns),
            None => req,
        }
    }

    async fn login(&self) -> PortResult<Token> {
        let body = serde_json::json!({
            "role_id": self.cfg.role_id,
            "secret_id": self.cfg.secret_id.expose_secret(),
        });
        let resp = self
            .request(reqwest::Method::POST, self.url("v1/auth/approle/login")?)
            .json(&body)
            .send()
            .await
            .map_err(unavailable)?;
        match resp.status() {
            s if s.is_success() => {}
            StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN => return Err(PortError::Forbidden),
            s => {
                return Err(PortError::Unavailable(format!(
                    "login AppRole : HTTP {}",
                    s.as_u16()
                )))
            }
        }
        let login: LoginResponse = resp
            .json()
            .await
            .map_err(|_| PortError::Other("réponse de login AppRole illisible".into()))?;
        // Renouvelle aux deux tiers de la durée du bail.
        let lease = Duration::from_secs(login.auth.lease_duration.max(30));
        tracing::info!(
            lease_secs = lease.as_secs(),
            "authentifié auprès du coffre (AppRole)"
        );
        Ok(Token {
            value: login.auth.client_token,
            renew_after: Instant::now() + lease * 2 / 3,
        })
    }

    async fn token(&self, force_refresh: bool) -> PortResult<SecretString> {
        let mut guard = self.token.lock().await;
        let valid = guard
            .as_ref()
            .filter(|t| !force_refresh && Instant::now() < t.renew_after);
        if let Some(t) = valid {
            return Ok(t.value.clone());
        }
        let fresh = self.login().await?;
        let value = fresh.value.clone();
        *guard = Some(fresh);
        Ok(value)
    }

    async fn read(&self, path: &str, token: &SecretString) -> PortResult<Option<reqwest::Response>> {
        let resp = self
            .request(reqwest::Method::GET, self.url(path)?)
            .header("X-Vault-Token", token.expose_secret())
            .send()
            .await
            .map_err(unavailable)?;
        match resp.status() {
            s if s.is_success() => Ok(Some(resp)),
            StatusCode::FORBIDDEN => Ok(None),
            StatusCode::NOT_FOUND => Err(PortError::NotFound),
            s => Err(PortError::Unavailable(format!(
                "lecture du coffre : HTTP {}",
                s.as_u16()
            ))),
        }
    }
}

#[async_trait]
impl SecretStore for OpenBaoSecretStore {
    async fn get_credential(&self, app_id: &str, user_key: &str) -> PortResult<Credential> {
        if !segment_ok(app_id) || validate_user_key(user_key).is_err() {
            return Err(PortError::Other(
                "identifiant d'appli ou d'utilisateur invalide".into(),
            ));
        }
        let path = format!(
            "v1/{}/data/{}/{}/users/{}",
            self.cfg.mount, self.cfg.path_prefix, app_id, user_key
        );
        let token = self.token(false).await?;
        let resp = match self.read(&path, &token).await? {
            Some(resp) => resp,
            // Jeton révoqué ou expiré côté coffre : une nouvelle authentification, un seul essai.
            None => {
                let token = self.token(true).await?;
                self.read(&path, &token).await?.ok_or(PortError::Forbidden)?
            }
        };
        let kv: KvResponse = resp
            .json()
            .await
            .map_err(|_| PortError::Other("secret illisible (valeurs texte attendues)".into()))?;
        Ok(Credential::new(kv.data.data))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::{json, Value};

    use super::*;

    #[derive(Default)]
    struct Mock {
        logins: AtomicU32,
    }

    async fn login(State(m): State<Arc<Mock>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
        if body["role_id"] != "role" || body["secret_id"] != "sid" {
            return (StatusCode::BAD_REQUEST, Json(json!({"errors": ["invalid"]})));
        }
        let n = m.logins.fetch_add(1, Ordering::SeqCst) + 1;
        let body = json!({"auth": {"client_token": format!("tok-{n}"), "lease_duration": 3600}});
        (StatusCode::OK, Json(body))
    }

    async fn read(Path(rest): Path<String>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
        // Le premier jeton est considéré comme révoqué : force la ré-authentification.
        if headers.get("x-vault-token").and_then(|v| v.to_str().ok()) != Some("tok-2") {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"errors": ["permission denied"]})),
            );
        }
        match rest.as_str() {
            "sesame/apps/fake-app/users/alice" => (
                StatusCode::OK,
                Json(json!({"data": {"data": {"username": "amartin", "password": "pw-123"}}})),
            ),
            _ => (StatusCode::NOT_FOUND, Json(json!({"errors": []}))),
        }
    }

    async fn store() -> OpenBaoSecretStore {
        let app = Router::new()
            .route("/v1/auth/approle/login", post(login))
            .route("/v1/secret/data/{*rest}", get(read))
            .with_state(Arc::new(Mock::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let cfg = OpenBaoConfig {
            addr: Url::parse(&format!("http://{addr}/")).unwrap(),
            mount: "secret".into(),
            path_prefix: "sesame/apps".into(),
            role_id: "role".into(),
            secret_id: SecretString::from("sid"),
            namespace: None,
        };
        OpenBaoSecretStore::new(cfg, reqwest::Client::builder().no_proxy().build().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn reads_credential_after_relogin() {
        let s = store().await;
        let cred = s.get_credential("fake-app", "alice").await.unwrap();
        assert_eq!(cred.get("username").unwrap().expose_secret(), "amartin");
        assert_eq!(cred.get("password").unwrap().expose_secret(), "pw-123");
        assert!(!format!("{cred:?}").contains("pw-123"));
        assert!(matches!(
            s.get_credential("fake-app", "bob").await,
            Err(PortError::NotFound)
        ));
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let s = store().await;
        for (app, user) in [
            ("fake-app", "../x"),
            ("fake-app", "a/b"),
            ("..", "alice"),
            ("a/b", "alice"),
        ] {
            assert!(matches!(
                s.get_credential(app, user).await,
                Err(PortError::Other(_))
            ));
        }
    }
}
