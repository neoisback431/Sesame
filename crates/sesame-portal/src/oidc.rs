// SPDX-License-Identifier: Apache-2.0
//! OIDC générique : discovery, authorization code + PKCE, vérification de l'ID token,
//! extraction de l'identité selon un mapping de claims configurable.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sesame_core::identity::{validate_user_key, UserIdentity};
use sesame_core::secret::ExposeSecret;

use crate::config::OidcConfig;
use crate::idp::PendingLogin;

type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("discovery OIDC : {0}")]
    Discovery(String),
    #[error("échange du code : {0}")]
    Exchange(String),
    #[error("ID token invalide : {0}")]
    Token(String),
    #[error("claims : {0}")]
    Claims(String),
}

pub struct Oidc {
    client: Client,
    client_id: String,
    /// `end_session_endpoint` du fournisseur, si la déconnexion chez lui est activée.
    end_session: Option<url::Url>,
    http: reqwest::Client,
    issuer: String,
    scopes: Vec<String>,
    user_key_claim: String,
    groups_claim: String,
}

/// Partie de `PendingLogin` propre à OIDC.
#[derive(Serialize, Deserialize)]
pub struct OidcPending {
    pub nonce: String,
    pub pkce_verifier: String,
}

impl Oidc {
    pub async fn discover(
        cfg: &OidcConfig,
        redirect: String,
        http: reqwest::Client,
    ) -> Result<Self, OidcError> {
        let issuer = IssuerUrl::new(cfg.issuer.clone()).map_err(|e| OidcError::Discovery(e.to_string()))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(cfg.client_id.clone()),
            Some(ClientSecret::new(cfg.client_secret.expose_secret().to_owned())),
        )
        .set_redirect_uri(RedirectUrl::new(redirect).map_err(|e| OidcError::Discovery(e.to_string()))?);
        let end_session = if cfg.idp_logout {
            let endpoint = end_session_endpoint(&cfg.issuer, &http).await;
            if endpoint.is_none() {
                tracing::warn!("déconnexion chez le fournisseur demandée mais end_session_endpoint absent : déconnexion locale seulement");
            }
            endpoint
        } else {
            None
        };
        Ok(Self {
            client,
            client_id: cfg.client_id.clone(),
            end_session,
            http,
            issuer: cfg.issuer.clone(),
            scopes: cfg.scopes.clone(),
            user_key_claim: cfg.user_key_claim.clone(),
            groups_claim: cfg.groups_claim.clone(),
        })
    }

    /// URL de déconnexion chez le fournisseur (RP-initiated logout), si activée.
    pub fn logout_url(&self, post_logout_redirect: &str) -> Option<String> {
        self.end_session
            .as_ref()
            .map(|e| logout_url(e, &self.client_id, post_logout_redirect))
    }

    /// URL d'autorisation et état à conserver jusqu'au retour.
    pub fn start(&self, return_to: String, expires_at: u64) -> (String, PendingLogin) {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut req = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in self.scopes.iter().filter(|s| *s != "openid") {
            req = req.add_scope(Scope::new(scope.clone()));
        }
        let (url, state, nonce) = req.url();
        let pending = PendingLogin {
            csrf: state.secret().clone(),
            return_to,
            expires_at,
            oidc: Some(OidcPending {
                nonce: nonce.secret().clone(),
                pkce_verifier: verifier.secret().clone(),
            }),
            saml: None,
        };
        (url.to_string(), pending)
    }

    /// Échange le code, vérifie l'ID token (signature, iss, aud, exp, nonce) et construit l'identité.
    pub async fn finish(&self, code: String, pending: &PendingLogin) -> Result<UserIdentity, OidcError> {
        let oidc_pending = pending
            .oidc
            .as_ref()
            .ok_or_else(|| OidcError::Token("état de connexion inattendu".into()))?;
        let response = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|e| OidcError::Exchange(e.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(oidc_pending.pkce_verifier.clone()))
            .request_async(&self.http)
            .await
            .map_err(|e| OidcError::Exchange(e.to_string()))?;
        let id_token = response
            .id_token()
            .ok_or_else(|| OidcError::Token("absent de la réponse".into()))?;
        id_token
            .claims(
                &self.client.id_token_verifier(),
                &Nonce::new(oidc_pending.nonce.clone()),
            )
            .map_err(|e| OidcError::Token(e.to_string()))?;
        // Jeton vérifié : on relit ses claims bruts pour appliquer le mapping configurable.
        let raw = id_token.to_string();
        let payload = raw
            .split('.')
            .nth(1)
            .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
            .and_then(|b| serde_json::from_slice::<Map<String, Value>>(&b).ok())
            .ok_or_else(|| OidcError::Token("charge utile illisible".into()))?;
        identity_from_claims(&payload, &self.issuer, &self.user_key_claim, &self.groups_claim)
    }
}

/// Lit `end_session_endpoint` dans le document de discovery (absent du modèle standard
/// d'`openidconnect`). Refuse un point de déconnexion d'un autre schéma que l'émetteur.
async fn end_session_endpoint(issuer: &str, http: &reqwest::Client) -> Option<url::Url> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let doc: Value = http
        .get(url)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    let endpoint = url::Url::parse(doc.get("end_session_endpoint")?.as_str()?).ok()?;
    let issuer_scheme = url::Url::parse(issuer).ok()?.scheme().to_owned();
    (endpoint.scheme() == issuer_scheme).then_some(endpoint)
}

/// URL de déconnexion OIDC RP-Initiated Logout : `client_id` + `post_logout_redirect_uri`.
///
/// Pas d'`id_token_hint` : Sesame ne conserve pas l'ID token. Certains fournisseurs
/// (Keycloak) demandent alors une confirmation à l'utilisateur.
pub fn logout_url(endpoint: &url::Url, client_id: &str, post_logout_redirect: &str) -> String {
    let mut url = endpoint.clone();
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("post_logout_redirect_uri", post_logout_redirect);
    url.to_string()
}

/// Construit l'identité à partir des claims d'un ID token déjà vérifié.
pub fn identity_from_claims(
    claims: &Map<String, Value>,
    issuer: &str,
    user_key_claim: &str,
    groups_claim: &str,
) -> Result<UserIdentity, OidcError> {
    let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);
    let subject = text("sub").ok_or_else(|| OidcError::Claims("sub absent".into()))?;
    let user_key =
        text(user_key_claim).ok_or_else(|| OidcError::Claims(format!("claim {user_key_claim} absent")))?;
    validate_user_key(&user_key).map_err(OidcError::Claims)?;
    // Claim de groupes absent : aucun groupe (cas normal chez la plupart des fournisseurs).
    let groups = match claims.get(groups_claim) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(one)) => vec![one.clone()],
        Some(_) => {
            return Err(OidcError::Claims(format!(
                "claim {groups_claim} de type inattendu"
            )))
        }
    };
    Ok(UserIdentity {
        issuer: text("iss").unwrap_or_else(|| issuer.to_owned()),
        subject,
        user_key,
        display_name: text("name")
            .or_else(|| text("email"))
            .or_else(|| text("preferred_username")),
        groups,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn claims(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn builds_rp_initiated_logout_url() {
        let endpoint = url::Url::parse("https://idp.example/realms/r/logout?x=1").unwrap();
        let u = logout_url(
            &endpoint,
            "sesame-portal",
            "https://sesame.example/auth/logged-out",
        );
        let parsed = url::Url::parse(&u).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(parsed.path(), "/realms/r/logout");
        assert_eq!(q["x"], "1");
        assert_eq!(q["client_id"], "sesame-portal");
        assert_eq!(
            q["post_logout_redirect_uri"],
            "https://sesame.example/auth/logged-out"
        );
        assert!(!q.contains_key("id_token_hint"));
    }

    #[test]
    fn maps_claims() {
        let c = claims(json!({
            "iss": "https://idp", "sub": "s-1", "preferred_username": "alice",
            "name": "Alice Martin", "groups": ["g1", "g2", 3]
        }));
        let id = identity_from_claims(&c, "https://idp", "preferred_username", "groups").unwrap();
        assert_eq!((id.subject.as_str(), id.user_key.as_str()), ("s-1", "alice"));
        assert_eq!(id.groups, ["g1", "g2"]);
        assert_eq!(id.display_name.as_deref(), Some("Alice Martin"));
    }

    #[test]
    fn missing_groups_means_none_and_sub_is_default_key() {
        let c = claims(json!({"sub": "0f8c6e3a-1b2c", "email": "bob@example.org"}));
        let id = identity_from_claims(&c, "https://idp", "sub", "groups").unwrap();
        assert!(id.groups.is_empty());
        assert_eq!(id.user_key, "0f8c6e3a-1b2c");
        assert_eq!(id.issuer, "https://idp");
    }

    #[test]
    fn rejects_unsafe_or_missing_user_key() {
        let c = claims(json!({"sub": "s", "preferred_username": "../admin"}));
        assert!(identity_from_claims(&c, "i", "preferred_username", "groups").is_err());
        assert!(identity_from_claims(&c, "i", "oid", "groups").is_err());
        let c = claims(json!({"sub": "s", "groups": {"x": 1}}));
        assert!(identity_from_claims(&c, "i", "sub", "groups").is_err());
    }
}
