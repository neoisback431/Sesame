// SPDX-License-Identifier: Apache-2.0
//! Rejeu du login d'une appli selon son descripteur.
//!
//! Les identifiants ne vivent qu'en mémoire, le temps du rejeu (types effacés à
//! la destruction). Chaque lecture du coffre et chaque rejeu sont audités, en
//! succès comme en échec ; un échec de rejeu passe le compte à l'état `failed`
//! pour éviter les verrouillages de compte par rejeux répétés.

use std::sync::Arc;
use std::time::SystemTime;

use reqwest::header::{CONTENT_TYPE, COOKIE, HOST, LOCATION, ORIGIN, REFERER, SET_COOKIE};
use reqwest::{Method, StatusCode};
use sesame_core::audit::{AuditAction, AuditEvent, AuditOutcome};
use sesame_core::descriptor::{AppDescriptor, Encoding, FormField, Method as LoginMethod};
use sesame_core::identity::UserIdentity;
use sesame_core::ports::{AccountRegistry, AccountStatus, AuditSink, PortError, SecretStore};
use sesame_core::secret::{Credential, ExposeSecret};
use url::Url;
use zeroize::Zeroizing;

use crate::form::{extract_csrf, parse_form};
use crate::jar::Jar;
use crate::matcher::{self, ResponseView};

const MAX_LOGIN_BODY: usize = 2 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// Pas de compte actif : refusé sans lire le coffre.
    #[error("accès refusé ({0})")]
    AccessDenied(&'static str),
    #[error("coffre indisponible")]
    SecretUnavailable,
    /// Connexion refusée ou page inattendue : compte passé à `failed`.
    #[error("rejeu refusé ({0})")]
    Rejected(&'static str),
    #[error("appli injoignable")]
    Upstream,
    #[error("journal d'audit indisponible")]
    Audit,
}

enum Outcome {
    Success(Jar),
    /// Échec certain : inutile de réessayer.
    Failure(&'static str),
    /// Réponse inattendue : un nouvel essai est permis dans la limite de `max_attempts`.
    Indeterminate(&'static str),
}

pub struct Replayer {
    pub secrets: Arc<dyn SecretStore>,
    pub accounts: Arc<dyn AccountRegistry>,
    pub audit: Arc<dyn AuditSink>,
}

/// Corps de requête effacé de la mémoire à la destruction (contient le mot de passe).
struct ZeroizingBody(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for ZeroizingBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.origin() == b.origin()
}

async fn read_limited(resp: reqwest::Response) -> Result<String, reqwest::Error> {
    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let room = MAX_LOGIN_BODY.saturating_sub(buf.len());
        buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if buf.len() >= MAX_LOGIN_BODY {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn set_cookies(resp: &reqwest::Response) -> Vec<String> {
    resp.headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect()
}

impl Replayer {
    async fn audit(&self, event: AuditEvent) -> Result<(), ReplayError> {
        self.audit.record(event).await.map_err(|e| {
            tracing::error!(error = %e, "écriture d'audit impossible");
            ReplayError::Audit
        })
    }

    async fn mark_failed(&self, d: &AppDescriptor, user: &UserIdentity, cid: &str, reason: &'static str) {
        let app = &d.metadata.id;
        match self
            .accounts
            .set_status(app, &user.user_key, AccountStatus::Failed, Some(reason))
            .await
        {
            Ok(()) => {
                let event = AuditEvent::new(AuditAction::AccountStatusChanged, AuditOutcome::Success)
                    .actor(user)
                    .app(app)
                    .correlation(cid)
                    .reason(format!("failed:{reason}"));
                let _ = self.audit(event).await;
            }
            Err(e) => tracing::error!(error = %e, app, "mise à jour du registre des comptes impossible"),
        }
    }

    /// Vérifie le compte, lit le coffre, rejoue le login. Renvoie le jar de session.
    pub async fn replay(
        &self,
        http: &reqwest::Client,
        d: &AppDescriptor,
        user: &UserIdentity,
        cid: &str,
    ) -> Result<Jar, ReplayError> {
        let app = d.metadata.id.as_str();
        let event = |action, outcome| {
            AuditEvent::new(action, outcome)
                .actor(user)
                .app(app)
                .correlation(cid)
        };

        // 1. Registre des comptes : aucun accès au coffre sans compte actif.
        let account = self
            .accounts
            .get_account(app, &user.user_key)
            .await
            .map_err(|_| ReplayError::SecretUnavailable)?;
        let denied = match account.map(|a| a.status) {
            Some(AccountStatus::Active) => None,
            Some(AccountStatus::Failed) => Some("account_failed"),
            Some(AccountStatus::Disabled) => Some("account_disabled"),
            None => Some("no_account"),
        };
        if let Some(reason) = denied {
            self.audit(event(AuditAction::AccessDenied, AuditOutcome::Failure).reason(reason))
                .await?;
            return Err(ReplayError::AccessDenied(reason));
        }

        // 2. Coffre : lecture auditée, succès ou échec.
        let credential = match self.secrets.get_credential(app, &user.user_key).await {
            Ok(c) => {
                self.audit(event(AuditAction::SecretRead, AuditOutcome::Success))
                    .await?;
                c
            }
            Err(e) => {
                let (reason, err) = match e {
                    PortError::NotFound => ("secret_missing", None),
                    PortError::Forbidden => ("secret_forbidden", Some(ReplayError::SecretUnavailable)),
                    _ => ("secret_store_unavailable", Some(ReplayError::SecretUnavailable)),
                };
                self.audit(event(AuditAction::SecretRead, AuditOutcome::Failure).reason(reason))
                    .await?;
                return Err(match err {
                    Some(err) => err,
                    None => {
                        self.mark_failed(d, user, cid, reason).await;
                        ReplayError::Rejected(reason)
                    }
                });
            }
        };

        // 3. Rejeu, dans la limite de max_attempts.
        let mut last = ReplayError::Upstream;
        for attempt in 1..=d.spec.login.max_attempts {
            match self.login(http, d, &credential).await {
                Ok(Outcome::Success(jar)) => {
                    self.audit(event(AuditAction::LoginReplay, AuditOutcome::Success))
                        .await?;
                    if let Err(e) = self
                        .accounts
                        .record_login(app, &user.user_key, SystemTime::now())
                        .await
                    {
                        tracing::warn!(error = %e, app, "date de dernière connexion non enregistrée");
                    }
                    tracing::info!(app, correlation_id = cid, attempt, "rejeu réussi");
                    return Ok(jar);
                }
                Ok(Outcome::Failure(reason)) => {
                    last = ReplayError::Rejected(reason);
                    break;
                }
                Ok(Outcome::Indeterminate(reason)) => last = ReplayError::Rejected(reason),
                Err(e) => {
                    tracing::warn!(app, correlation_id = cid, error = %e.without_url(), "appli injoignable pendant le rejeu");
                    last = ReplayError::Upstream;
                }
            }
        }
        drop(credential);

        let err = last;
        let reason: &'static str = match &err {
            ReplayError::Rejected(r) => r,
            _ => "upstream_unreachable",
        };
        self.audit(event(AuditAction::LoginReplay, AuditOutcome::Failure).reason(reason))
            .await?;
        if let ReplayError::Rejected(r) = err {
            self.mark_failed(d, user, cid, r).await;
        }
        tracing::warn!(app, correlation_id = cid, reason, "rejeu en échec");
        Err(err)
    }

    async fn login(
        &self,
        http: &reqwest::Client,
        d: &AppDescriptor,
        cred: &Credential,
    ) -> Result<Outcome, reqwest::Error> {
        let spec = &d.spec;
        let login = &spec.login;
        let Ok(base) = Url::parse(&spec.upstream.base_url) else {
            return Ok(Outcome::Failure("invalid_base_url"));
        };
        let Ok(mut page_url) = base.join(&login.form_url) else {
            return Ok(Outcome::Failure("invalid_form_url"));
        };
        let request = |method: Method, url: Url, jar: &Jar| {
            let mut req = http.request(method, url).timeout(spec.upstream.timeout);
            if let Some(h) = &spec.upstream.host_header {
                req = req.header(HOST, h);
            }
            if let Some(c) = jar.header() {
                req = req.header(COOKIE, c.expose_secret());
            }
            req
        };

        // Page de login (redirections suivies dans la même origine).
        let mut jar = Jar::default();
        let mut resp = request(Method::GET, page_url.clone(), &jar).send().await?;
        for _ in 0..MAX_REDIRECTS {
            jar.apply(set_cookies(&resp).iter().map(String::as_str));
            if !resp.status().is_redirection() {
                break;
            }
            let next = resp
                .headers()
                .get(LOCATION)
                .and_then(|l| l.to_str().ok())
                .and_then(|l| page_url.join(l).ok());
            match next {
                Some(next) if same_origin(&next, &base) => page_url = next,
                _ => return Ok(Outcome::Failure("login_page_redirects_away")),
            }
            resp = request(Method::GET, page_url.clone(), &jar).send().await?;
        }
        if resp.status() != StatusCode::OK {
            return Ok(Outcome::Indeterminate("login_page_status"));
        }
        let html = read_limited(resp).await?;

        let Ok(form) = parse_form(&html, &login.form_selector) else {
            return Ok(Outcome::Failure("login_form_not_found"));
        };
        let action = login
            .action
            .as_deref()
            .or(form.action.as_deref().filter(|a| !a.is_empty()))
            .map_or(Ok(page_url.clone()), |a| page_url.join(a));
        let action = match action {
            // Jamais d'identifiants envoyés hors de l'origine de l'appli.
            Ok(a) if same_origin(&a, &base) => a,
            _ => return Ok(Outcome::Failure("login_action_foreign_origin")),
        };

        // Champs : cachés, puis descripteur (identifiants), puis jetons CSRF.
        let mut fields: Vec<(String, Zeroizing<String>)> = Vec::new();
        let mut set = |name: &str, value: Zeroizing<String>| match fields.iter_mut().find(|(n, _)| n == name)
        {
            Some(slot) => slot.1 = value,
            None => fields.push((name.to_owned(), value)),
        };
        if login.include_hidden_inputs {
            for (name, value) in &form.hidden {
                set(name, Zeroizing::new(value.clone()));
            }
        }
        for (name, field) in &login.fields {
            let value = match field {
                FormField::Value(v) => v.clone(),
                FormField::FromSecret(key) => match cred.get(key) {
                    Some(secret) => secret.expose_secret().to_owned(),
                    None => return Ok(Outcome::Failure("secret_key_missing")),
                },
            };
            set(name, Zeroizing::new(value));
        }
        let mut csrf_headers = Vec::new();
        for token in &login.csrf {
            let Ok(value) = extract_csrf(token, &html, &jar) else {
                return Ok(Outcome::Failure("csrf_token_not_found"));
            };
            match (&token.send_as.header, &token.send_as.field) {
                (Some(header), _) => csrf_headers.push((header.clone(), value)),
                (None, field) => set(field.as_deref().unwrap_or(&token.name), Zeroizing::new(value)),
            }
        }

        let (method, content_type, body) = match (login.method, login.encoding) {
            (LoginMethod::Get, _) => (Method::GET, None, None),
            (LoginMethod::Post, Encoding::Form) => {
                let mut ser = url::form_urlencoded::Serializer::new(String::new());
                for (n, v) in &fields {
                    ser.append_pair(n, v);
                }
                let encoded = Zeroizing::new(ser.finish());
                (
                    Method::POST,
                    Some("application/x-www-form-urlencoded"),
                    Some(encoded),
                )
            }
            (LoginMethod::Post, Encoding::Json) => {
                let map: serde_json::Map<_, _> = fields
                    .iter()
                    .map(|(n, v)| (n.clone(), serde_json::Value::String(v.to_string())))
                    .collect();
                let encoded = Zeroizing::new(serde_json::Value::Object(map).to_string());
                (Method::POST, Some("application/json"), Some(encoded))
            }
        };
        let mut target = action;
        if method == Method::GET {
            let mut q = target.query_pairs_mut();
            for (n, v) in &fields {
                q.append_pair(n, v);
            }
        }
        let mut req = request(method, target.clone(), &jar)
            .header(REFERER, page_url.as_str())
            .header(ORIGIN, base.origin().ascii_serialization());
        for (k, v) in &login.extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        for (k, v) in &csrf_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let (Some(ct), Some(body)) = (content_type, body) {
            let owned = ZeroizingBody(Zeroizing::new(body.as_bytes().to_vec()));
            req = req
                .header(CONTENT_TYPE, ct)
                .body(reqwest::Body::from(bytes::Bytes::from_owner(owned)));
        }
        drop(fields);
        let resp = req.send().await?;

        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get(LOCATION)
            .and_then(|l| l.to_str().ok())
            .map(str::to_owned);
        let raw_cookies = set_cookies(&resp);
        let (names, _) = jar.apply(raw_cookies.iter().map(String::as_str));
        let body = read_limited(resp).await?;
        let view = ResponseView {
            status,
            location: location.as_deref(),
            set_cookie_names: &names,
            body: Some(&body),
        };
        if login.failure.as_ref().is_some_and(|f| matcher::any(f, &view)) {
            return Ok(Outcome::Failure("login_rejected"));
        }
        if !matcher::any(&login.success, &view) {
            return Ok(Outcome::Indeterminate("login_unexpected_response"));
        }
        if !spec.session.cookies.iter().all(|c| jar.contains(c)) {
            return Ok(Outcome::Failure("session_cookie_missing"));
        }
        Ok(Outcome::Success(jar))
    }
}
