// SPDX-License-Identifier: Apache-2.0
//! Modèle du descripteur d'appli (`schemas/app-descriptor.schema.json`).
//!
//! Le schéma JSON fait foi pour la structure ; `validate` ajoute les contrôles
//! qu'il ne peut pas exprimer (regex compilables, clés du coffre cohérentes).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Deserializer};

pub const API_VERSION: &str = "sesame/v1";
pub const KIND: &str = "AppDescriptor";

#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    #[error("lecture de {path} : {source}")]
    Io { path: String, source: std::io::Error },
    #[error("syntaxe : {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("invalide : {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AppDescriptor {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: Spec,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub revision: u32,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub upstream: Upstream,
    pub public: Public,
    #[serde(default)]
    pub access: Access,
    pub credentials: Credentials,
    pub login: Login,
    pub session: Session,
    pub expiry: MatcherSet,
    #[serde(default)]
    pub logout: Logout,
    #[serde(default)]
    pub rewrite: Rewrite,
    #[serde(default)]
    pub health: Health,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub base_url: String,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default = "default_timeout", deserialize_with = "de_duration")]
    pub timeout: Duration,
    #[serde(default)]
    pub host_header: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    #[serde(default = "yes")]
    pub verify: bool,
    #[serde(default)]
    pub ca_file: Option<String>,
}

impl Default for Tls {
    fn default() -> Self {
        Self {
            verify: true,
            ca_file: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Public {
    pub host: String,
    /// Page d'arrivée ouverte par la tuile du portail.
    #[serde(default = "default_start_path")]
    pub start_path: String,
}

fn default_start_path() -> String {
    "/".into()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
}

impl Access {
    /// Habilitation vide (aucun groupe ni utilisateur) : autorisé — le compte actif fait foi.
    /// Sinon, autorisé si l'utilisateur est listé ou appartient à l'un des groupes.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty() && self.users.is_empty()
    }

    pub fn allows(&self, user_key: &str, groups: &[String]) -> bool {
        self.is_empty()
            || self.users.iter().any(|u| u == user_key)
            || self.groups.iter().any(|g| groups.contains(g))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    PerUser,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub mode: CredentialMode,
    pub keys: Vec<String>,
}

/// Valeur d'un champ rejoué : clé du coffre ou constante non sensible.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawFormField")]
pub enum FormField {
    FromSecret(String),
    Value(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFormField {
    from_secret: Option<String>,
    value: Option<String>,
}

impl TryFrom<RawFormField> for FormField {
    type Error = String;

    fn try_from(raw: RawFormField) -> Result<Self, Self::Error> {
        match (raw.from_secret, raw.value) {
            (Some(key), None) => Ok(Self::FromSecret(key)),
            (None, Some(value)) => Ok(Self::Value(value)),
            _ => Err("un champ attend exactement une propriété : from_secret ou value".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CsrfSource {
    HiddenInput,
    Meta,
    Cookie,
    Regex,
    /// Réponse d'un appel GET fait juste avant le login (`url`) : champ JSON `name`
    /// (chemin pointé) ou `pattern` appliqué au corps.
    Endpoint,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendAs {
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub header: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsrfToken {
    pub source: CsrfSource,
    pub name: String,
    /// Pour `source: endpoint` : chemin appelé en GET, même origine.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub send_as: SendAs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum Method {
    #[default]
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "GET")]
    Get,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    #[default]
    Form,
    Json,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    pub form_url: String,
    #[serde(default = "default_form_selector")]
    pub form_selector: String,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub method: Method,
    #[serde(default)]
    pub encoding: Encoding,
    #[serde(default = "yes")]
    pub include_hidden_inputs: bool,
    pub fields: BTreeMap<String, FormField>,
    #[serde(default)]
    pub csrf: Vec<CsrfToken>,
    #[serde(default)]
    pub extra_headers: BTreeMap<String, String>,
    pub success: MatcherSet,
    #[serde(default)]
    pub failure: Option<MatcherSet>,
    #[serde(default = "one")]
    pub max_attempts: u8,
}

/// Condition sur une réponse : toutes les propriétés présentes doivent être vraies.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub location_matches: Option<String>,
    #[serde(default)]
    pub location_not_matches: Option<String>,
    #[serde(default)]
    pub cookie_set: Option<String>,
    #[serde(default)]
    pub body_contains: Option<String>,
    #[serde(default)]
    pub body_not_contains: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatcherSet {
    pub any_of: Vec<Matcher>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub cookies: Vec<String>,
    #[serde(default = "default_max_ttl", deserialize_with = "de_duration")]
    pub max_ttl: Duration,
    #[serde(default = "default_idle_ttl", deserialize_with = "de_duration")]
    pub idle_ttl: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogoutAction {
    #[default]
    Forward,
    PortalLogout,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Logout {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub action: LogoutAction,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    #[serde(default = "yes")]
    pub location: bool,
    #[serde(default)]
    pub body_absolute_urls: bool,
    #[serde(default = "default_content_types")]
    pub content_types: Vec<String>,
}

impl Default for Rewrite {
    fn default() -> Self {
        Self {
            location: true,
            body_absolute_urls: false,
            content_types: default_content_types(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    #[serde(default = "default_health_interval", deserialize_with = "de_duration")]
    pub interval: Duration,
    #[serde(default)]
    pub form_fingerprint: Option<String>,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            interval: default_health_interval(),
            form_fingerprint: None,
        }
    }
}

impl AppDescriptor {
    pub fn from_yaml(text: &str) -> Result<Self, DescriptorError> {
        let descriptor: Self = serde_yaml::from_str(text)?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Descripteur stocké en base (document JSON), avec les mêmes contrôles.
    pub fn from_json(value: serde_json::Value) -> Result<Self, DescriptorError> {
        let descriptor: Self =
            serde_json::from_value(value).map_err(|e| DescriptorError::Invalid(format!("document : {e}")))?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn from_file(path: &Path) -> Result<Self, DescriptorError> {
        let text = std::fs::read_to_string(path).map_err(|source| DescriptorError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml(&text)
    }

    /// Contrôles non exprimables dans le schéma JSON.
    pub fn validate(&self) -> Result<(), DescriptorError> {
        let id = &self.metadata.id;
        let err = |msg: String| DescriptorError::Invalid(format!("{id} : {msg}"));
        let invalid = |msg: String| Err(err(msg));

        if self.api_version != API_VERSION || self.kind != KIND {
            return invalid(format!("apiVersion/kind attendus : {API_VERSION}/{KIND}"));
        }
        let id_ok = Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("regex statique");
        if !id_ok.is_match(&self.metadata.id) {
            return invalid("metadata.id invalide".into());
        }
        let start = &self.spec.public.start_path;
        if !start.starts_with('/') || start.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return invalid("public.start_path : chemin commençant par / attendu".into());
        }
        let spec = &self.spec;
        if spec.credentials.keys.is_empty() {
            return invalid("credentials.keys vide".into());
        }
        for (name, field) in &spec.login.fields {
            if let FormField::FromSecret(key) = field {
                if !spec.credentials.keys.contains(key) {
                    return invalid(format!("login.fields.{name} référence la clé inconnue « {key} »"));
                }
            }
        }
        for token in &spec.login.csrf {
            if token.source == CsrfSource::Regex {
                match &token.pattern {
                    Some(p) => compile(p).map_err(err)?,
                    None => {
                        return invalid(format!("csrf {} : pattern requis pour source=regex", token.name))
                    }
                };
            }
            match (token.source, token.url.as_deref()) {
                (CsrfSource::Endpoint, Some(u)) if u.starts_with('/') => {
                    if let Some(p) = &token.pattern {
                        compile(p).map_err(err)?;
                    }
                }
                (CsrfSource::Endpoint, _) => {
                    return invalid(format!(
                        "csrf {} : url (chemin commençant par /) requise pour source=endpoint",
                        token.name
                    ))
                }
                (_, Some(_)) => {
                    return invalid(format!("csrf {} : url réservée à source=endpoint", token.name))
                }
                _ => {}
            }
        }
        if spec.session.cookies.is_empty() {
            return invalid("session.cookies vide".into());
        }
        if !(1..=5).contains(&spec.login.max_attempts) {
            return invalid("login.max_attempts doit être entre 1 et 5".into());
        }
        let sets = [
            Some(&spec.login.success),
            spec.login.failure.as_ref(),
            Some(&spec.expiry),
        ];
        for set in sets.into_iter().flatten() {
            if set.any_of.is_empty() {
                return invalid("any_of vide".into());
            }
            for m in &set.any_of {
                for p in [&m.location_matches, &m.location_not_matches]
                    .into_iter()
                    .flatten()
                {
                    compile(p).map_err(err)?;
                }
            }
        }
        for p in &spec.logout.paths {
            compile(p).map_err(err)?;
        }
        Ok(())
    }
}

/// Charge tous les `*.yaml` / `*.yml` d'un dossier. Un descripteur invalide,
/// un `metadata.id` ou un `public.host` en double font échouer le chargement.
pub fn load_dir(dir: &Path) -> Result<Vec<AppDescriptor>, DescriptorError> {
    let io = |source| DescriptorError::Io {
        path: dir.display().to_string(),
        source,
    };
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .map_err(io)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "yaml" || ext == "yml"))
        .collect();
    paths.sort();
    let descriptors = paths
        .iter()
        .map(|p| AppDescriptor::from_file(p))
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen = std::collections::HashSet::new();
    for d in &descriptors {
        if !seen.insert(("id", d.metadata.id.as_str())) {
            return Err(DescriptorError::Invalid(format!(
                "metadata.id en double : {}",
                d.metadata.id
            )));
        }
        if !seen.insert(("host", d.spec.public.host.as_str())) {
            return Err(DescriptorError::Invalid(format!(
                "public.host en double : {}",
                d.spec.public.host
            )));
        }
    }
    Ok(descriptors)
}

fn compile(pattern: &str) -> Result<Regex, String> {
    Regex::new(pattern).map_err(|e| format!("regex « {pattern} » : {e}"))
}

/// Durée « 30s », « 15m », « 8h ».
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let invalid = || format!("durée invalide : {text}");
    let (digits, factor) = [("s", 1), ("m", 60), ("h", 3600)]
        .into_iter()
        .find_map(|(unit, factor)| text.strip_suffix(unit).map(|d| (d, factor)))
        .ok_or_else(invalid)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let n: u64 = digits.parse().map_err(|_| invalid())?;
    n.checked_mul(factor).map(Duration::from_secs).ok_or_else(invalid)
}

fn de_duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let text = String::deserialize(d)?;
    parse_duration(&text).map_err(serde::de::Error::custom)
}

fn yes() -> bool {
    true
}
fn one() -> u8 {
    1
}
fn default_timeout() -> Duration {
    Duration::from_secs(30)
}
fn default_max_ttl() -> Duration {
    Duration::from_secs(8 * 3600)
}
fn default_idle_ttl() -> Duration {
    Duration::from_secs(30 * 60)
}
fn default_health_interval() -> Duration {
    Duration::from_secs(3600)
}
fn default_form_selector() -> String {
    "form".into()
}
fn default_content_types() -> Vec<String> {
    ["text/html", "text/css", "application/javascript"]
        .map(String::from)
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_APP: &str = include_str!("../../../descriptors/fake-app.yaml");

    #[test]
    fn parses_fake_app_descriptor() {
        let d = AppDescriptor::from_yaml(FAKE_APP).expect("descripteur valide");
        assert_eq!(d.metadata.id, "fake-app");
        assert_eq!(d.spec.credentials.mode, CredentialMode::PerUser);
        assert_eq!(d.spec.session.cookies, ["FAKEAPPSESSID"]);
        assert_eq!(d.spec.session.idle_ttl, Duration::from_secs(1800));
        assert!(matches!(d.spec.login.fields["password"], FormField::FromSecret(ref k) if k == "password"));
        assert_eq!(d.spec.login.csrf[0].source, CsrfSource::HiddenInput);
    }

    #[test]
    fn access_by_group_or_user() {
        let access = Access {
            groups: vec!["g1".into()],
            users: vec!["carol".into()],
        };
        assert!(access.allows("alice", &["g1".into()]));
        assert!(access.allows("carol", &[]));
        assert!(!access.allows("bob", &["g2".into()]));
        // Habilitation vide : autorisé (le compte actif fait foi).
        let open = Access::default();
        assert!(open.is_empty() && open.allows("bob", &[]));
    }

    #[test]
    fn endpoint_csrf_requires_a_path_and_nothing_else_takes_one() {
        let with = |from: &str, to: &str| AppDescriptor::from_yaml(&FAKE_APP.replace(from, to));
        let endpoint = "- source: endpoint\n        url: /api/csrf-token";
        let d = with("- source: hidden_input", endpoint).expect("endpoint valide");
        assert_eq!(d.spec.login.csrf[0].source, CsrfSource::Endpoint);
        assert_eq!(d.spec.login.csrf[0].url.as_deref(), Some("/api/csrf-token"));
        assert!(
            with("- source: hidden_input", "- source: endpoint").is_err(),
            "url requise"
        );
        assert!(with("- source: hidden_input", "- source: endpoint\n        url: api").is_err());
        assert!(
            with("name: csrf_token", "name: csrf_token\n        url: /x").is_err(),
            "url réservée"
        );
    }

    #[test]
    fn start_path_defaults_to_root_and_must_be_a_path() {
        assert_eq!(
            AppDescriptor::from_yaml(FAKE_APP).unwrap().spec.public.start_path,
            "/"
        );
        let with = |p: &str| {
            AppDescriptor::from_yaml(&FAKE_APP.replace("start_path: /  ", &format!("start_path: \"{p}\"  ")))
        };
        assert_eq!(
            with("/chat?room=1").unwrap().spec.public.start_path,
            "/chat?room=1"
        );
        assert!(with("chat").is_err() && with("/a b").is_err());
    }

    #[test]
    fn descriptor_without_access_is_valid_and_open() {
        let text = FAKE_APP.replace("  access:\n    groups:\n      - fake-app-users\n", "");
        let d = AppDescriptor::from_yaml(&text).expect("access facultatif");
        assert!(d.spec.access.is_empty());
        assert!(d.spec.access.allows("nimporte", &[]));
    }

    #[test]
    fn rejects_unknown_secret_key() {
        let text = FAKE_APP.replace(
            "password: { from_secret: password }",
            "password: { from_secret: pin }",
        );
        let err = AppDescriptor::from_yaml(&text).unwrap_err().to_string();
        assert!(err.contains("pin"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = FAKE_APP.replace("  revision: 1", "  revision: 1\n  typo: x");
        assert!(matches!(
            AppDescriptor::from_yaml(&text),
            Err(DescriptorError::Parse(_))
        ));
    }

    #[test]
    fn rejects_bad_regex() {
        let text = FAKE_APP.replace(r#"paths: ["^/logout$"]"#, r#"paths: ["(unclosed"]"#);
        assert!(matches!(
            AppDescriptor::from_yaml(&text),
            Err(DescriptorError::Invalid(_))
        ));
    }

    #[test]
    fn parses_json_documents() {
        let yaml: serde_json::Value = serde_yaml::from_str(FAKE_APP).unwrap();
        let d = AppDescriptor::from_json(yaml.clone()).expect("document JSON valide");
        assert_eq!(d.metadata.id, "fake-app");
        let mut bad = yaml;
        bad["spec"]["login"]["fields"]["password"] = serde_json::json!({"from_secret": "pin"});
        assert!(matches!(
            AppDescriptor::from_json(bad),
            Err(DescriptorError::Invalid(_))
        ));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert!(parse_duration("10d").is_err());
        assert!(parse_duration("").is_err());
    }
}
