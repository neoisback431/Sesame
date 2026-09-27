// SPDX-License-Identifier: Apache-2.0
//! Types transportant des secrets.
//!
//! Leur représentation `Debug` est masquée, ils n'implémentent ni `Display`
//! ni `Serialize`, et leur mémoire est effacée à la destruction (`zeroize`
//! via `secrecy`). Lire la valeur exige un appel explicite à `expose_secret`.

use std::collections::BTreeMap;
use std::fmt;

pub use secrecy::{ExposeSecret, SecretString};

/// Identifiants applicatifs d'un couple (appli, utilisateur), lus dans le coffre.
///
/// Les clés (`username`, `password`…) ne sont pas sensibles ; les valeurs le sont.
pub struct Credential {
    fields: BTreeMap<String, SecretString>,
}

impl Credential {
    pub fn new(fields: BTreeMap<String, SecretString>) -> Self {
        Self { fields }
    }

    pub fn get(&self, key: &str) -> Option<&SecretString> {
        self.fields.get(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(String::as_str)
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("keys", &self.fields.keys().collect::<Vec<_>>())
            .field("values", &"***")
            .finish()
    }
}

/// Cookie de session applicatif. Ne quitte jamais le serveur.
pub struct AppCookie {
    pub name: String,
    pub value: SecretString,
}

impl fmt::Debug for AppCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppCookie")
            .field("name", &self.name)
            .field("value", &"***")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_values() {
        let cred = Credential::new(BTreeMap::from([
            ("username".into(), SecretString::from("alice-app")),
            ("password".into(), SecretString::from("s3cr3t-value")),
        ]));
        let cookie = AppCookie {
            name: "SESSID".into(),
            value: SecretString::from("cookie-value"),
        };
        let out = format!("{cred:?} {cred:#?} {cookie:?} {cookie:#?}");
        for leaked in ["alice-app", "s3cr3t-value", "cookie-value"] {
            assert!(!out.contains(leaked), "fuite de {leaked} dans {out}");
        }
        assert!(out.contains("username") && out.contains("SESSID"));
        assert_eq!(cred.get("password").unwrap().expose_secret(), "s3cr3t-value");
    }
}
