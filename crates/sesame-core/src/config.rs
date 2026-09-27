// SPDX-License-Identifier: Apache-2.0
//! Lecture de la configuration par variables d'environnement.

use std::time::Duration;

use crate::descriptor::parse_duration;
use crate::secret::SecretString;

#[derive(Debug, thiserror::Error)]
#[error("configuration : {0}")]
pub struct ConfigError(pub String);

pub fn required(name: &str) -> Result<String, ConfigError> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| ConfigError(format!("variable {name} requise")))
}

pub fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

pub fn or(name: &str, default: &str) -> String {
    optional(name).unwrap_or_else(|| default.to_owned())
}

/// Variable sensible : jamais affichée, y compris dans les erreurs.
pub fn secret(name: &str) -> Result<SecretString, ConfigError> {
    required(name).map(SecretString::from)
}

pub fn duration(name: &str, default: &str) -> Result<Duration, ConfigError> {
    parse_duration(&or(name, default)).map_err(|e| ConfigError(format!("{name} : {e}")))
}

pub fn flag(name: &str) -> bool {
    matches!(optional(name).as_deref(), Some("1" | "true" | "yes"))
}
