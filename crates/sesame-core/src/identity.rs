// SPDX-License-Identifier: Apache-2.0
//! Identité utilisateur issue du fournisseur d'identité, indépendante de celui-ci.

use serde::{Deserialize, Serialize};

/// Utilisateur authentifié par le portail.
///
/// Construit à partir des claims OIDC selon un mapping configurable : le cœur
/// ne connaît ni Entra ID, ni Keycloak, ni aucun autre fournisseur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserIdentity {
    /// Émetteur OIDC (`iss`).
    pub issuer: String,
    /// Identifiant stable chez le fournisseur (`sub`, ou `oid` pour Entra ID).
    pub subject: String,
    /// Clé de l'utilisateur dans le coffre (claim configurable, `subject` par défaut).
    pub user_key: String,
    /// Libellé affichable (nom, à défaut e-mail), sans valeur d'autorisation.
    pub display_name: Option<String>,
    /// Adresse e-mail déclarée par le fournisseur d'identité, pour distinguer des homonymes
    /// dans l'administration. Jamais une valeur d'autorisation.
    pub email: Option<String>,
    /// Groupes issus des claims, utilisés pour les habilitations.
    pub groups: Vec<String>,
}

/// Vérifie qu'une clé utilisateur peut servir de segment de chemin (coffre, logs).
///
/// Refuse tout ce qui permettrait de sortir du chemin prévu (`/`, `..`) ou de
/// polluer les journaux (caractères de contrôle).
pub fn validate_user_key(key: &str) -> Result<(), String> {
    let ok = !key.is_empty()
        && key.len() <= 256
        && key != "."
        && key != ".."
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-' | '+'));
    if ok {
        Ok(())
    } else {
        Err("clé utilisateur invalide (caractères autorisés : A-Z a-z 0-9 @ . _ - +)".into())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_user_key;

    #[test]
    fn user_keys() {
        for ok in [
            "alice",
            "a.martin@example.org",
            "0f8c6e3a-1b2c-4d5e-8f90-123456789abc",
        ] {
            assert!(validate_user_key(ok).is_ok(), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "../x", "a b", "a\nb", "é"] {
            assert!(validate_user_key(bad).is_err(), "{bad:?}");
        }
    }
}
