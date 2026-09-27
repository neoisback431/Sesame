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
    /// Libellé affichable (e-mail, nom), sans valeur d'autorisation.
    pub display_name: Option<String>,
    /// Groupes issus des claims, utilisés pour les habilitations.
    pub groups: Vec<String>,
}
