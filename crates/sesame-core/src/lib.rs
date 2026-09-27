// SPDX-License-Identifier: Apache-2.0
//! Cœur de Sesame.
//!
//! Ce crate ne dépend d'aucun fournisseur externe : il définit le modèle des
//! descripteurs d'appli, les interfaces des briques externes (coffre, magasin
//! de sessions, audit), l'identité utilisateur issue de l'OIDC et les types
//! qui transportent des secrets sans jamais les afficher.

pub mod audit;
pub mod descriptor;
pub mod identity;
pub mod ports;
pub mod secret;
pub mod telemetry;
