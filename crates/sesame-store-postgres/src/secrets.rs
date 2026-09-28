// SPDX-License-Identifier: Apache-2.0
//! Coffre de secrets PostgreSQL (ADR 0021) : implémentation par défaut de `SecretStore`,
//! sans dépendance à Vault / OpenBao. Une ligne par champ (`app_secrets`), valeur
//! chiffrée (AES-256-GCM, liée par AAD au triplet appli / utilisateur / champ). Le proxy
//! lit avec cette implémentation ; l'UI d'admin écrit avec la même clé, côté Python
//! (`admin/…/crypto.py`), jamais avec les mêmes droits PostgreSQL en production
//! (voir ADR 0021 : rôles distincts recommandés, comme l'AppRole de Vault).

use std::collections::BTreeMap;

use async_trait::async_trait;
use sesame_core::crypto::CookieCipher;
use sesame_core::identity::validate_user_key;
use sesame_core::ports::{PortError, PortResult, SecretStore};
use sesame_core::secret::{Credential, SecretString};
use sqlx::postgres::PgPool;
use sqlx::Row;

use crate::db_err;

pub struct PgSecretStore {
    pool: PgPool,
    cipher: CookieCipher,
}

fn segment_ok(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains('/')
}

fn aad(app_id: &str, user_key: &str, key: &str) -> Vec<u8> {
    format!("{app_id}|{user_key}|{key}").into_bytes()
}

impl PgSecretStore {
    pub fn new(pool: PgPool, cipher: CookieCipher) -> Self {
        Self { pool, cipher }
    }

    /// Écrit les champs d'un secret (usage : seed de dev et tests ; en production,
    /// l'UI d'admin écrit directement, avec ses propres droits PostgreSQL).
    /// Remplace l'ensemble des champs, comme un `PUT` KV v2 de Vault.
    pub async fn put_credential(
        &self,
        app_id: &str,
        user_key: &str,
        fields: &BTreeMap<String, String>,
    ) -> PortResult<()> {
        if !segment_ok(app_id) || validate_user_key(user_key).is_err() {
            return Err(PortError::Other(
                "identifiant d'appli ou d'utilisateur invalide".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let keys: Vec<&str> = fields.keys().map(String::as_str).collect();
        sqlx::query("DELETE FROM app_secrets WHERE app_id = $1 AND user_key = $2 AND NOT (key = ANY($3))")
            .bind(app_id)
            .bind(user_key)
            .bind(&keys)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        for (key, value) in fields {
            let ciphertext = self.cipher.encrypt(value.as_bytes(), &aad(app_id, user_key, key));
            sqlx::query(
                "INSERT INTO app_secrets (app_id, user_key, key, ciphertext) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (app_id, user_key, key) DO UPDATE SET ciphertext = $4, updated_at = now()",
            )
            .bind(app_id)
            .bind(user_key)
            .bind(key)
            .bind(&ciphertext)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)
    }

    /// Supprime toutes les valeurs d'un secret (usage : seed de dev et tests).
    pub async fn delete_credential(&self, app_id: &str, user_key: &str) -> PortResult<()> {
        sqlx::query("DELETE FROM app_secrets WHERE app_id = $1 AND user_key = $2")
            .bind(app_id)
            .bind(user_key)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }
}

#[async_trait]
impl SecretStore for PgSecretStore {
    async fn get_credential(&self, app_id: &str, user_key: &str) -> PortResult<Credential> {
        if !segment_ok(app_id) || validate_user_key(user_key).is_err() {
            return Err(PortError::Other(
                "identifiant d'appli ou d'utilisateur invalide".into(),
            ));
        }
        let rows = sqlx::query("SELECT key, ciphertext FROM app_secrets WHERE app_id = $1 AND user_key = $2")
            .bind(app_id)
            .bind(user_key)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        if rows.is_empty() {
            return Err(PortError::NotFound);
        }
        let mut fields = BTreeMap::new();
        for row in rows {
            let key: String = row.get("key");
            let ciphertext: Vec<u8> = row.get("ciphertext");
            let plain = self
                .cipher
                .decrypt(&ciphertext, &aad(app_id, user_key, &key))
                .map_err(|_| PortError::Other("secret indéchiffrable".into()))?;
            let value = String::from_utf8(plain.to_vec())
                .map_err(|_| PortError::Other("secret illisible (valeurs texte attendues)".into()))?;
            fields.insert(key, SecretString::from(value));
        }
        Ok(Credential::new(fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    fn cipher() -> CookieCipher {
        CookieCipher::from_base64(&SecretString::from(STANDARD.encode([9u8; 32]))).unwrap()
    }

    #[test]
    fn rejects_invalid_identifiers() {
        assert!(!segment_ok(""));
        assert!(!segment_ok(".."));
        assert!(!segment_ok("a/b"));
        assert!(segment_ok("fake-app"));
    }

    #[test]
    fn aad_binds_app_user_and_key() {
        let c = cipher();
        let ct = c.encrypt(b"s3cret", &aad("app1", "alice", "password"));
        assert!(c.decrypt(&ct, &aad("app1", "alice", "password")).is_ok());
        assert!(c.decrypt(&ct, &aad("app1", "alice", "username")).is_err());
        assert!(c.decrypt(&ct, &aad("app2", "alice", "password")).is_err());
    }
}
