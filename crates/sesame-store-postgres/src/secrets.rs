// SPDX-License-Identifier: Apache-2.0
//! Coffre de secrets PostgreSQL (ADR 0021) : implémentation par défaut de `SecretStore`,
//! sans dépendance à Vault / OpenBao. Une ligne par champ (`app_secrets`), valeur
//! chiffrée (AES-256-GCM, liée par AAD au compte et au champ). Le proxy
//! lit avec cette implémentation ; l'UI d'admin écrit avec la même clé, côté Python
//! (`admin/…/crypto.py`), jamais avec les mêmes droits PostgreSQL en production
//! (voir ADR 0021 : rôles distincts recommandés, comme l'AppRole de Vault).

use std::collections::BTreeMap;

use async_trait::async_trait;
use sesame_core::crypto::CookieCipher;
use sesame_core::identity::validate_user_key;
use sesame_core::ports::{account_id_ok, AccountKey, PortError, PortResult, SecretStore, SecretWriter};
use sesame_core::secret::{Credential, ExposeSecret, SecretString};
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

/// Donnée authentifiée d'un champ. Compte `default` : `appli|utilisateur|champ`, format d'avant
/// les comptes multiples (ADR 0034), pour ne rien rechiffrer. Autres comptes :
/// `appli|utilisateur#compte|champ` ; `#` et `|` étant interdits dans une clé utilisateur, les
/// deux formes ne peuvent pas coïncider. Doit rester identique à `admin/…/crypto.py`.
fn aad(account: &AccountKey, key: &str) -> Vec<u8> {
    let AccountKey {
        app_id,
        user_key,
        account_id,
    } = account;
    if account.is_default_id() {
        format!("{app_id}|{user_key}|{key}").into_bytes()
    } else {
        format!("{app_id}|{user_key}#{account_id}|{key}").into_bytes()
    }
}

fn check(account: &AccountKey) -> PortResult<()> {
    if !segment_ok(&account.app_id)
        || validate_user_key(&account.user_key).is_err()
        || !account_id_ok(&account.account_id)
    {
        return Err(PortError::Other(
            "identifiant d'appli, d'utilisateur ou de compte invalide".into(),
        ));
    }
    Ok(())
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
        account: &AccountKey,
        fields: &BTreeMap<String, String>,
    ) -> PortResult<()> {
        check(account)?;
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let keys: Vec<&str> = fields.keys().map(String::as_str).collect();
        sqlx::query(
            "DELETE FROM app_secrets
             WHERE app_id = $1 AND user_key = $2 AND account_id = $3 AND NOT (key = ANY($4))",
        )
        .bind(&account.app_id)
        .bind(&account.user_key)
        .bind(&account.account_id)
        .bind(&keys)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        for (key, value) in fields {
            let ciphertext = self.cipher.encrypt(value.as_bytes(), &aad(account, key));
            sqlx::query(
                "INSERT INTO app_secrets (app_id, user_key, account_id, key, ciphertext) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (app_id, user_key, account_id, key) DO UPDATE SET ciphertext = $5, updated_at = now()",
            )
            .bind(&account.app_id)
            .bind(&account.user_key)
            .bind(&account.account_id)
            .bind(key)
            .bind(&ciphertext)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)
    }

    /// Supprime toutes les valeurs d'un secret (usage : seed de dev et tests).
    pub async fn delete_credential(&self, account: &AccountKey) -> PortResult<()> {
        sqlx::query("DELETE FROM app_secrets WHERE app_id = $1 AND user_key = $2 AND account_id = $3")
            .bind(&account.app_id)
            .bind(&account.user_key)
            .bind(&account.account_id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }
}

#[async_trait]
impl SecretWriter for PgSecretStore {
    async fn put_credential(&self, account: &AccountKey, credential: &Credential) -> PortResult<()> {
        let fields = credential
            .keys()
            .filter_map(|k| {
                credential
                    .get(k)
                    .map(|v| (k.to_owned(), v.expose_secret().to_owned()))
            })
            .collect();
        PgSecretStore::put_credential(self, account, &fields).await
    }
}

#[async_trait]
impl SecretStore for PgSecretStore {
    async fn get_credential(&self, account: &AccountKey) -> PortResult<Credential> {
        check(account)?;
        let rows = sqlx::query(
            "SELECT key, ciphertext FROM app_secrets WHERE app_id = $1 AND user_key = $2 AND account_id = $3",
        )
        .bind(&account.app_id)
        .bind(&account.user_key)
        .bind(&account.account_id)
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
                .decrypt(&ciphertext, &aad(account, &key))
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
    fn aad_binds_account_and_key() {
        let c = cipher();
        let alice = AccountKey::default_of("app1", "alice");
        let admin = AccountKey::new("app1", "alice", "admin");
        // Compte `default` : format d'avant les comptes multiples, inchangé.
        assert_eq!(aad(&alice, "password"), b"app1|alice|password");
        assert_eq!(aad(&admin, "password"), b"app1|alice#admin|password");
        let ct = c.encrypt(b"s3cret", &aad(&alice, "password"));
        assert!(c.decrypt(&ct, &aad(&alice, "password")).is_ok());
        assert!(c.decrypt(&ct, &aad(&alice, "username")).is_err());
        assert!(c.decrypt(&ct, &aad(&admin, "password")).is_err());
        assert!(c
            .decrypt(&ct, &aad(&AccountKey::default_of("app2", "alice"), "password"))
            .is_err());
    }

    #[test]
    fn rejects_invalid_account_ids() {
        assert!(check(&AccountKey::new("app1", "alice", "admin")).is_ok());
        for bad in ["", "Admin", "a/b", "-x", "a|b", "a#b"] {
            assert!(check(&AccountKey::new("app1", "alice", bad)).is_err(), "{bad}");
        }
    }
}
