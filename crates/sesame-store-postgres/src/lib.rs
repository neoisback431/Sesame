// SPDX-License-Identifier: Apache-2.0
//! Magasin de sessions et registre des comptes sur PostgreSQL.
//!
//! Les jetons de session portail sont stockés sous forme d'empreinte (fournie
//! par l'appelant), les jars de cookies applicatifs chiffrés (AES-256-GCM,
//! lié par AAD au couple session / appli).

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sesame_core::crypto::CookieCipher;
use sesame_core::identity::UserIdentity;
use sesame_core::ports::{
    AccountRegistry, AccountStatus, AppAccount, AppSession, PortError, PortResult, PortalSession,
    SessionStore,
};
use sesame_core::secret::{AppCookie, ExposeSecret, SecretString};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use zeroize::Zeroizing;

pub struct PgStore {
    pool: PgPool,
    /// Absent pour les services qui ne manipulent pas de sessions applicatives (portail).
    cipher: Option<Arc<CookieCipher>>,
}

fn db_err(e: sqlx::Error) -> PortError {
    match e {
        sqlx::Error::PoolTimedOut | sqlx::Error::Io(_) | sqlx::Error::PoolClosed => {
            PortError::Unavailable("base de données".into())
        }
        other => PortError::Other(format!("base de données : {other}")),
    }
}

fn ts(t: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(t)
}

fn aad(portal_session_id: &str, app_id: &str) -> Vec<u8> {
    format!("{portal_session_id}|{app_id}").into_bytes()
}

fn status_str(s: AccountStatus) -> &'static str {
    match s {
        AccountStatus::Active => "active",
        AccountStatus::Failed => "failed",
        AccountStatus::Disabled => "disabled",
    }
}

fn parse_status(s: &str) -> PortResult<AccountStatus> {
    match s {
        "active" => Ok(AccountStatus::Active),
        "failed" => Ok(AccountStatus::Failed),
        "disabled" => Ok(AccountStatus::Disabled),
        other => Err(PortError::Other(format!("état de compte inconnu : {other}"))),
    }
}

impl PgStore {
    pub async fn connect(url: &SecretString, cipher: Option<CookieCipher>) -> PortResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(url.expose_secret())
            .await
            .map_err(db_err)?;
        Ok(Self {
            pool,
            cipher: cipher.map(Arc::new),
        })
    }

    /// Applique les migrations embarquées (verrou consultatif : sûr en parallèle).
    pub async fn migrate(&self) -> PortResult<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| PortError::Other(format!("migrations : {e}")))
    }

    /// Crée ou réactive un compte (usage : seed de dev et tests ; en production, l'UI d'admin).
    pub async fn seed_account(&self, app_id: &str, user_key: &str) -> PortResult<()> {
        sqlx::query(
            "INSERT INTO app_accounts (app_id, user_key, status) VALUES ($1, $2, 'active')
             ON CONFLICT (app_id, user_key) DO UPDATE SET status = 'active', status_reason = NULL, updated_at = now()",
        )
        .bind(app_id)
        .bind(user_key)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    fn cipher(&self) -> PortResult<&CookieCipher> {
        self.cipher
            .as_deref()
            .ok_or_else(|| PortError::Other("chiffrement des sessions applicatives non configuré".into()))
    }

    fn encrypt_jar(&self, session: &AppSession) -> PortResult<Vec<u8>> {
        let pairs: Vec<(&str, &str)> = session
            .cookies
            .iter()
            .map(|c| (c.name.as_str(), c.value.expose_secret()))
            .collect();
        let plain = Zeroizing::new(serde_json::to_vec(&pairs).map_err(|e| PortError::Other(e.to_string()))?);
        Ok(self
            .cipher()?
            .encrypt(&plain, &aad(&session.portal_session_id, &session.app_id)))
    }

    fn decrypt_jar(&self, data: &[u8], portal_session_id: &str, app_id: &str) -> PortResult<Vec<AppCookie>> {
        let plain = self
            .cipher()?
            .decrypt(data, &aad(portal_session_id, app_id))
            .map_err(|_| PortError::Other("jar de cookies indéchiffrable".into()))?;
        let pairs: Vec<(String, String)> = serde_json::from_slice(&plain)
            .map_err(|_| PortError::Other("jar de cookies illisible".into()))?;
        Ok(pairs.into_iter().map(|(n, v)| AppCookie::new(n, v)).collect())
    }
}

#[async_trait]
impl SessionStore for PgStore {
    async fn create_portal_session(&self, s: PortalSession) -> PortResult<()> {
        sqlx::query(
            "INSERT INTO portal_sessions (id_hash, issuer, subject, user_key, display_name, groups, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&s.id)
        .bind(&s.user.issuer)
        .bind(&s.user.subject)
        .bind(&s.user.user_key)
        .bind(&s.user.display_name)
        .bind(&s.user.groups)
        .bind(ts(s.created_at))
        .bind(ts(s.expires_at))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_portal_session(&self, id: &str) -> PortResult<Option<PortalSession>> {
        let row = sqlx::query(
            "SELECT issuer, subject, user_key, display_name, groups, created_at, expires_at
             FROM portal_sessions WHERE id_hash = $1 AND expires_at > now()",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| -> Result<_, sqlx::Error> {
            Ok(PortalSession {
                id: id.to_owned(),
                user: UserIdentity {
                    issuer: r.try_get("issuer")?,
                    subject: r.try_get("subject")?,
                    user_key: r.try_get("user_key")?,
                    display_name: r.try_get("display_name")?,
                    groups: r.try_get("groups")?,
                },
                created_at: r.try_get::<DateTime<Utc>, _>("created_at")?.into(),
                expires_at: r.try_get::<DateTime<Utc>, _>("expires_at")?.into(),
            })
        })
        .transpose()
        .map_err(db_err)
    }

    async fn delete_portal_session(&self, id: &str) -> PortResult<()> {
        sqlx::query("DELETE FROM portal_sessions WHERE id_hash = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn put_app_session(&self, s: AppSession) -> PortResult<()> {
        let jar = self.encrypt_jar(&s)?;
        sqlx::query(
            "INSERT INTO app_sessions (portal_session, app_id, cookies, created_at, last_used_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (portal_session, app_id) DO UPDATE
             SET cookies = EXCLUDED.cookies, created_at = EXCLUDED.created_at,
                 last_used_at = EXCLUDED.last_used_at, expires_at = EXCLUDED.expires_at",
        )
        .bind(&s.portal_session_id)
        .bind(&s.app_id)
        .bind(jar)
        .bind(ts(s.created_at))
        .bind(ts(s.last_used_at))
        .bind(ts(s.expires_at))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_app_session(&self, portal_session_id: &str, app_id: &str) -> PortResult<Option<AppSession>> {
        let row = sqlx::query(
            "SELECT cookies, created_at, last_used_at, expires_at FROM app_sessions
             WHERE portal_session = $1 AND app_id = $2 AND expires_at > now()",
        )
        .bind(portal_session_id)
        .bind(app_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        let Some(r) = row else { return Ok(None) };
        let data: Vec<u8> = r.try_get("cookies").map_err(db_err)?;
        let get_ts = |c: &str| {
            r.try_get::<DateTime<Utc>, _>(c)
                .map(SystemTime::from)
                .map_err(db_err)
        };
        Ok(Some(AppSession {
            portal_session_id: portal_session_id.to_owned(),
            app_id: app_id.to_owned(),
            cookies: self.decrypt_jar(&data, portal_session_id, app_id)?,
            created_at: get_ts("created_at")?,
            last_used_at: get_ts("last_used_at")?,
            expires_at: get_ts("expires_at")?,
        }))
    }

    async fn touch_app_session(
        &self,
        portal_session_id: &str,
        app_id: &str,
        at: SystemTime,
    ) -> PortResult<()> {
        sqlx::query("UPDATE app_sessions SET last_used_at = $3 WHERE portal_session = $1 AND app_id = $2")
            .bind(portal_session_id)
            .bind(app_id)
            .bind(ts(at))
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn delete_app_session(&self, portal_session_id: &str, app_id: &str) -> PortResult<()> {
        sqlx::query("DELETE FROM app_sessions WHERE portal_session = $1 AND app_id = $2")
            .bind(portal_session_id)
            .bind(app_id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn purge_expired(&self, now: SystemTime) -> PortResult<u64> {
        let apps = sqlx::query("DELETE FROM app_sessions WHERE expires_at <= $1")
            .bind(ts(now))
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        let portal = sqlx::query("DELETE FROM portal_sessions WHERE expires_at <= $1")
            .bind(ts(now))
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(apps.rows_affected() + portal.rows_affected())
    }
}

fn account_from_row(r: &sqlx::postgres::PgRow) -> PortResult<AppAccount> {
    let status: String = r.try_get("status").map_err(db_err)?;
    Ok(AppAccount {
        app_id: r.try_get("app_id").map_err(db_err)?,
        user_key: r.try_get("user_key").map_err(db_err)?,
        status: parse_status(&status)?,
        status_reason: r.try_get("status_reason").map_err(db_err)?,
        last_login_at: r
            .try_get::<Option<DateTime<Utc>>, _>("last_login_at")
            .map_err(db_err)?
            .map(SystemTime::from),
    })
}

const ACCOUNT_COLUMNS: &str = "app_id, user_key, status, status_reason, last_login_at";

#[async_trait]
impl AccountRegistry for PgStore {
    async fn get_account(&self, app_id: &str, user_key: &str) -> PortResult<Option<AppAccount>> {
        let row = sqlx::query(&format!(
            "SELECT {ACCOUNT_COLUMNS} FROM app_accounts WHERE app_id = $1 AND user_key = $2"
        ))
        .bind(app_id)
        .bind(user_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.as_ref().map(account_from_row).transpose()
    }

    async fn list_accounts(&self, user_key: &str) -> PortResult<Vec<AppAccount>> {
        let rows = sqlx::query(&format!(
            "SELECT {ACCOUNT_COLUMNS} FROM app_accounts WHERE user_key = $1 ORDER BY app_id"
        ))
        .bind(user_key)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(account_from_row).collect()
    }

    async fn set_status(
        &self,
        app_id: &str,
        user_key: &str,
        status: AccountStatus,
        reason: Option<&str>,
    ) -> PortResult<()> {
        let done = sqlx::query(
            "UPDATE app_accounts SET status = $3, status_reason = $4, updated_at = now()
             WHERE app_id = $1 AND user_key = $2",
        )
        .bind(app_id)
        .bind(user_key)
        .bind(status_str(status))
        .bind(reason)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        if done.rows_affected() == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }

    async fn record_login(&self, app_id: &str, user_key: &str, at: SystemTime) -> PortResult<()> {
        sqlx::query("UPDATE app_accounts SET last_login_at = $3 WHERE app_id = $1 AND user_key = $2")
            .bind(app_id)
            .bind(user_key)
            .bind(ts(at))
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }
}
