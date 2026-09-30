# SPDX-License-Identifier: Apache-2.0
"""Registre des comptes et descripteurs d'applis sur PostgreSQL (asyncpg).

Le schéma appartient aux migrations Rust (``crates/sesame-store-postgres/migrations``).
"""

from __future__ import annotations

import json
from typing import Any

import asyncpg

from .crypto import SecretCipher, field_aad
from .identity import valid_user_key
from .ports import (
    AccessRequest,
    Account,
    Conflict,
    DescriptorRevision,
    Diagnostic,
    NotFound,
    Notification,
    NotificationSettings,
    Status,
    StoredDescriptor,
    Unavailable,
)

_COLUMNS = "app_id, user_key, status, status_reason, last_login_at, updated_at"


def _segment_ok(s: str) -> bool:
    return bool(s) and s not in {".", ".."} and "/" not in s


def _account(r: asyncpg.Record) -> Account:
    return Account(
        r["app_id"], r["user_key"], r["status"], r["status_reason"], r["last_login_at"], r["updated_at"]
    )


class PgPool:
    """Pool de connexions partagé par les magasins, ouvert à la première requête."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    def __repr__(self) -> str:  # la chaîne de connexion contient un mot de passe
        return "PgPool()"

    async def get(self) -> asyncpg.Pool:
        if self._pool is None:
            try:
                self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=5, timeout=5)
            except (OSError, asyncpg.PostgresError) as e:
                raise Unavailable(f"base de données injoignable ({type(e).__name__})") from None
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None


class PostgresAccountStore:
    def __init__(self, db: str | PgPool) -> None:
        self._db = db if isinstance(db, PgPool) else PgPool(db)

    def __repr__(self) -> str:
        return "PostgresAccountStore()"

    async def pool(self) -> asyncpg.Pool:
        return await self._db.get()

    async def close(self) -> None:
        await self._db.close()

    async def list_accounts(self, app_id: str) -> list[Account]:
        rows = await (await self.pool()).fetch(
            f"SELECT {_COLUMNS} FROM app_accounts WHERE app_id = $1 ORDER BY user_key",  # noqa: S608 (colonnes constantes)
            app_id,
        )
        return [_account(r) for r in rows]

    async def get_account(self, app_id: str, user_key: str) -> Account | None:
        r = await (await self.pool()).fetchrow(
            f"SELECT {_COLUMNS} FROM app_accounts WHERE app_id = $1 AND user_key = $2",  # noqa: S608 (colonnes constantes)
            app_id,
            user_key,
        )
        return _account(r) if r else None

    async def upsert_active(self, app_id: str, user_key: str) -> None:
        await (await self.pool()).execute(
            """INSERT INTO app_accounts (app_id, user_key, status) VALUES ($1, $2, 'active')
               ON CONFLICT (app_id, user_key) DO UPDATE
               SET status = 'active', status_reason = NULL, updated_at = now()""",
            app_id,
            user_key,
        )

    async def set_status(self, app_id: str, user_key: str, status: Status, reason: str | None) -> None:
        done = await (await self.pool()).execute(
            """UPDATE app_accounts SET status = $3, status_reason = $4, updated_at = now()
               WHERE app_id = $1 AND user_key = $2""",
            app_id,
            user_key,
            status,
            reason,
        )
        if done.endswith(" 0"):
            raise NotFound(user_key)

    async def delete_account(self, app_id: str, user_key: str) -> None:
        done = await (await self.pool()).execute(
            "DELETE FROM app_accounts WHERE app_id = $1 AND user_key = $2", app_id, user_key
        )
        if done.endswith(" 0"):
            raise NotFound(user_key)

    async def count_by_app(self) -> dict[str, dict[str, int]]:
        rows = await (await self.pool()).fetch(
            "SELECT app_id, status, count(*) AS n FROM app_accounts GROUP BY app_id, status"
        )
        out: dict[str, dict[str, int]] = {}
        for r in rows:
            out.setdefault(r["app_id"], {})[r["status"]] = r["n"]
        return out

    async def known_users(self, limit: int) -> list[str]:
        # Titulaires d'un compte + personnes déjà connectées au portail (même base).
        rows = await (await self.pool()).fetch(
            """SELECT user_key FROM app_accounts
               UNION SELECT user_key FROM portal_sessions
               ORDER BY user_key LIMIT $1""",
            limit,
        )
        return [r["user_key"] for r in rows]

    async def get_diagnostic(self, app_id: str, user_key: str) -> Diagnostic | None:
        row = await (await self.pool()).fetchrow(
            "SELECT document FROM replay_diagnostics WHERE app_id = $1 AND user_key = $2",
            app_id,
            user_key,
        )
        return Diagnostic.from_document(json.loads(row["document"])) if row else None

    async def list_user_accounts(self, user_key: str) -> list[Account]:
        rows = await (await self.pool()).fetch(
            f"SELECT {_COLUMNS} FROM app_accounts WHERE user_key = $1 ORDER BY app_id",  # noqa: S608 (colonnes constantes)
            user_key,
        )
        return [_account(r) for r in rows]

    async def search_users(self, query: str, limit: int) -> list[tuple[str, dict[str, int]]]:
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = await (await self.pool()).fetch(
            """SELECT user_key, status, count(*) AS n FROM app_accounts
               WHERE user_key IN (
                 SELECT DISTINCT user_key FROM app_accounts
                 WHERE user_key ILIKE $1 ESCAPE '\\' ORDER BY user_key LIMIT $2)
               GROUP BY user_key, status ORDER BY user_key""",
            pattern,
            limit,
        )
        out: dict[str, dict[str, int]] = {}
        for r in rows:
            out.setdefault(r["user_key"], {})[r["status"]] = r["n"]
        return list(out.items())

    async def revoke_app_sessions(self, app_id: str, user_key: str) -> int:
        done = await (await self.pool()).execute(
            """DELETE FROM app_sessions WHERE app_id = $1 AND portal_session IN
               (SELECT id_hash FROM portal_sessions WHERE user_key = $2)""",
            app_id,
            user_key,
        )
        return int(done.rsplit(" ", 1)[-1])


def _stored(r: asyncpg.Record) -> StoredDescriptor:
    return StoredDescriptor(
        r["app_id"], r["revision"], json.loads(r["document"]), r["updated_at"], r["updated_by"]
    )


def _conflict(e: asyncpg.UniqueViolationError) -> Conflict:
    if "public_host" in (e.constraint_name or ""):
        return Conflict("hôte public déjà utilisé")
    return Conflict("identifiant déjà utilisé")


class PostgresNotificationStore:
    """Réglages et boîte d'envoi des notifications (ADR 0030)."""

    def __init__(self, db: str | PgPool) -> None:
        self._db = db if isinstance(db, PgPool) else PgPool(db)

    def __repr__(self) -> str:
        return "PostgresNotificationStore()"

    async def pool(self) -> asyncpg.Pool:
        return await self._db.get()

    async def close(self) -> None:
        await self._db.close()

    async def get_settings(self) -> NotificationSettings:
        r = await (await self.pool()).fetchrow("SELECT * FROM notification_settings WHERE id = 1")
        if r is None:
            return NotificationSettings()
        return NotificationSettings(
            enabled=r["enabled"],
            smtp_host=r["smtp_host"],
            smtp_port=r["smtp_port"],
            smtp_security=r["smtp_security"],
            smtp_user=r["smtp_user"],
            from_address=r["from_address"],
            recipients=tuple(r["recipients"]),
            events=tuple(r["events"]),
            updated_at=r["updated_at"],
            updated_by=r["updated_by"],
        )

    async def save_settings(self, s: NotificationSettings, by: str) -> None:
        await (await self.pool()).execute(
            """INSERT INTO notification_settings
                 (id, enabled, smtp_host, smtp_port, smtp_security, smtp_user, from_address,
                  recipients, events, updated_at, updated_by)
               VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, now(), $9)
               ON CONFLICT (id) DO UPDATE SET enabled = $1, smtp_host = $2, smtp_port = $3,
                 smtp_security = $4, smtp_user = $5, from_address = $6, recipients = $7,
                 events = $8, updated_at = now(), updated_by = $9""",
            s.enabled,
            s.smtp_host,
            s.smtp_port,
            s.smtp_security,
            s.smtp_user,
            s.from_address,
            list(s.recipients),
            list(s.events),
            by,
        )

    async def enqueue(
        self, event: str, app_id: str | None, user_key: str | None, reason: str | None, actor: str | None
    ) -> None:
        await (await self.pool()).execute(
            "INSERT INTO notifications (event, app_id, user_key, reason, actor) VALUES ($1, $2, $3, $4, $5)",
            event,
            app_id,
            user_key,
            reason,
            actor,
        )

    @staticmethod
    def _notification(r: asyncpg.Record) -> Notification:
        return Notification(
            r["id"],
            r["event"],
            r["app_id"],
            r["user_key"],
            r["reason"],
            r["actor"],
            r["status"],
            r["attempts"],
            r["last_error"],
            r["created_at"],
            r["sent_at"],
        )

    async def claim_pending(self, limit: int) -> list[Notification]:
        rows = await (await self.pool()).fetch(
            """UPDATE notifications SET next_attempt_at = now() + interval '5 minutes'
               WHERE id IN (SELECT id FROM notifications
                            WHERE status = 'pending' AND next_attempt_at <= now()
                            ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED)
               RETURNING *""",
            limit,
        )
        return sorted((self._notification(r) for r in rows), key=lambda n: n.id)

    async def mark(self, notification_id: int, status: str, error: str | None) -> None:
        pool = await self.pool()
        if status == "retry":
            await pool.execute(
                """UPDATE notifications SET attempts = attempts + 1, last_error = $2,
                       next_attempt_at = now() + make_interval(mins => power(2, attempts)::int)
                   WHERE id = $1""",
                notification_id,
                error,
            )
        else:
            await pool.execute(
                """UPDATE notifications SET status = $2, last_error = $3,
                       attempts = attempts + CASE WHEN $2 = 'failed' THEN 1 ELSE 0 END,
                       sent_at = CASE WHEN $2 = 'sent' THEN now() ELSE sent_at END
                   WHERE id = $1""",
                notification_id,
                status,
                error,
            )

    async def recent(self, limit: int) -> list[Notification]:
        rows = await (await self.pool()).fetch("SELECT * FROM notifications ORDER BY id DESC LIMIT $1", limit)
        return [self._notification(r) for r in rows]

    async def purge(self, older_than_days: int) -> int:
        done = await (await self.pool()).execute(
            """DELETE FROM notifications
               WHERE status <> 'pending' AND created_at < now() - make_interval(days => $1)""",
            older_than_days,
        )
        return int(done.rsplit(" ", 1)[-1])


class PostgresAccessRequestStore:
    """Demandes d'accès : lecture et clôture seulement, le dépôt vient du portail et du proxy."""

    def __init__(self, db: str | PgPool) -> None:
        self._db = db if isinstance(db, PgPool) else PgPool(db)

    def __repr__(self) -> str:
        return "PostgresAccessRequestStore()"

    async def pool(self) -> asyncpg.Pool:
        return await self._db.get()

    async def close(self) -> None:
        await self._db.close()

    @staticmethod
    def _request(r: asyncpg.Record) -> AccessRequest:
        return AccessRequest(r["app_id"], r["user_key"], r["kind"], r["note"], r["created_at"])

    async def list_open(self) -> list[AccessRequest]:
        rows = await (await self.pool()).fetch(
            """SELECT app_id, user_key, kind, note, created_at FROM access_requests
               WHERE status = 'open' ORDER BY created_at"""
        )
        return [self._request(r) for r in rows]

    async def get_open(self, app_id: str, user_key: str) -> AccessRequest | None:
        r = await (await self.pool()).fetchrow(
            """SELECT app_id, user_key, kind, note, created_at FROM access_requests
               WHERE app_id = $1 AND user_key = $2 AND status = 'open'""",
            app_id,
            user_key,
        )
        return self._request(r) if r else None

    async def count_open(self) -> int:
        return int(
            await (await self.pool()).fetchval("SELECT count(*) FROM access_requests WHERE status = 'open'")
        )

    async def resolve(self, app_id: str, user_key: str, status: str, by: str) -> bool:
        done = await (await self.pool()).execute(
            """UPDATE access_requests SET status = $3, resolved_at = now(), resolved_by = $4
               WHERE app_id = $1 AND user_key = $2 AND status = 'open'""",
            app_id,
            user_key,
            status,
            by,
        )
        return not done.endswith(" 0")


class PostgresDescriptorStore:
    """Descripteurs en base ; chaque écriture et sa ligne d'historique forment une transaction."""

    def __init__(self, db: str | PgPool) -> None:
        self._db = db if isinstance(db, PgPool) else PgPool(db)

    def __repr__(self) -> str:
        return "PostgresDescriptorStore()"

    async def pool(self) -> asyncpg.Pool:
        return await self._db.get()

    async def close(self) -> None:
        await self._db.close()

    async def list_descriptors(self) -> list[StoredDescriptor]:
        rows = await (await self.pool()).fetch(
            "SELECT app_id, revision, document::text AS document, updated_at, updated_by"
            " FROM app_descriptors ORDER BY app_id"
        )
        return [_stored(r) for r in rows]

    async def get_descriptor(self, app_id: str) -> StoredDescriptor | None:
        r = await (await self.pool()).fetchrow(
            "SELECT app_id, revision, document::text AS document, updated_at, updated_by"
            " FROM app_descriptors WHERE app_id = $1",
            app_id,
        )
        return _stored(r) if r else None

    @staticmethod
    async def _log(conn: Any, app_id: str, revision: int, action: str, document: str | None, by: str) -> None:
        await conn.execute(
            """INSERT INTO app_descriptor_history (app_id, revision, action, document, changed_by)
               VALUES ($1, $2, $3, $4::jsonb, $5)""",
            app_id,
            revision,
            action,
            document,
            by,
        )

    async def create_descriptor(self, app_id: str, document: dict[str, Any], by: str) -> int:
        async with (await self.pool()).acquire() as conn, conn.transaction():
            try:
                doc = await conn.fetchval(
                    """INSERT INTO app_descriptors (app_id, revision, document, updated_by)
                       VALUES ($1, 1, jsonb_set($2::jsonb, '{metadata,revision}', '1'), $3)
                       RETURNING document::text""",
                    app_id,
                    json.dumps(document),
                    by,
                )
            except asyncpg.UniqueViolationError as e:
                raise _conflict(e) from None
            await self._log(conn, app_id, 1, "created", doc, by)
        return 1

    async def update_descriptor(
        self, app_id: str, document: dict[str, Any], by: str, expected_revision: int
    ) -> int:
        async with (await self.pool()).acquire() as conn, conn.transaction():
            try:
                r = await conn.fetchrow(
                    """UPDATE app_descriptors
                       SET revision = revision + 1,
                           document = jsonb_set($2::jsonb, '{metadata,revision}', to_jsonb(revision + 1)),
                           updated_at = now(), updated_by = $3
                       WHERE app_id = $1 AND revision = $4
                       RETURNING revision, document::text AS document""",
                    app_id,
                    json.dumps(document),
                    by,
                    expected_revision,
                )
            except asyncpg.UniqueViolationError as e:
                raise _conflict(e) from None
            if r is None:
                exists = await conn.fetchval("SELECT 1 FROM app_descriptors WHERE app_id = $1", app_id)
                raise Conflict("révision modifiée entre-temps") if exists else NotFound(app_id)
            await self._log(conn, app_id, r["revision"], "updated", r["document"], by)
        return r["revision"]

    async def delete_descriptor(self, app_id: str, by: str, expected_revision: int) -> None:
        async with (await self.pool()).acquire() as conn, conn.transaction():
            revision = await conn.fetchval(
                "DELETE FROM app_descriptors WHERE app_id = $1 AND revision = $2 RETURNING revision",
                app_id,
                expected_revision,
            )
            if revision is None:
                exists = await conn.fetchval("SELECT 1 FROM app_descriptors WHERE app_id = $1", app_id)
                raise Conflict("révision modifiée entre-temps") if exists else NotFound(app_id)
            await self._log(conn, app_id, revision, "deleted", None, by)

    async def history(self, app_id: str) -> list[DescriptorRevision]:
        rows = await (await self.pool()).fetch(
            """SELECT id, app_id, revision, action, document::text AS document, changed_at, changed_by
               FROM app_descriptor_history WHERE app_id = $1 ORDER BY id DESC""",
            app_id,
        )
        return [
            DescriptorRevision(
                r["id"],
                r["app_id"],
                r["revision"],
                r["action"],
                json.loads(r["document"]) if r["document"] is not None else None,
                r["changed_at"],
                r["changed_by"],
            )
            for r in rows
        ]


class PostgresSecretWriter:
    """Coffre de secrets PostgreSQL (ADR 0021), implémentation par défaut : écrit des
    valeurs chiffrées (AES-256-GCM, `crypto.SecretCipher`) dans `app_secrets`. Ne relit
    jamais un secret : ni ici, ni ailleurs dans l'admin (aucune méthode de lecture).

    Séparation lecture / écriture : contrairement à l'AppRole de Vault (garantie par le
    serveur du coffre), elle repose ici sur l'application (aucune API n'expose un
    secret déchiffré) et, en production, sur un rôle PostgreSQL dédié à l'admin sans
    droit `SELECT` sur `app_secrets` (voir ADR 0021 et `docs/configuration.md`).
    """

    def __init__(self, db: str | PgPool, cipher: SecretCipher) -> None:
        self._db = db if isinstance(db, PgPool) else PgPool(db)
        self._cipher = cipher

    def __repr__(self) -> str:
        return "PostgresSecretWriter()"

    async def pool(self) -> asyncpg.Pool:
        return await self._db.get()

    async def close(self) -> None:
        await self._db.close()

    def _check(self, app_id: str, user_key: str) -> None:
        if not _segment_ok(app_id) or not valid_user_key(user_key):
            raise ValueError("identifiant d'appli ou d'utilisateur invalide")

    async def write_credential(self, app_id: str, user_key: str, fields: dict[str, str]) -> None:
        self._check(app_id, user_key)
        pool = await self.pool()
        try:
            async with pool.acquire() as conn, conn.transaction():
                await conn.execute(
                    """DELETE FROM app_secrets
                       WHERE app_id = $1 AND user_key = $2 AND NOT (key = ANY($3::text[]))""",
                    app_id,
                    user_key,
                    list(fields.keys()),
                )
                for key, value in fields.items():
                    ciphertext = self._cipher.encrypt(value, field_aad(app_id, user_key, key))
                    await conn.execute(
                        """INSERT INTO app_secrets (app_id, user_key, key, ciphertext) VALUES ($1, $2, $3, $4)
                           ON CONFLICT (app_id, user_key, key)
                           DO UPDATE SET ciphertext = $4, updated_at = now()""",
                        app_id,
                        user_key,
                        key,
                        ciphertext,
                    )
        except (OSError, asyncpg.PostgresError) as e:
            raise Unavailable(f"coffre injoignable ({type(e).__name__})") from None

    async def delete_credential(self, app_id: str, user_key: str) -> None:
        self._check(app_id, user_key)
        try:
            await (await self.pool()).execute(
                "DELETE FROM app_secrets WHERE app_id = $1 AND user_key = $2", app_id, user_key
            )
        except (OSError, asyncpg.PostgresError) as e:
            raise Unavailable(f"coffre injoignable ({type(e).__name__})") from None
