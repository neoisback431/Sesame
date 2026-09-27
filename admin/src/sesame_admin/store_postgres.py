# SPDX-License-Identifier: Apache-2.0
"""Registre des comptes sur PostgreSQL (asyncpg).

Le schéma appartient aux migrations Rust (``crates/sesame-store-postgres/migrations``).
"""

from __future__ import annotations

import asyncpg

from .ports import Account, NotFound, Status, Unavailable

_COLUMNS = "app_id, user_key, status, status_reason, last_login_at, updated_at"


def _account(r: asyncpg.Record) -> Account:
    return Account(
        r["app_id"], r["user_key"], r["status"], r["status_reason"], r["last_login_at"], r["updated_at"]
    )


class PostgresAccountStore:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    def __repr__(self) -> str:  # la chaîne de connexion contient un mot de passe
        return "PostgresAccountStore()"

    async def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            try:
                self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=5, timeout=5)
            except (OSError, asyncpg.PostgresError) as e:
                raise Unavailable(f"base de données injoignable ({type(e).__name__})") from None
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()

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
