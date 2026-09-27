# SPDX-License-Identifier: Apache-2.0
"""Implémentations en mémoire, pour les tests et le dev local."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from .ports import Account, NotFound, Status


class MemorySecretWriter:
    def __init__(self) -> None:
        self.entries: dict[tuple[str, str], dict[str, str]] = {}

    async def write_credential(self, app_id: str, user_key: str, fields: dict[str, str]) -> None:
        self.entries[(app_id, user_key)] = dict(fields)

    async def delete_credential(self, app_id: str, user_key: str) -> None:
        self.entries.pop((app_id, user_key), None)


class MemoryAccountStore:
    def __init__(self) -> None:
        self.accounts: dict[tuple[str, str], Account] = {}
        # Sessions applicatives ouvertes simulées : (appli, utilisateur) -> nombre.
        self.app_sessions: dict[tuple[str, str], int] = {}

    async def list_accounts(self, app_id: str) -> list[Account]:
        return sorted((a for a in self.accounts.values() if a.app_id == app_id), key=lambda a: a.user_key)

    async def get_account(self, app_id: str, user_key: str) -> Account | None:
        return self.accounts.get((app_id, user_key))

    async def upsert_active(self, app_id: str, user_key: str) -> None:
        old = self.accounts.get((app_id, user_key))
        self.accounts[(app_id, user_key)] = Account(
            app_id, user_key, "active", None, old.last_login_at if old else None, datetime.now(UTC)
        )

    async def set_status(self, app_id: str, user_key: str, status: Status, reason: str | None) -> None:
        old = self.accounts.get((app_id, user_key))
        if old is None:
            raise NotFound(user_key)
        self.accounts[(app_id, user_key)] = Account(
            app_id, user_key, status, reason, old.last_login_at, datetime.now(UTC)
        )

    async def delete_account(self, app_id: str, user_key: str) -> None:
        if self.accounts.pop((app_id, user_key), None) is None:
            raise NotFound(user_key)

    async def count_by_app(self) -> dict[str, dict[str, int]]:
        counts: dict[str, Counter[str]] = {}
        for a in self.accounts.values():
            counts.setdefault(a.app_id, Counter())[a.status] += 1
        return {k: dict(v) for k, v in counts.items()}

    async def list_user_accounts(self, user_key: str) -> list[Account]:
        return sorted((a for a in self.accounts.values() if a.user_key == user_key), key=lambda a: a.app_id)

    async def search_users(self, query: str, limit: int) -> list[tuple[str, dict[str, int]]]:
        counts: dict[str, Counter[str]] = {}
        for a in self.accounts.values():
            if query.lower() in a.user_key.lower():
                counts.setdefault(a.user_key, Counter())[a.status] += 1
        return [(u, dict(counts[u])) for u in sorted(counts)[:limit]]

    async def revoke_app_sessions(self, app_id: str, user_key: str) -> int:
        return self.app_sessions.pop((app_id, user_key), 0)
