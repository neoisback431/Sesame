# SPDX-License-Identifier: Apache-2.0
"""Implémentations en mémoire, pour les tests et le dev local."""

from __future__ import annotations

import copy
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from .ports import Account, Conflict, DescriptorRevision, NotFound, Status, StoredDescriptor


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


def _host(document: dict[str, Any]) -> Any:
    return document.get("spec", {}).get("public", {}).get("host")


class MemoryDescriptorStore:
    def __init__(self) -> None:
        self.descriptors: dict[str, StoredDescriptor] = {}
        self.log: list[DescriptorRevision] = []

    def _put(self, app_id: str, document: dict[str, Any], by: str, revision: int, action: str) -> int:
        host = _host(document)
        if host is not None and any(
            _host(d.document) == host for d in self.descriptors.values() if d.app_id != app_id
        ):
            raise Conflict("hôte public déjà utilisé")
        doc = copy.deepcopy(document)
        doc.setdefault("metadata", {})["revision"] = revision
        now = datetime.now(UTC)
        self.descriptors[app_id] = StoredDescriptor(app_id, revision, doc, now, by)
        self.log.append(
            DescriptorRevision(len(self.log) + 1, app_id, revision, action, copy.deepcopy(doc), now, by)  # type: ignore[arg-type]
        )
        return revision

    async def list_descriptors(self) -> list[StoredDescriptor]:
        return [copy.deepcopy(self.descriptors[k]) for k in sorted(self.descriptors)]

    async def get_descriptor(self, app_id: str) -> StoredDescriptor | None:
        return copy.deepcopy(self.descriptors.get(app_id))

    async def create_descriptor(self, app_id: str, document: dict[str, Any], by: str) -> int:
        if app_id in self.descriptors:
            raise Conflict("identifiant déjà utilisé")
        return self._put(app_id, document, by, 1, "created")

    async def update_descriptor(
        self, app_id: str, document: dict[str, Any], by: str, expected_revision: int
    ) -> int:
        current = self.descriptors.get(app_id)
        if current is None:
            raise NotFound(app_id)
        if current.revision != expected_revision:
            raise Conflict("révision modifiée entre-temps")
        return self._put(app_id, document, by, current.revision + 1, "updated")

    async def delete_descriptor(self, app_id: str, by: str, expected_revision: int) -> None:
        current = self.descriptors.get(app_id)
        if current is None:
            raise NotFound(app_id)
        if current.revision != expected_revision:
            raise Conflict("révision modifiée entre-temps")
        del self.descriptors[app_id]
        self.log.append(
            DescriptorRevision(
                len(self.log) + 1, app_id, current.revision, "deleted", None, datetime.now(UTC), by
            )
        )

    async def history(self, app_id: str) -> list[DescriptorRevision]:
        return [copy.deepcopy(r) for r in reversed(self.log) if r.app_id == app_id]
