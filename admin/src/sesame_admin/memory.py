# SPDX-License-Identifier: Apache-2.0
"""Implémentations en mémoire, pour les tests et le dev local."""

from __future__ import annotations

import copy
from collections import Counter
from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

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
    UserProfile,
)


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
        # Personnes déjà connectées au portail (simulées dans les tests).
        self.portal_users: set[str] = set()
        # Profils (écrits par le portail en production) : clé utilisateur -> nom, e-mail.
        self.profiles: dict[str, UserProfile] = {}
        # Diagnostics de rejeu (écrits par le proxy en production) : documents JSON.
        self.diagnostics: dict[tuple[str, str], dict[str, Any]] = {}

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
        self.diagnostics.pop((app_id, user_key), None)  # ON DELETE CASCADE en base

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
            p = self.profiles.get(a.user_key)
            haystack = " ".join(
                [a.user_key, *(x for x in (p.display_name, p.email) if x)] if p else [a.user_key]
            )
            if query.lower() in haystack.lower():
                counts.setdefault(a.user_key, Counter())[a.status] += 1
        return [(u, dict(counts[u])) for u in sorted(counts)[:limit]]

    async def user_profiles(self, user_keys: Iterable[str]) -> dict[str, UserProfile]:
        return {k: self.profiles[k] for k in user_keys if k in self.profiles}

    async def known_users(self, limit: int) -> list[str]:
        keys = {u for _, u in self.accounts} | self.portal_users
        return sorted(keys)[:limit]

    async def revoke_app_sessions(self, app_id: str, user_key: str) -> int:
        return self.app_sessions.pop((app_id, user_key), 0)

    async def get_diagnostic(self, app_id: str, user_key: str) -> Diagnostic | None:
        doc = self.diagnostics.get((app_id, user_key))
        return Diagnostic.from_document(doc) if doc is not None else None


class MemoryNotificationStore:
    def __init__(self) -> None:
        self.settings = NotificationSettings()
        self.items: list[Notification] = []
        self._next_id = 1

    async def get_settings(self) -> NotificationSettings:
        return self.settings

    async def save_settings(self, settings: NotificationSettings, by: str) -> None:
        self.settings = replace(settings, updated_at=datetime.now(UTC), updated_by=by)

    async def enqueue(self, event, app_id, user_key, reason, actor) -> None:  # type: ignore[no-untyped-def]
        self.deposit(event, app_id, user_key, reason, actor)

    def deposit(self, event, app_id=None, user_key=None, reason=None, actor=None) -> None:  # type: ignore[no-untyped-def]
        """Simule un dépôt du portail / du proxy."""
        self.items.append(
            Notification(
                self._next_id, event, app_id, user_key, reason, actor, "pending", 0, None, datetime.now(UTC)
            )
        )
        self._next_id += 1

    async def claim_pending(self, limit: int) -> list[Notification]:
        return [n for n in self.items if n.status == "pending"][:limit]

    async def mark(self, notification_id: int, status: str, error: str | None) -> None:
        for i, n in enumerate(self.items):
            if n.id == notification_id:
                attempts = n.attempts + (1 if status in ("retry", "failed") else 0)
                new = "pending" if status == "retry" else status
                sent_at = datetime.now(UTC) if status == "sent" else n.sent_at
                self.items[i] = replace(n, status=new, attempts=attempts, last_error=error, sent_at=sent_at)

    async def recent(self, limit: int) -> list[Notification]:
        return list(reversed(self.items))[:limit]

    async def purge(self, older_than_days: int) -> int:
        return 0


class MemoryAccessRequestStore:
    def __init__(self) -> None:
        self.requests: dict[tuple[str, str], AccessRequest] = {}
        self.resolved: dict[tuple[str, str], str] = {}

    def submit(self, app_id: str, user_key: str, kind: str, note: str | None = None) -> None:
        """Simule le dépôt d'une demande (fait par le portail / le proxy en production)."""
        self.requests[(app_id, user_key)] = AccessRequest(
            app_id,
            user_key,
            kind,
            note,
            datetime.now(UTC),  # type: ignore[arg-type]
        )
        self.resolved.pop((app_id, user_key), None)

    async def list_open(self) -> list[AccessRequest]:
        return sorted(self.requests.values(), key=lambda r: r.created_at)

    async def get_open(self, app_id: str, user_key: str) -> AccessRequest | None:
        return self.requests.get((app_id, user_key))

    async def count_open(self) -> int:
        return len(self.requests)

    async def resolve(self, app_id: str, user_key: str, status: str, by: str) -> bool:
        if self.requests.pop((app_id, user_key), None) is None:
            return False
        self.resolved[(app_id, user_key)] = status
        return True


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
