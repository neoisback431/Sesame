# SPDX-License-Identifier: Apache-2.0
"""Interfaces des briques externes utilisées par l'UI d'administration.

Aucun type propre à un fournisseur : les implémentations (OpenBao / Vault,
PostgreSQL, mémoire) sont choisies par configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

Status = Literal["active", "failed", "disabled"]


class Unavailable(RuntimeError):
    """Brique externe injoignable ou refusant l'opération. Message sans secret."""


class NotFound(LookupError):
    pass


@dataclass(frozen=True)
class Account:
    app_id: str
    user_key: str
    status: Status
    status_reason: str | None
    last_login_at: datetime | None
    updated_at: datetime | None


class SecretWriter(Protocol):
    """Coffre en écriture seule : l'UI d'admin ne relit jamais un secret."""

    async def write_credential(self, app_id: str, user_key: str, fields: dict[str, str]) -> None: ...

    async def delete_credential(self, app_id: str, user_key: str) -> None: ...


class AccountStore(Protocol):
    """Registre des comptes, côté administration."""

    async def list_accounts(self, app_id: str) -> list[Account]: ...

    async def get_account(self, app_id: str, user_key: str) -> Account | None: ...

    async def upsert_active(self, app_id: str, user_key: str) -> None: ...

    async def set_status(self, app_id: str, user_key: str, status: Status, reason: str | None) -> None: ...

    async def delete_account(self, app_id: str, user_key: str) -> None: ...

    async def count_by_app(self) -> dict[str, dict[str, int]]: ...
