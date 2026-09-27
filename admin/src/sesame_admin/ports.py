# SPDX-License-Identifier: Apache-2.0
"""Interfaces des briques externes utilisées par l'UI d'administration.

Aucun type propre à un fournisseur : les implémentations (OpenBao / Vault,
PostgreSQL, mémoire) sont choisies par configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol

Status = Literal["active", "failed", "disabled"]


class Unavailable(RuntimeError):
    """Brique externe injoignable ou refusant l'opération. Message sans secret."""


class NotFound(LookupError):
    pass


class Conflict(RuntimeError):
    """Écriture concurrente : la révision attendue n'est plus la révision courante."""


@dataclass(frozen=True)
class Account:
    app_id: str
    user_key: str
    status: Status
    status_reason: str | None
    last_login_at: datetime | None
    updated_at: datetime | None


@dataclass(frozen=True)
class StoredDescriptor:
    """Descripteur en base : document JSON conforme au schéma, sans aucun secret."""

    app_id: str
    revision: int
    document: dict[str, Any]
    updated_at: datetime | None
    updated_by: str | None


@dataclass(frozen=True)
class DescriptorRevision:
    """Entrée de l'historique (ajout seul) ; ``document`` est absent pour une suppression."""

    id: int
    app_id: str
    revision: int
    action: Literal["created", "updated", "deleted"]
    document: dict[str, Any] | None
    changed_at: datetime | None
    changed_by: str | None


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

    async def list_user_accounts(self, user_key: str) -> list[Account]:
        """Tous les comptes d'un utilisateur, toutes applis confondues."""
        ...

    async def revoke_app_sessions(self, app_id: str, user_key: str) -> int:
        """Supprime les sessions applicatives ouvertes de l'utilisateur sur l'appli.

        Sans cela, un compte désactivé resterait utilisable jusqu'à l'expiration de sa
        session en cours. Renvoie le nombre de sessions supprimées.
        """
        ...

    async def search_users(self, query: str, limit: int) -> list[tuple[str, dict[str, int]]]:
        """Utilisateurs dont la clé contient ``query`` (casse ignorée), avec leurs comptes par état."""
        ...

    async def known_users(self, limit: int) -> list[str]:
        """Clés utilisateur connues, pour suggérer une valeur exacte au provisionnement :
        titulaires d'un compte et personnes déjà connectées au portail. Triées."""
        ...


class DescriptorStore(Protocol):
    """Descripteurs d'applis en base (table ``app_descriptors`` et son historique).

    Écriture à contrôle de concurrence optimiste : chaque écriture indique la
    révision qu'elle remplace et échoue (``Conflict``) si elle a changé entre-temps.
    ``metadata.revision`` du document stocké est tenu égal à la révision en base.
    """

    async def list_descriptors(self) -> list[StoredDescriptor]: ...

    async def get_descriptor(self, app_id: str) -> StoredDescriptor | None: ...

    async def create_descriptor(self, app_id: str, document: dict[str, Any], by: str) -> int:
        """Crée le descripteur (révision 1). ``Conflict`` s'il existe déjà ou si l'hôte public est pris."""
        ...

    async def update_descriptor(
        self, app_id: str, document: dict[str, Any], by: str, expected_revision: int
    ) -> int:
        """Remplace le document et renvoie la nouvelle révision. ``NotFound`` / ``Conflict``."""
        ...

    async def delete_descriptor(self, app_id: str, by: str, expected_revision: int) -> None: ...

    async def history(self, app_id: str) -> list[DescriptorRevision]:
        """Historique de l'appli, du plus récent au plus ancien."""
        ...
