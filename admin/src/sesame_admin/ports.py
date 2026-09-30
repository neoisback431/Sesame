# SPDX-License-Identifier: Apache-2.0
"""Interfaces des briques externes utilisées par l'UI d'administration.

Aucun type propre à un fournisseur : les implémentations (OpenBao / Vault,
PostgreSQL, mémoire) sont choisies par configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

# ``pending`` : identifiants fournis par l'utilisateur, en attente d'activation (ADR 0029).
Status = Literal["active", "failed", "disabled", "pending"]


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


@dataclass(frozen=True)
class Diagnostic:
    """Dernier rejeu en échec d'un compte, écrit par le proxy si ``SESAME_REPLAY_DEBUG``
    (ADR 0018). Valeurs du coffre et des cookies déjà masquées par le proxy."""

    correlation_id: str
    reason: str
    step: str
    method: str
    url: str
    sent_fields: tuple[str, ...]
    status: int | None
    headers: tuple[tuple[str, str], ...]
    body: str
    body_truncated: bool
    at: datetime

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> Diagnostic:
        return cls(
            correlation_id=str(doc.get("correlation_id", "")),
            reason=str(doc.get("reason", "")),
            step=str(doc.get("step", "")),
            method=str(doc.get("method", "")),
            url=str(doc.get("url", "")),
            sent_fields=tuple(str(f) for f in doc.get("sent_fields", [])),
            status=doc.get("status"),
            headers=tuple((str(n), str(v)) for n, v in doc.get("headers", [])),
            body=str(doc.get("body", "")),
            body_truncated=bool(doc.get("body_truncated")),
            at=datetime.fromtimestamp(int(doc.get("at", 0)), UTC),
        )


@dataclass(frozen=True)
class AccessRequest:
    """Demande d'accès ouverte depuis « Mes applications » (ADR 0029). Aucun secret.

    ``credentials`` : l'utilisateur a fourni ses identifiants (compte ``pending``, l'admin n'a
    qu'à activer) ; ``no_account`` : il n'a pas de compte, l'admin doit le créer."""

    app_id: str
    user_key: str
    kind: Literal["credentials", "no_account"]
    note: str | None
    created_at: datetime


NOTIFICATION_EVENTS = ("access_requested", "account_failed", "upstream_unreachable", "admin_sensitive")


@dataclass(frozen=True)
class NotificationSettings:
    """Réglages des notifications par mail (ADR 0030). Le mot de passe SMTP n'en fait pas
    partie : il vit dans l'environnement de l'admin, jamais en base."""

    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: Literal["starttls", "tls", "none"] = "starttls"
    smtp_user: str = ""
    from_address: str = ""
    recipients: tuple[str, ...] = ()
    events: tuple[str, ...] = ("access_requested", "account_failed")
    updated_at: datetime | None = None
    updated_by: str | None = None


@dataclass(frozen=True)
class Notification:
    """Événement de la boîte d'envoi. Codes courts seulement, jamais de secret."""

    id: int
    event: str
    app_id: str | None
    user_key: str | None
    reason: str | None
    actor: str | None
    status: str
    attempts: int
    last_error: str | None
    created_at: datetime
    sent_at: datetime | None = None


class NotificationStore(Protocol):
    """Réglages et boîte d'envoi (tables ``notification_settings`` et ``notifications``)."""

    async def get_settings(self) -> NotificationSettings: ...

    async def save_settings(self, settings: NotificationSettings, by: str) -> None: ...

    async def enqueue(
        self, event: str, app_id: str | None, user_key: str | None, reason: str | None, actor: str | None
    ) -> None:
        """Dépose un événement (côté admin : ``admin_sensitive``). Le portail et le proxy
        déposent les leurs directement."""
        ...

    async def claim_pending(self, limit: int) -> list[Notification]:
        """Événements à expédier, avec un bail de quelques minutes (une réplique de l'admin
        ne reprend pas ce qu'une autre est en train d'envoyer)."""
        ...

    async def mark(self, notification_id: int, status: str, error: str | None) -> None:
        """``sent`` / ``skipped`` / ``failed`` ; ``retry`` remet en file avec une attente
        croissante (les tentatives sont comptées)."""
        ...

    async def recent(self, limit: int) -> list[Notification]: ...

    async def purge(self, older_than_days: int) -> int: ...


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

    async def get_diagnostic(self, app_id: str, user_key: str) -> Diagnostic | None:
        """Diagnostic du dernier rejeu en échec (écrit par le proxy), s'il existe."""
        ...


class AccessRequestStore(Protocol):
    """Demandes d'accès (table ``access_requests``, écrite par le portail et le proxy)."""

    async def list_open(self) -> list[AccessRequest]:
        """Demandes ouvertes, de la plus ancienne à la plus récente."""
        ...

    async def get_open(self, app_id: str, user_key: str) -> AccessRequest | None: ...

    async def count_open(self) -> int: ...

    async def resolve(
        self, app_id: str, user_key: str, status: Literal["approved", "rejected", "fulfilled"], by: str
    ) -> bool:
        """Clôt la demande ouverte du couple ; ``False`` s'il n'y en avait pas."""
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
