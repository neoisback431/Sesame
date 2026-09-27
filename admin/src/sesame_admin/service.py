# SPDX-License-Identifier: Apache-2.0
"""Opérations d'administration : identifiants applicatifs et registre des comptes.

Chaque opération est auditée, en succès comme en échec. Les valeurs des
identifiants ne sont jamais journalisées, auditées ni renvoyées.
"""

from __future__ import annotations

import logging

from .audit import AuditEvent, AuditSink
from .descriptors import App
from .identity import AdminUser, valid_user_key
from .ports import AccountStore, NotFound, SecretWriter, Unavailable

log = logging.getLogger(__name__)

MAX_VALUE_LEN = 4096


class InvalidInput(ValueError):
    """Saisie refusée ; le message est affichable (jamais de valeur saisie)."""


class AdminService:
    def __init__(self, apps: dict[str, App], secrets: SecretWriter, accounts: AccountStore, audit: AuditSink):
        self.apps = apps
        self.secrets = secrets
        self.accounts = accounts
        self.audit = audit

    def app(self, app_id: str) -> App:
        try:
            return self.apps[app_id]
        except KeyError:
            raise NotFound(app_id) from None

    async def provision(
        self, actor: AdminUser, app_id: str, user_key: str, fields: dict[str, str], cid: str
    ) -> None:
        """Écrit les identifiants dans le coffre puis active le compte dans le registre."""
        app = self.app(app_id)
        user_key = user_key.strip()
        if not valid_user_key(user_key):
            raise InvalidInput(
                "Identifiant utilisateur invalide (caractères autorisés : A-Z a-z 0-9 @ . _ - +)."
            )
        if set(fields) != set(app.credential_keys):
            raise InvalidInput("Champs attendus : " + ", ".join(app.credential_keys) + ".")
        for key, value in fields.items():
            if not value or len(value) > MAX_VALUE_LEN or "\x00" in value:
                raise InvalidInput(f"Valeur invalide pour « {key} ».")

        def event(action: str, outcome: str, reason: str | None = None) -> AuditEvent:
            return AuditEvent.of(
                action, outcome, actor, app_id=app_id, target_user=user_key, correlation_id=cid, reason=reason
            )

        try:
            await self.secrets.write_credential(app_id, user_key, fields)
        except Unavailable:
            await self.audit.record(event("credential_written", "failure", "secret_store_unavailable"))
            raise
        await self.audit.record(event("credential_written", "success"))
        try:
            await self.accounts.upsert_active(app_id, user_key)
        except Exception:
            await self.audit.record(event("account_status_changed", "failure", "registry_unavailable"))
            raise
        await self.audit.record(event("account_status_changed", "success", "active:provisioned"))
        log.info(
            "compte provisionné", extra={"app_id": app_id, "target_user": user_key, "correlation_id": cid}
        )

    async def set_status(self, actor: AdminUser, app_id: str, user_key: str, status: str, cid: str) -> None:
        """Active ou désactive un compte existant (``failed`` est réservé au proxy)."""
        self.app(app_id)
        if status not in ("active", "disabled"):
            raise InvalidInput("État demandé invalide.")
        reason = None if status == "active" else "disabled_by_admin"
        event = AuditEvent.of(
            "account_status_changed",
            "success",
            actor,
            app_id=app_id,
            target_user=user_key,
            correlation_id=cid,
            reason=f"{status}:admin",
        )
        try:
            await self.accounts.set_status(app_id, user_key, status, reason)  # type: ignore[arg-type]
        except NotFound:
            event.outcome, event.reason = "failure", "no_account"
            await self.audit.record(event)
            raise
        if status == "disabled":
            await self.accounts.revoke_app_sessions(app_id, user_key)
        await self.audit.record(event)

    async def delete(self, actor: AdminUser, app_id: str, user_key: str, cid: str) -> None:
        """Supprime les identifiants du coffre puis l'entrée du registre."""
        self.app(app_id)

        def event(action: str, outcome: str, reason: str | None = None) -> AuditEvent:
            return AuditEvent.of(
                action, outcome, actor, app_id=app_id, target_user=user_key, correlation_id=cid, reason=reason
            )

        try:
            await self.secrets.delete_credential(app_id, user_key)
        except Unavailable:
            await self.audit.record(event("credential_deleted", "failure", "secret_store_unavailable"))
            raise
        await self.audit.record(event("credential_deleted", "success"))
        try:
            await self.accounts.delete_account(app_id, user_key)
        except NotFound:
            pass
        await self.accounts.revoke_app_sessions(app_id, user_key)
        await self.audit.record(event("account_status_changed", "success", "deleted:admin"))

    async def disable_all(self, actor: AdminUser, user_key: str, cid: str) -> int:
        """Désactive tous les comptes actifs ou en échec d'un utilisateur (départ, suspension).

        Couvre aussi les comptes d'applis dont le descripteur a été retiré.
        Renvoie le nombre de comptes désactivés ; chacun est audité.
        """
        count = 0
        for account in await self.accounts.list_user_accounts(user_key):
            if account.status == "disabled":
                continue
            await self.accounts.set_status(account.app_id, user_key, "disabled", "disabled_by_admin")
            await self.accounts.revoke_app_sessions(account.app_id, user_key)
            await self.audit.record(
                AuditEvent.of(
                    "account_status_changed",
                    "success",
                    actor,
                    app_id=account.app_id,
                    target_user=user_key,
                    correlation_id=cid,
                    reason="disabled:admin_bulk",
                )
            )
            count += 1
        return count
