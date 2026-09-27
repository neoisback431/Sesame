# SPDX-License-Identifier: Apache-2.0
"""Opérations d'administration : applis (descripteurs en base), identifiants
applicatifs et registre des comptes.

Chaque opération est auditée, en succès comme en échec. Les valeurs des
identifiants ne sont jamais journalisées, auditées ni renvoyées.
"""

from __future__ import annotations

import logging
from typing import Any

from .audit import AuditEvent, AuditSink
from .descriptors import (
    App,
    Catalog,
    DescriptorError,
    DescriptorValidator,
    merge,
    parse_yaml,
)
from .identity import AdminUser, valid_user_key
from .ports import (
    AccountStore,
    Conflict,
    DescriptorStore,
    NotFound,
    SecretWriter,
    StoredDescriptor,
    Unavailable,
)

log = logging.getLogger(__name__)

MAX_VALUE_LEN = 4096


class InvalidInput(ValueError):
    """Saisie refusée ; le message est affichable (jamais de valeur saisie)."""


class InvalidDescriptor(InvalidInput):
    """Descripteur refusé ; ``errors`` est affichable (un descripteur ne contient aucun secret)."""

    def __init__(self, errors: list[str]):
        super().__init__("Descripteur invalide.")
        self.errors = errors


class AdminService:
    def __init__(
        self,
        files: dict[str, App],
        secrets: SecretWriter,
        accounts: AccountStore,
        audit: AuditSink,
        descriptors: DescriptorStore,
        validator: DescriptorValidator,
    ):
        self.files = files  # descripteurs Git, lecture seule
        self.secrets = secrets
        self.accounts = accounts
        self.audit = audit
        self.descriptors = descriptors
        self.validator = validator

    async def catalog(self) -> Catalog:
        """Relu à chaque appel : une appli créée ou modifiée est visible immédiatement."""
        return merge(self.files, await self.descriptors.list_descriptors(), self.validator)

    async def app(self, app_id: str) -> App:
        try:
            return (await self.catalog()).apps[app_id]
        except KeyError:
            raise NotFound(app_id) from None

    async def stored(self, app_id: str) -> StoredDescriptor:
        """Descripteur en base, y compris s'il est écarté du catalogue (pour le corriger)."""
        found = await self.descriptors.get_descriptor(app_id)
        if found is None:
            raise NotFound(app_id)
        return found

    # --- Descripteurs d'applis -------------------------------------------------------

    def parse(self, text: str, revision: int) -> dict[str, Any]:
        """YAML saisi → document validé. ``metadata.revision`` est tenue par Sesame."""
        try:
            doc = parse_yaml(text)
        except DescriptorError as e:
            raise InvalidDescriptor([str(e)]) from None
        if isinstance(doc.get("metadata"), dict):
            doc["metadata"]["revision"] = revision
        errors = self.validator.check(doc)
        if errors:
            raise InvalidDescriptor(errors)
        return doc

    async def _collisions(self, doc: dict[str, Any], app_id: str | None) -> list[str]:
        """Identifiant ou hôte public déjà pris par une autre appli (fichier ou base)."""
        new_id, host = doc["metadata"]["id"], doc["spec"]["public"]["host"]
        errors = []
        if new_id in self.files:
            errors.append(f"metadata/id : « {new_id} » est déjà décrit par un fichier Git")
        stored = await self.descriptors.list_descriptors()
        if app_id is None and any(s.app_id == new_id for s in stored):
            errors.append(f"metadata/id : « {new_id} » est déjà utilisé")
        others = [a.public_host for a in self.files.values()] + [
            s.document.get("spec", {}).get("public", {}).get("host") for s in stored if s.app_id != new_id
        ]
        if host in others:
            errors.append(f"spec/public/host : « {host} » est déjà utilisé par une autre appli")
        return errors

    async def _audit(
        self, action: str, actor: AdminUser, app_id: str | None, cid: str, outcome: str, reason: str
    ) -> None:
        await self.audit.record(
            AuditEvent.of(action, outcome, actor, app_id=app_id, correlation_id=cid, reason=reason)
        )

    async def create_descriptor(self, actor: AdminUser, text: str, cid: str) -> tuple[str, int]:
        """Crée une appli en base ; portail et proxy la chargent au prochain rechargement à chaud."""
        try:
            doc = self.parse(text, 1)
            app_id = doc["metadata"]["id"]
            if errors := await self._collisions(doc, None):
                raise InvalidDescriptor(errors)
        except InvalidDescriptor:
            await self._audit("descriptor_created", actor, None, cid, "failure", "invalid_descriptor")
            raise
        try:
            revision = await self.descriptors.create_descriptor(app_id, doc, actor.actor)
        except Conflict as e:
            await self._audit("descriptor_created", actor, app_id, cid, "failure", "conflict")
            raise InvalidDescriptor([f"Enregistrement refusé : {e}."]) from None
        except Unavailable:
            await self._audit("descriptor_created", actor, app_id, cid, "failure", "store_unavailable")
            raise
        await self._audit("descriptor_created", actor, app_id, cid, "success", f"revision:{revision}")
        log.info("appli créée", extra={"app_id": app_id, "correlation_id": cid})
        return app_id, revision

    async def update_descriptor(
        self, actor: AdminUser, app_id: str, text: str, expected_revision: int, cid: str
    ) -> int:
        """Remplace le descripteur si personne ne l'a modifié depuis ``expected_revision``."""
        try:
            if app_id in self.files:
                raise InvalidDescriptor(
                    ["Appli décrite par un fichier Git : modification par merge request."]
                )
            doc = self.parse(text, expected_revision + 1)
            if doc["metadata"]["id"] != app_id:
                raise InvalidDescriptor(["metadata/id : l'identifiant d'une appli ne peut pas changer."])
            if errors := await self._collisions(doc, app_id):
                raise InvalidDescriptor(errors)
        except InvalidDescriptor:
            await self._audit("descriptor_updated", actor, app_id, cid, "failure", "invalid_descriptor")
            raise
        try:
            revision = await self.descriptors.update_descriptor(app_id, doc, actor.actor, expected_revision)
        except (Conflict, NotFound) as e:
            reason = "conflict" if isinstance(e, Conflict) else "not_found"
            await self._audit("descriptor_updated", actor, app_id, cid, "failure", reason)
            if isinstance(e, NotFound):
                raise
            raise InvalidDescriptor(
                [f"Enregistrement refusé : {e}. Rechargez la page pour repartir de la version courante."]
            ) from None
        except Unavailable:
            await self._audit("descriptor_updated", actor, app_id, cid, "failure", "store_unavailable")
            raise
        await self._audit("descriptor_updated", actor, app_id, cid, "success", f"revision:{revision}")
        log.info("appli modifiée", extra={"app_id": app_id, "correlation_id": cid})
        return revision

    async def open_access(self, actor: AdminUser, app_id: str, cid: str) -> int:
        """Retire ``spec.access`` : tout titulaire d'un compte actif accède à l'appli (ADR 0017).
        Nouvelle révision, auditée comme toute modification de descripteur."""
        if app_id in self.files:
            await self._audit("descriptor_updated", actor, app_id, cid, "failure", "read_only")
            raise InvalidInput("Appli décrite par un fichier Git : retirer spec.access par merge request.")
        stored = await self.stored(app_id)
        doc = {**stored.document, "spec": dict(stored.document.get("spec", {}))}
        doc["spec"].pop("access", None)
        return await self.update_descriptor(actor, app_id, self.validator.to_yaml(doc), stored.revision, cid)

    async def delete_descriptor(
        self, actor: AdminUser, app_id: str, expected_revision: int, cid: str
    ) -> None:
        """Supprime une appli en base. Refusé tant qu'elle a des comptes : leurs identifiants
        resteraient sinon dans le coffre sans plus apparaître nulle part."""

        async def fail(reason: str) -> None:
            await self._audit("descriptor_deleted", actor, app_id, cid, "failure", reason)

        if app_id in self.files:
            await fail("read_only")
            raise InvalidInput("Appli décrite par un fichier Git : suppression par merge request.")
        if await self.accounts.list_accounts(app_id):
            await fail("accounts_remaining")
            raise InvalidInput("Supprimez d'abord les comptes de cette appli (coffre et registre).")
        try:
            await self.descriptors.delete_descriptor(app_id, actor.actor, expected_revision)
        except Conflict:
            await fail("conflict")
            raise InvalidInput("Le descripteur a été modifié entre-temps : rechargez la page.") from None
        except NotFound:
            await fail("not_found")
            raise
        except Unavailable:
            await fail("store_unavailable")
            raise
        await self._audit(
            "descriptor_deleted", actor, app_id, cid, "success", f"revision:{expected_revision}"
        )
        log.info("appli supprimée", extra={"app_id": app_id, "correlation_id": cid})

    # --- Comptes -------------------------------------------------------------------

    async def provision(
        self, actor: AdminUser, app_id: str, user_key: str, fields: dict[str, str], cid: str
    ) -> None:
        """Écrit les identifiants dans le coffre puis active le compte dans le registre."""
        app = await self.app(app_id)
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
        await self.app(app_id)
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
        await self.app(app_id)

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
