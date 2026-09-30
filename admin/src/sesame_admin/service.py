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
from .notifications import (
    Mailer,
    MailError,
    SettingsError,
    build_test_message,
    validate_settings,
)
from .ports import (
    AccessRequest,
    AccessRequestStore,
    AccountStore,
    Conflict,
    DescriptorStore,
    NotFound,
    NotificationSettings,
    NotificationStore,
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
        requests: AccessRequestStore,
        notifications: NotificationStore,
        mailer: Mailer | None = None,
    ):
        self.files = files  # descripteurs Git, lecture seule
        self.secrets = secrets
        self.accounts = accounts
        self.audit = audit
        self.descriptors = descriptors
        self.validator = validator
        self.requests = requests  # demandes d'accès (ADR 0029)
        self.notifications = notifications  # réglages et boîte d'envoi (ADR 0030)
        self.mailer = mailer

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
        await self._notify_sensitive(actor, "descriptor_deleted", app_id, None)
        log.info("appli supprimée", extra={"app_id": app_id, "correlation_id": cid})

    # --- Notifications par mail (ADR 0030) ---------------------------------------------

    async def _notify_sensitive(
        self, actor: AdminUser, reason: str, app_id: str | None, user_key: str | None
    ) -> None:
        """Signale une action d'administration sensible. Ne fait jamais échouer l'action :
        elle est déjà faite et auditée, la notification n'est qu'un signalement."""
        try:
            await self.notifications.enqueue("admin_sensitive", app_id, user_key, reason, actor.actor)
        except Exception:  # noqa: BLE001
            log.warning("notification non enregistrée", extra={"reason": reason})

    async def notification_settings(self) -> NotificationSettings:
        return await self.notifications.get_settings()

    async def save_notification_settings(
        self, actor: AdminUser, settings: NotificationSettings, cid: str
    ) -> None:
        """Valide puis enregistre les réglages (audité, succès comme échec). Aucun secret."""
        try:
            validate_settings(settings)
        except SettingsError as e:
            await self.audit.record(
                AuditEvent.of(
                    "notification_settings_updated", "failure", actor, correlation_id=cid, reason="invalid"
                )
            )
            raise InvalidInput(str(e)) from None
        await self.notifications.save_settings(settings, actor.actor)
        await self.audit.record(
            AuditEvent.of(
                "notification_settings_updated",
                "success",
                actor,
                correlation_id=cid,
                reason=f"enabled:{str(settings.enabled).lower()};events:{len(settings.events)};"
                f"recipients:{len(settings.recipients)}",
            )
        )

    async def send_test_mail(self, actor: AdminUser, public_url: str, cid: str) -> None:
        """Envoie un mail de test aux destinataires enregistrés (sans passer par la boîte d'envoi)."""
        settings = await self.notifications.get_settings()
        if self.mailer is None or not (settings.smtp_host and settings.from_address and settings.recipients):
            raise InvalidInput("Enregistrez d'abord le serveur, l'expéditeur et au moins un destinataire.")
        try:
            await self.mailer.send(settings, build_test_message(settings, public_url))
        except MailError as e:
            await self.audit.record(
                AuditEvent.of("notification_test", "failure", actor, correlation_id=cid, reason=e.code)
            )
            raise InvalidInput(
                f"Envoi impossible ({e.code}). Vérifiez le serveur, le port et la sécurité."
            ) from None
        await self.audit.record(AuditEvent.of("notification_test", "success", actor, correlation_id=cid))

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
        await self._close_request(actor, app_id, user_key, cid, provisioned=True)
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
        # Activer un compte en attente revient à approuver sa demande ; désactiver la refuse.
        await self._close_request(actor, app_id, user_key, cid, approved=status == "active")
        if status == "disabled":
            await self._notify_sensitive(actor, "account_disabled", app_id, user_key)

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
        await self._close_request(actor, app_id, user_key, cid, approved=False)
        await self._notify_sensitive(actor, "account_deleted", app_id, user_key)

    # --- Demandes d'accès (ADR 0029) ---------------------------------------------------

    async def open_requests(self) -> list[AccessRequest]:
        return await self.requests.list_open()

    async def _close_request(
        self,
        actor: AdminUser,
        app_id: str,
        user_key: str,
        cid: str,
        *,
        approved: bool = True,
        provisioned: bool = False,
    ) -> None:
        """Clôt la demande ouverte du couple, si elle existe, et l'audite.

        ``provisioned`` : l'admin vient d'enregistrer un compte par le formulaire habituel ; la
        demande « sans compte » est alors satisfaite (``fulfilled``), celle avec identifiants
        approuvée. Sans demande ouverte, rien ne se passe."""
        request = await self.requests.get_open(app_id, user_key)
        if request is None:
            return
        if provisioned:
            status = "approved" if request.kind == "credentials" else "fulfilled"
        else:
            status = "approved" if approved else "rejected"
        if await self.requests.resolve(app_id, user_key, status, actor.actor):  # type: ignore[arg-type]
            await self.audit.record(
                AuditEvent.of(
                    f"access_request_{status}",
                    "success",
                    actor,
                    app_id=app_id,
                    target_user=user_key,
                    correlation_id=cid,
                    reason=request.kind,
                )
            )

    async def approve_access(self, actor: AdminUser, app_id: str, user_key: str, cid: str) -> None:
        """Active le compte d'une demande avec identifiants (déjà vérifiés et stockés)."""
        request = await self.requests.get_open(app_id, user_key)
        account = await self.accounts.get_account(app_id, user_key)
        if request is None or request.kind != "credentials" or account is None or account.status != "pending":
            raise InvalidInput("Aucune demande avec identifiants en attente pour ce compte.")
        # set_status clôt la demande (approuvée) et audite l'activation.
        await self.set_status(actor, app_id, user_key, "active", cid)

    async def reject_access(self, actor: AdminUser, app_id: str, user_key: str, cid: str) -> None:
        """Refuse une demande. Avec identifiants : ils sont supprimés du coffre, avec le compte
        en attente. Un compte qui n'est pas en attente n'est jamais touché."""
        request = await self.requests.get_open(app_id, user_key)
        if request is None:
            raise InvalidInput("Cette demande n'est plus ouverte.")
        if request.kind == "credentials":
            account = await self.accounts.get_account(app_id, user_key)
            if account is not None and account.status != "pending":
                raise InvalidInput("Le compte n'est plus en attente : gérez-le depuis la page de l'appli.")
            await self.delete(actor, app_id, user_key, cid)  # supprime secret + compte, clôt (refusée)
        await self._close_request(actor, app_id, user_key, cid, approved=False)

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
            await self._close_request(actor, account.app_id, user_key, cid, approved=False)
            count += 1
        if count:
            await self._notify_sensitive(actor, "disable_all", None, user_key)
        return count
