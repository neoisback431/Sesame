# SPDX-License-Identifier: Apache-2.0
"""Notifications par mail aux administrateurs (ADR 0030).

Le portail et le proxy déposent un événement dans la boîte d'envoi (``notifications``) ; ce
module l'expédie en SMTP. Un SMTP en panne ne bloque donc jamais une connexion : l'envoi est
repris avec une attente croissante, puis abandonné. Aucun mail ne contient de secret : un
événement ne porte que des codes courts (appli, utilisateur, motif).
"""

from __future__ import annotations

import asyncio
import logging
import re
import smtplib
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Protocol

from .ports import Notification, NotificationSettings, NotificationStore

log = logging.getLogger(__name__)

EVENTS: dict[str, str] = {
    "access_requested": "Nouvelle demande d'accès",
    "account_failed": "Compte passé en échec",
    "upstream_unreachable": "Application injoignable",
    "admin_sensitive": "Action d'administration sensible",
}

# Motifs courts émis par le proxy et l'admin, rendus lisibles ; un motif inconnu s'affiche tel quel.
REASONS: dict[str, str] = {
    "credentials": "identifiants fournis par l'utilisateur (à activer)",
    "no_account": "l'utilisateur n'a pas de compte (à créer)",
    "login_rejected": "identifiants refusés par l'application",
    "login_unexpected_response": "réponse inattendue de l'application au login",
    "form_not_found": "formulaire de login introuvable (page modifiée ?)",
    "secret_missing": "identifiants absents du coffre",
    "upstream_unreachable": "application injoignable (DNS, TLS, connexion refusée…)",
    "account_deleted": "compte supprimé",
    "account_disabled": "compte désactivé",
    "disable_all": "tous les comptes d'un utilisateur désactivés",
    "descriptor_deleted": "application supprimée",
}

MAX_ATTEMPTS = 6
BATCH = 20
_EMAIL = re.compile(r"^[^@\s<>,;\"'()\\]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$")
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class SettingsError(ValueError):
    """Réglages refusés ; le message est affichable (jamais de valeur sensible)."""


def valid_email(value: str) -> bool:
    return bool(_EMAIL.fullmatch(value))


def parse_recipients(text: str) -> tuple[str, ...]:
    """Adresses séparées par des virgules, points-virgules ou retours à la ligne."""
    found: list[str] = []
    for part in re.split(r"[,;\n\r]+", text):
        part = part.strip()
        if part and part not in found:
            found.append(part)
    return tuple(found)


def validate_settings(s: NotificationSettings) -> None:
    if not 1 <= s.smtp_port <= 65535:
        raise SettingsError("Port SMTP invalide.")
    if s.smtp_security not in ("starttls", "tls", "none"):
        raise SettingsError("Sécurité SMTP inconnue.")
    if s.smtp_host and not _HOST.fullmatch(s.smtp_host):
        raise SettingsError("Serveur SMTP invalide (nom d'hôte ou adresse attendu).")
    if len(s.smtp_user) > 254 or any(c in s.smtp_user for c in "\r\n\x00"):
        raise SettingsError("Identifiant SMTP invalide.")
    if s.from_address and not valid_email(s.from_address):
        raise SettingsError("Adresse d'expédition invalide.")
    if len(s.recipients) > 20:
        raise SettingsError("20 destinataires au plus.")
    for r in s.recipients:
        if not valid_email(r):
            raise SettingsError(f"Adresse de destinataire invalide : {r[:80]}")
    if unknown := set(s.events) - set(EVENTS):
        raise SettingsError(f"Événement inconnu : {sorted(unknown)[0][:40]}")
    if s.enabled and not (s.smtp_host and s.from_address and s.recipients):
        raise SettingsError(
            "Pour activer les notifications : serveur, expéditeur et un destinataire au moins."
        )


class Mailer(Protocol):
    """Expéditeur de mails. ``send`` lève ``MailError`` avec un code court."""

    async def send(self, settings: NotificationSettings, message: EmailMessage) -> None: ...


class MailError(RuntimeError):
    """Échec d'envoi ; ``code`` est un motif court, sans contenu du serveur SMTP ni de mail."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class SmtpMailer:
    """Envoi SMTP (bibliothèque standard). Le mot de passe vient de l'environnement de l'admin,
    jamais de la base ; il n'apparaît dans aucun message d'erreur ni journal."""

    def __init__(self, password: str | None, ca_file: str | None = None, timeout: float = 15.0) -> None:
        self._password = password
        self._ca_file = ca_file
        self._timeout = timeout

    def __repr__(self) -> str:
        return "SmtpMailer()"

    @property
    def has_password(self) -> bool:
        return bool(self._password)

    def _send_blocking(self, s: NotificationSettings, message: EmailMessage) -> None:
        context = ssl.create_default_context(cafile=self._ca_file)
        if self._password and s.smtp_security == "none":
            raise MailError("password_without_tls")
        try:
            if s.smtp_security == "tls":
                client: smtplib.SMTP = smtplib.SMTP_SSL(
                    s.smtp_host, s.smtp_port, timeout=self._timeout, context=context
                )
            else:
                client = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=self._timeout)
            with client:
                if s.smtp_security == "starttls":
                    client.starttls(context=context)
                if s.smtp_user and self._password:
                    client.login(s.smtp_user, self._password)
                client.send_message(message)
        except MailError:
            raise
        except smtplib.SMTPAuthenticationError:
            raise MailError("smtp_auth") from None
        except smtplib.SMTPRecipientsRefused:
            raise MailError("smtp_recipients_refused") from None
        except (ssl.SSLError, smtplib.SMTPNotSupportedError):
            raise MailError("smtp_tls") from None
        except (OSError, smtplib.SMTPException) as e:
            raise MailError(f"smtp_{type(e).__name__.lower()}"[:60]) from None

    async def send(self, settings: NotificationSettings, message: EmailMessage) -> None:
        await asyncio.to_thread(self._send_blocking, settings, message)


def _clean(text: str, limit: int = 200) -> str:
    """Une seule ligne, sans caractère de contrôle : rien ne peut injecter un en-tête."""
    return "".join(c if c.isprintable() else " " for c in text)[:limit].strip()


def build_message(
    n: Notification, settings: NotificationSettings, public_url: str, app_names: dict[str, str]
) -> EmailMessage:
    label = EVENTS.get(n.event, n.event)
    app = n.app_id or ""
    app_label = f"{app_names[app]} ({app})" if app in app_names else app or "—"
    reason = REASONS.get(n.reason or "", n.reason or "—")
    link = f"{public_url}/requests" if n.event == "access_requested" else f"{public_url}/apps/{app}"
    lines = [
        label,
        "",
        f"Application : {app_label}",
        f"Utilisateur : {n.user_key or '—'}",
        f"Détail      : {reason}",
    ]
    if n.actor:
        lines.append(f"Par         : {n.actor}")
    lines += [
        f"Date        : {n.created_at.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "",
        f"Console d'administration : {link if app or n.event == 'access_requested' else public_url}",
        "",
        "Ce message est envoyé par Sesame. Il ne contient aucun identifiant applicatif.",
    ]
    msg = EmailMessage()
    msg["Subject"] = _clean(f"[Sesame] {label}" + (f" : {app}" if app else ""), 150)
    msg["From"] = settings.from_address
    msg["To"] = ", ".join(settings.recipients)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=settings.from_address.rpartition("@")[2] or None)
    msg.set_content("\n".join(_clean(line, 400) for line in lines))
    return msg


def build_test_message(settings: NotificationSettings, public_url: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = "[Sesame] Mail de test"
    msg["From"] = settings.from_address
    msg["To"] = ", ".join(settings.recipients)
    msg["Date"] = formatdate(localtime=False)
    msg.set_content(
        f"Ceci est un mail de test envoyé depuis la console d'administration Sesame ({public_url}).\n"
        "Si vous le recevez, les notifications sont correctement configurées."
    )
    return msg


@dataclass
class NotificationWorker:
    """Expédie la boîte d'envoi. ``run_once`` est appelable seul (tests) ; ``run`` boucle."""

    store: NotificationStore
    mailer: Mailer
    public_url: str
    # Noms lisibles des applis (identifiant -> nom), fournis par l'application ; facultatif.
    app_names: Callable[[], Awaitable[dict[str, str]]] | None = None
    interval: float = 30.0

    async def run_once(self) -> int:
        """Traite un lot ; renvoie le nombre de notifications expédiées."""
        settings = await self.store.get_settings()
        pending = await self.store.claim_pending(BATCH)
        if not pending:
            return 0
        names = await self.app_names() if self.app_names else {}
        sent = 0
        for n in pending:
            if not settings.enabled or n.event not in settings.events:
                await self.store.mark(n.id, "skipped", None)
                continue
            if not (settings.smtp_host and settings.from_address and settings.recipients):
                await self.store.mark(n.id, "skipped", "not_configured")
                continue
            try:
                await self.mailer.send(settings, build_message(n, settings, self.public_url, names))
            except MailError as e:
                retry = n.attempts + 1 < MAX_ATTEMPTS
                await self.store.mark(n.id, "retry" if retry else "failed", e.code)
                log.warning("envoi de notification échoué", extra={"reason": e.code})
            else:
                await self.store.mark(n.id, "sent", None)
                sent += 1
        return sent

    async def run(self) -> None:
        cycles = 0
        while True:
            try:
                await self.run_once()
                cycles += 1
                if cycles % 2880 == 0:  # ~ une fois par jour à 30 s
                    await self.store.purge(30)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 (le worker ne doit jamais s'arrêter)
                log.exception("boucle de notification en erreur")
            await asyncio.sleep(self.interval)
