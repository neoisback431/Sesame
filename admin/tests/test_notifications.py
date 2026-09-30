# SPDX-License-Identifier: Apache-2.0
"""Notifications par mail (ADR 0030) : réglages, boîte d'envoi, worker, SMTP, absence de fuite."""

import asyncio
import re
import smtplib
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sesame_admin.audit import MemoryAuditSink
from sesame_admin.notifications import (
    MailError,
    NotificationWorker,
    SettingsError,
    SmtpMailer,
    build_message,
    parse_recipients,
    validate_settings,
)
from sesame_admin.ports import NotificationSettings
from sesame_admin.service import InvalidInput
from sesame_admin.web import create_app

from .conftest import ADMIN, make_service
from .test_web import FakeAuth, login

SMTP_SECRET = "SMTP-Pw-très-secret-4242"
CONFIGURED = NotificationSettings(
    enabled=True,
    smtp_host="smtp.example.org",
    from_address="sesame@example.org",
    recipients=("ops@example.org", "sec@example.org"),
    events=("access_requested", "account_failed", "upstream_unreachable", "admin_sensitive"),
)


class FakeMailer:
    def __init__(self, fail: str | None = None):
        self.sent = []
        self.fail = fail

    async def send(self, settings, message):
        if self.fail:
            raise MailError(self.fail)
        self.sent.append(message)


def run(coro):
    return asyncio.run(coro)


def worker_for(service, mailer):
    async def names():
        return {"fake-app": "Appli factice"}

    return NotificationWorker(service.notifications, mailer, "https://admin.test", names)


@pytest.fixture
def svc(apps):
    mailer = FakeMailer()
    audit = MemoryAuditSink()
    service = make_service(apps, audit, mailer)
    run(service.notifications.save_settings(CONFIGURED, "admin"))
    return service, mailer, audit


# --- Réglages ------------------------------------------------------------------------


def test_recipients_are_parsed_and_deduplicated():
    assert parse_recipients("a@x.org, b@x.org;a@x.org\n c@x.org\r\n") == ("a@x.org", "b@x.org", "c@x.org")


@pytest.mark.parametrize(
    "change",
    [
        {"smtp_port": 0},
        {"smtp_port": 70000},
        {"smtp_security": "ssl"},
        {"smtp_host": "smtp.example.org\r\nBcc: x@y.z"},
        {"smtp_host": "-bad"},
        {"from_address": "pas-une-adresse"},
        {"from_address": "a@x.org\r\nBcc: v@x.org"},
        {"recipients": ("ok@x.org", "mauvais")},
        {"recipients": tuple(f"u{i}@x.org" for i in range(21))},
        {"events": ("access_requested", "inconnu")},
        {"smtp_user": "a\r\nb"},
        {"recipients": ()},  # activé sans destinataire
        {"smtp_host": ""},  # activé sans serveur
    ],
)
def test_invalid_settings_are_refused(change):
    with pytest.raises(SettingsError):
        validate_settings(replace(CONFIGURED, **change))


def test_valid_settings_and_disabled_state_pass():
    validate_settings(CONFIGURED)
    validate_settings(NotificationSettings())  # désactivé : rien d'obligatoire


def test_saving_is_audited_without_addresses(svc):
    service, _, audit = svc
    run(service.save_notification_settings(ADMIN, replace(CONFIGURED, enabled=False), "cid"))
    event = audit.events[-1]
    assert (event.action, event.outcome) == ("notification_settings_updated", "success")
    assert "example.org" not in repr(event)
    with pytest.raises(InvalidInput):
        run(service.save_notification_settings(ADMIN, replace(CONFIGURED, smtp_port=0), "cid"))
    assert audit.events[-1].outcome == "failure"
    assert run(service.notification_settings()).enabled is False  # refus : réglages précédents conservés


# --- Worker --------------------------------------------------------------------------


def test_worker_sends_one_mail_per_event_without_secrets(svc):
    service, mailer, _ = svc
    store = service.notifications
    store.deposit("access_requested", "fake-app", "bob", "credentials")
    store.deposit("account_failed", "fake-app", "alice", "login_rejected")
    store.deposit("upstream_unreachable", "fake-app", None, "upstream_unreachable")
    assert run(worker_for(service, mailer).run_once()) == 3
    subjects = [m["Subject"] for m in mailer.sent]
    assert "[Sesame] Nouvelle demande d'accès : fake-app" in subjects
    assert all(m["To"] == "ops@example.org, sec@example.org" for m in mailer.sent)
    body = mailer.sent[0].get_content()
    assert "Appli factice (fake-app)" in body and "bob" in body
    assert "https://admin.test/requests" in body
    assert "identifiants refusés par l'application" in mailer.sent[1].get_content()
    assert {n.status for n in store.items} == {"sent"}
    assert run(worker_for(service, mailer).run_once()) == 0  # rien à renvoyer


def test_disabled_events_and_global_switch_skip_without_sending(svc):
    service, mailer, _ = svc
    store = service.notifications
    run(store.save_settings(replace(CONFIGURED, events=("access_requested",)), "admin"))
    store.deposit("account_failed", "fake-app", "alice", "login_rejected")
    store.deposit("access_requested", "fake-app", "bob", "no_account")
    assert run(worker_for(service, mailer).run_once()) == 1
    assert [n.status for n in store.items] == ["skipped", "sent"]

    run(store.save_settings(replace(CONFIGURED, enabled=False), "admin"))
    store.deposit("access_requested", "fake-app", "eve", "no_account")
    assert run(worker_for(service, mailer).run_once()) == 0
    assert store.items[-1].status == "skipped"


def test_unconfigured_smtp_skips(apps):
    service = make_service(apps, mailer=FakeMailer())
    service.notifications.deposit("access_requested", "fake-app", "bob", "no_account")
    assert run(worker_for(service, service.mailer).run_once()) == 0
    assert service.notifications.items[0].status == "skipped"


def test_smtp_failure_is_retried_then_abandoned_without_blocking(svc):
    service, _, _ = svc
    failing = FakeMailer(fail="smtp_connect")
    worker = worker_for(service, failing)
    service.notifications.deposit("access_requested", "fake-app", "bob", "credentials")
    for attempt in range(1, 6):
        assert run(worker.run_once()) == 0
        n = service.notifications.items[0]
        assert (n.status, n.attempts, n.last_error) == ("pending", attempt, "smtp_connect")
    run(worker.run_once())  # 6e échec : abandon
    n = service.notifications.items[0]
    assert (n.status, n.attempts) == ("failed", 6)
    # Un SMTP rétabli n'envoie pas ce qui est abandonné, mais les nouveaux événements passent.
    ok = FakeMailer()
    service.notifications.deposit("access_requested", "fake-app", "carol", "no_account")
    assert run(worker_for(service, ok).run_once()) == 1


def test_message_headers_cannot_be_injected(svc):
    service, _, _ = svc
    service.notifications.deposit("account_failed", "app\r\nBcc: evil@x.org", "u\r\nX: y", "r\r\nZ: 1")
    n = service.notifications.items[0]
    msg = build_message(n, CONFIGURED, "https://admin.test", {})
    assert "\n" not in msg["Subject"] and "\r" not in msg["Subject"]
    assert msg["Bcc"] is None
    assert msg["To"] == "ops@example.org, sec@example.org"


# --- Événements d'administration -------------------------------------------------------


def test_sensitive_admin_actions_enqueue_an_event_with_the_actor(svc):
    service, _, _ = svc
    run(service.provision(ADMIN, "fake-app", "dave", {"username": "d", "password": SMTP_SECRET}, "c"))
    run(service.set_status(ADMIN, "fake-app", "dave", "disabled", "c"))
    run(service.delete(ADMIN, "fake-app", "dave", "c"))
    reasons = [(n.event, n.reason, n.user_key, n.actor) for n in service.notifications.items]
    assert [r[:3] for r in reasons] == [
        ("admin_sensitive", "account_disabled", "dave"),
        ("admin_sensitive", "account_deleted", "dave"),
    ]
    assert all(r[3] == ADMIN.actor for r in reasons)
    assert SMTP_SECRET not in repr(service.notifications.items)
    body = build_message(service.notifications.items[0], CONFIGURED, "https://admin.test", {}).get_content()
    assert ADMIN.actor in body


def test_a_broken_outbox_never_fails_the_admin_action(svc):
    service, _, _ = svc

    async def boom(*a, **k):
        raise RuntimeError("base indisponible")

    service.notifications.enqueue = boom
    run(service.provision(ADMIN, "fake-app", "dave", {"username": "d", "password": "p"}, "c"))
    run(service.delete(ADMIN, "fake-app", "dave", "c"))  # ne lève pas


# --- SMTP réel (client bibliothèque standard, serveur simulé) ----------------------------


class FakeSmtp:
    log: list = []
    fail_login = False

    def __init__(self, host, port, timeout=None, context=None):
        FakeSmtp.log.append(("connect", host, port, type(self).__name__))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        FakeSmtp.log.append(("starttls",))

    def login(self, user, password):
        FakeSmtp.log.append(("login", user))
        if FakeSmtp.fail_login:
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials " + password.encode())

    def send_message(self, message):
        FakeSmtp.log.append(("send", message["Subject"]))


class FakeSmtpSsl(FakeSmtp):
    pass


@pytest.fixture
def smtp(monkeypatch):
    FakeSmtp.log = []
    FakeSmtp.fail_login = False
    monkeypatch.setattr(smtplib, "SMTP", FakeSmtp)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSmtpSsl)
    return FakeSmtp


def message(service):
    service.notifications.deposit("access_requested", "fake-app", "bob", "no_account")
    return build_message(service.notifications.items[0], CONFIGURED, "https://admin.test", {})


def test_starttls_login_and_send(svc, smtp):
    service, _, _ = svc
    run(SmtpMailer(SMTP_SECRET).send(replace(CONFIGURED, smtp_user="sesame"), message(service)))
    assert [e[0] for e in smtp.log] == ["connect", "starttls", "login", "send"]


def test_implicit_tls_uses_ssl_client(svc, smtp):
    service, _, _ = svc
    run(SmtpMailer(None).send(replace(CONFIGURED, smtp_security="tls", smtp_port=465), message(service)))
    assert smtp.log[0] == ("connect", "smtp.example.org", 465, "FakeSmtpSsl")
    assert "starttls" not in [e[0] for e in smtp.log] and "login" not in [e[0] for e in smtp.log]


def test_password_is_never_sent_without_encryption(svc, smtp):
    service, _, _ = svc
    with pytest.raises(MailError) as e:
        run(
            SmtpMailer(SMTP_SECRET).send(
                replace(CONFIGURED, smtp_security="none", smtp_user="u"), message(service)
            )
        )
    assert e.value.code == "password_without_tls" and not smtp.log


def test_smtp_errors_become_short_codes_without_server_text(svc, smtp):
    service, _, _ = svc
    smtp.fail_login = True
    with pytest.raises(MailError) as e:
        run(SmtpMailer(SMTP_SECRET).send(replace(CONFIGURED, smtp_user="sesame"), message(service)))
    assert e.value.code == "smtp_auth"
    assert SMTP_SECRET not in str(e.value) and SMTP_SECRET not in repr(SmtpMailer(SMTP_SECRET))


# --- Pages -----------------------------------------------------------------------------


@pytest.fixture
def web(apps):
    audit = MemoryAuditSink()
    mailer = FakeMailer()
    service = make_service(apps, audit, mailer)
    app = create_app(
        service,
        FakeAuth(),
        audit,
        public_url="https://admin.test",
        session_key="k" * 32,
        admin_group="sesame-admins",
        issuer="https://idp.test",
        user_key_claim="preferred_username",
        groups_claim="groups",
        smtp_password_set=True,
    )
    client = TestClient(app, base_url="https://admin.test", follow_redirects=False)
    login(client)
    return client, service, mailer, audit


def token(client):
    return re.search(r'name="csrf" value="([^"]+)"', client.get("/settings/notifications").text).group(1)


FORM = {
    "enabled": "1",
    "smtp_host": "smtp.example.org",
    "smtp_port": "587",
    "smtp_security": "starttls",
    "smtp_user": "sesame",
    "from_address": "sesame@example.org",
    "recipients": "ops@example.org\nsec@example.org",
}


def test_settings_page_saves_and_shows_events_and_history(web):
    client, service, _, audit = web
    page = client.get("/settings/notifications").text
    assert "SESAME_SMTP_PASSWORD" in page and "défini" in page
    assert "Compte passé en échec" in page and "Aucune notification" in page

    t = token(client)
    r = client.post(
        "/settings/notifications",
        data={**FORM, "csrf": t, "events": ["access_requested", "admin_sensitive"]},
    )
    assert r.status_code == 303
    saved = run(service.notification_settings())
    assert saved.enabled and saved.recipients == ("ops@example.org", "sec@example.org")
    assert saved.events == ("access_requested", "admin_sensitive")
    assert saved.updated_by.endswith("|s-admin")  # identité fournie par FakeAuth
    assert "enregistrés" in client.get("/settings/notifications").text

    service.notifications.deposit("access_requested", "fake-app", "bob", "no_account")
    assert "no_account" in client.get("/settings/notifications").text
    assert ("notification_settings_updated", "success") in [(e.action, e.outcome) for e in audit.events]


def test_invalid_form_is_reported_and_keeps_previous_settings(web):
    client, service, _, _ = web
    t = token(client)
    r = client.post("/settings/notifications", data={**FORM, "csrf": t, "smtp_port": "abc"})
    assert r.status_code == 422 and "Port SMTP invalide" in r.text
    assert 'value="smtp.example.org"' in r.text  # la saisie est conservée pour correction
    assert run(service.notification_settings()).enabled is False


def test_settings_require_admin_and_csrf(web, apps):
    client, service, _, _ = web
    r = client.post("/settings/notifications", data={**FORM, "csrf": "faux"})
    assert r.status_code == 400
    assert run(service.notification_settings()).enabled is False
    anonymous = TestClient(client.app, base_url="https://admin.test", follow_redirects=False)
    assert anonymous.get("/settings/notifications").status_code == 302
    assert anonymous.post("/settings/notifications", data=FORM).status_code == 403
    assert anonymous.post("/settings/notifications/test", data={}).status_code == 403


def test_test_mail_button(web):
    client, service, mailer, audit = web
    t = token(client)
    client.post("/settings/notifications/test", data={"csrf": t})
    assert "Enregistrez d" in client.get("/settings/notifications").text  # rien à envoyer encore
    client.post("/settings/notifications", data={**FORM, "csrf": t})
    client.post("/settings/notifications/test", data={"csrf": t})
    assert "Mail de test envoyé" in client.get("/settings/notifications").text
    assert mailer.sent[-1]["Subject"] == "[Sesame] Mail de test"
    mailer.fail = "smtp_auth"
    client.post("/settings/notifications/test", data={"csrf": t})
    page = client.get("/settings/notifications").text
    assert "smtp_auth" in page
    assert ("notification_test", "failure") in [(e.action, e.outcome) for e in audit.events]
