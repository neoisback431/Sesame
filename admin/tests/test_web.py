# SPDX-License-Identifier: Apache-2.0
"""UI d'administration : authentification, groupe admin, CSRF, opérations, absence de fuite."""

import re

import pytest
from fastapi.testclient import TestClient
from sesame_admin.audit import MemoryAuditSink
from sesame_admin.auth import AuthError
from sesame_admin.memory import MemoryAccountStore, MemorySecretWriter
from sesame_admin.ports import Unavailable
from sesame_admin.service import AdminService
from sesame_admin.web import create_app
from starlette.responses import RedirectResponse

SECRET = "Pw-ADMIN-4242-secret"


class FakeAuth:
    def __init__(self):
        self.claims = {
            "iss": "https://idp.test",
            "sub": "s-admin",
            "preferred_username": "admin",
            "groups": ["sesame-admins"],
        }
        self.fail = False

    async def login_redirect(self, request, redirect_uri):
        return RedirectResponse(redirect_uri, status_code=302)

    async def callback(self, request):
        if self.fail:
            raise AuthError("access_denied")
        return self.claims


@pytest.fixture
def ctx(apps):
    audit = MemoryAuditSink()
    service = AdminService(apps, MemorySecretWriter(), MemoryAccountStore(), audit)
    auth = FakeAuth()
    app = create_app(
        service,
        auth,
        audit,
        public_url="https://admin.test",
        session_key="k" * 32,
        admin_group="sesame-admins",
        issuer="https://idp.test",
        user_key_claim="preferred_username",
        groups_claim="groups",
    )
    client = TestClient(app, base_url="https://admin.test", follow_redirects=False)
    return client, service, auth, audit


def login(client):
    r = client.get("/login")
    assert r.status_code == 302
    r = client.get(r.headers["location"].replace("https://admin.test", ""))
    assert r.status_code == 302, r.text
    return r


def csrf(client, path="/apps/fake-app"):
    html = client.get(path).text
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def assert_no_leak(text: str):
    assert SECRET not in text


def test_requires_login(ctx):
    client, *_ = ctx
    r = client.get("/apps/fake-app")
    assert r.status_code == 302 and r.headers["location"].startswith("/login?next=/apps/fake-app")
    assert client.post("/apps/fake-app/accounts", data={"user_key": "x"}).status_code == 403


def test_login_redirects_to_next_and_audits(ctx):
    client, _, _, audit = ctx
    client.get("/login?next=/apps/fake-app")
    r = client.get("/auth/callback")
    assert r.headers["location"] == "/apps/fake-app"
    assert [(e.action, e.outcome) for e in audit.events] == [("admin_login", "success")]
    assert "Appli factice" in client.get("/").text


def test_open_redirect_is_refused(ctx):
    client, *_ = ctx
    client.get("/login?next=//evil.example/")
    assert client.get("/auth/callback").headers["location"] == "/"


def test_non_admin_is_denied(ctx):
    client, _, auth, audit = ctx
    auth.claims = {**auth.claims, "groups": ["fake-app-users"]}
    client.get("/login")
    r = client.get("/auth/callback")
    assert r.status_code == 403
    assert audit.events[-1].action == "access_denied" and audit.events[-1].reason == "not_admin"
    assert client.get("/").status_code == 302  # pas de session


def test_oidc_failure(ctx):
    client, _, auth, audit = ctx
    auth.fail = True
    client.get("/login")
    assert client.get("/auth/callback").status_code == 401
    assert audit.events[-1].outcome == "failure"


def test_provision_disable_delete_flow(ctx):
    client, service, _, audit = ctx
    login(client)
    token = csrf(client)
    r = client.post(
        "/apps/fake-app/accounts",
        data={"csrf": token, "user_key": "carol", "cred_username": "cdupont", "cred_password": SECRET},
    )
    assert r.status_code == 303
    page = client.get("/apps/fake-app").text
    assert "enregistré et activé" in page and "carol" in page and "actif" in page
    assert_no_leak(page)
    assert service.secrets.entries[("fake-app", "carol")]["password"] == SECRET

    client.post("/apps/fake-app/accounts/carol/status", data={"csrf": token, "status": "disabled"})
    assert "désactivé" in client.get("/apps/fake-app").text
    client.post("/apps/fake-app/accounts/carol/delete", data={"csrf": token})
    assert ("fake-app", "carol") not in service.secrets.entries
    actions = [e.action for e in audit.events]
    assert actions.count("credential_written") == 1 and "credential_deleted" in actions
    assert_no_leak(repr(audit.events))


def test_csrf_is_required(ctx):
    client, service, *_ = ctx
    login(client)
    client.post(
        "/apps/fake-app/accounts",
        data={"csrf": "forged", "user_key": "carol", "cred_username": "u", "cred_password": SECRET},
    )
    page = client.get("/apps/fake-app").text
    assert "CSRF" in page and service.secrets.entries == {}


def test_invalid_input_is_reported_without_echoing_secrets(ctx):
    client, service, *_ = ctx
    login(client)
    token = csrf(client)
    client.post(
        "/apps/fake-app/accounts",
        data={"csrf": token, "user_key": "../x", "cred_username": "u", "cred_password": SECRET},
    )
    page = client.get("/apps/fake-app").text
    assert "Identifiant utilisateur invalide" in page
    assert_no_leak(page)
    assert service.secrets.entries == {}


def test_secret_store_outage_is_reported(ctx):
    client, service, *_ = ctx

    async def down(*_):
        raise Unavailable("coffre injoignable")

    service.secrets.write_credential = down
    login(client)
    token = csrf(client)
    client.post(
        "/apps/fake-app/accounts",
        data={"csrf": token, "user_key": "carol", "cred_username": "u", "cred_password": SECRET},
    )
    page = client.get("/apps/fake-app").text
    assert "service indisponible" in page
    assert_no_leak(page)


def test_unknown_app(ctx):
    client, *_ = ctx
    login(client)
    assert client.get("/apps/inconnue").status_code == 404


def test_logout(ctx):
    client, *_ = ctx
    login(client)
    token = csrf(client, "/")
    assert client.post("/logout", data={"csrf": token}).status_code == 303
    assert client.get("/").status_code == 302


def test_logs_never_contain_secrets(ctx, caplog, capsys):
    client, *_ = ctx
    caplog.set_level("DEBUG")
    login(client)
    token = csrf(client)
    client.post(
        "/apps/fake-app/accounts",
        data={"csrf": token, "user_key": "carol", "cred_username": "u", "cred_password": SECRET},
    )
    captured = capsys.readouterr()
    for text in (caplog.text, captured.out, captured.err):
        assert_no_leak(text)
