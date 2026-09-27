# SPDX-License-Identifier: Apache-2.0
"""UI d'administration : authentification, groupe admin, CSRF, opérations, absence de fuite."""

import asyncio
import html
import re

import pytest
from fastapi.testclient import TestClient
from sesame_admin.audit import MemoryAuditSink
from sesame_admin.auth import AuthError
from sesame_admin.ports import Unavailable
from sesame_admin.web import create_app
from starlette.responses import RedirectResponse

from .conftest import descriptor_yaml, make_service

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
    service = make_service(apps, audit)
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
    home = client.get("/").text
    assert "Appli factice" in home and 'href="/apps/fake-app"' in home
    assert "Gérer les comptes" in home and "Ajouter une application" in home


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


def test_user_view_search_and_bulk_disable(ctx):
    client, service, _, audit = ctx
    login(client)
    token = csrf(client)
    client.post(
        "/apps/fake-app/accounts",
        data={"csrf": token, "user_key": "carol", "cred_username": "u", "cred_password": SECRET},
    )
    page = client.get("/users?q=CAR").text
    assert 'href="/users/carol"' in page and "1 actif(s)" in page
    assert "Aucun utilisateur ne correspond" in client.get("/users?q=zzz").text

    page = client.get("/users/carol").text
    assert "Appli factice" in page and "Tout désactiver" in page
    assert_no_leak(page)

    # Action depuis la vue utilisateur : retour sur cette vue.
    r = client.post(
        "/apps/fake-app/accounts/carol/status",
        data={"csrf": token, "status": "disabled", "back": "/users/carol"},
    )
    assert r.headers["location"] == "/users/carol"
    # Retour hors de l'administration refusé.
    r = client.post(
        "/apps/fake-app/accounts/carol/status",
        data={"csrf": token, "status": "active", "back": "https://evil.example/"},
    )
    assert r.headers["location"] == "/apps/fake-app"

    r = client.post("/users/carol/disable-all", data={"csrf": token})
    assert r.headers["location"] == "/users/carol"
    assert "1 compte(s)" in client.get("/users/carol").text
    assert audit.events[-1].reason == "disabled:admin_bulk"


def test_bulk_disable_requires_csrf(ctx):
    client, service, *_ = ctx
    login(client)
    client.post("/users/carol/disable-all", data={"csrf": "forged"})
    assert "CSRF" in client.get("/users/carol").text


GUIDED = {
    "id": "crm",
    "name": "CRM",
    "public_host": "crm.sesame.test",
    "base_url": "http://crm.interne:8080",
    "groups": "ventes",
    "form_url": "/login",
    "form_selector": "form",
    "username_field": "user",
    "password_field": "pass",
    "session_cookie": "CRMSESSID",
}


def editor_text(page: str) -> str:
    return html.unescape(re.search(r"<textarea[^>]*>(.*?)</textarea>", page, re.S).group(1))


def test_create_app_from_guided_form_then_edit_history_delete(ctx):
    client, service, _, audit = ctx
    login(client)
    token = csrf(client, "/apps/new")
    r = client.post("/apps/new", data={"csrf": token, **GUIDED})
    assert r.status_code == 200 and "Créer l'application" in r.text
    text = editor_text(r.text)
    assert "id: crm" in text and "user:\n" in text and service.audit.events[-1].action == "admin_login"

    r = client.post("/apps", data={"csrf": token, "descriptor": text, "check": "1"})
    assert "Descripteur valide" in r.text and not await_list(service)
    r = client.post("/apps", data={"csrf": token, "descriptor": text})
    assert r.status_code == 303 and r.headers["location"] == "/apps/crm"
    page = client.get("/apps/crm").text
    assert "créée" in page and "Modifier le descripteur" in page and "base" in page
    assert "CRM" in client.get("/").text

    r = client.get("/apps/crm/descriptor")
    assert 'name="revision" value="1"' in r.text
    changed = editor_text(r.text).replace("name: CRM", "name: CRM ventes")
    r = client.post("/apps/crm/descriptor", data={"csrf": token, "descriptor": changed, "revision": "1"})
    assert r.status_code == 303
    assert "révision 2" in client.get("/apps/crm").text
    # Deuxième onglet resté sur la révision 1 : refusé, rien n'est écrasé.
    r = client.post("/apps/crm/descriptor", data={"csrf": token, "descriptor": text, "revision": "1"})
    assert r.status_code == 422 and "entre-temps" in r.text

    history = client.get("/apps/crm/history").text
    assert history.count("<tr>") >= 3 and "modification" in history and "création" in history

    r = client.post("/apps/crm/delete", data={"csrf": token, "revision": "2"})
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert "supprimée" in client.get("/").text
    assert client.get("/apps/crm").status_code == 404
    assert [e.action for e in audit.events if e.action.startswith("descriptor_")] == [
        "descriptor_created",
        "descriptor_updated",
        "descriptor_updated",
        "descriptor_deleted",
    ]


def await_list(service):
    return asyncio.run(service.descriptors.list_descriptors())


def test_invalid_descriptor_is_reported_and_escaped(ctx):
    client, service, *_ = ctx
    login(client)
    token = csrf(client, "/apps/new")
    evil = descriptor_yaml(
        **{"name: Appli factice": "name: x\n  bogus: </textarea><script>alert(1)</script>"}
    )
    r = client.post("/apps", data={"csrf": token, "descriptor": evil})
    assert r.status_code == 422 and 'role="alert"' in r.text
    assert "<script>alert(1)" not in r.text and "&lt;/textarea&gt;" in r.text
    assert await_list(service) == []


def test_descriptor_writes_require_csrf(ctx):
    client, service, *_ = ctx
    login(client)
    r = client.post("/apps", data={"csrf": "forged", "descriptor": descriptor_yaml()})
    assert r.status_code == 400 and "CSRF" in r.text
    assert await_list(service) == []
    assert client.post("/apps/new", data={"csrf": "forged", **GUIDED}).status_code == 400


def test_git_descriptors_stay_read_only(ctx):
    client, *_ = ctx
    login(client)
    assert "Modifier le descripteur" not in client.get("/apps/fake-app").text
    assert client.get("/apps/fake-app/descriptor").status_code == 409


def test_rejected_descriptor_opens_in_the_editor(ctx):
    client, service, *_ = ctx
    login(client)
    doc = {"apiVersion": "sesame/v1", "kind": "AppDescriptor", "metadata": {"id": "old", "name": "Old"}}
    asyncio.run(service.descriptors.create_descriptor("old", doc, "x"))
    assert "Descripteurs écartés" in client.get("/").text
    r = client.get("/apps/old")
    assert r.status_code == 302 and r.headers["location"] == "/apps/old/descriptor"
    assert "id: old" in editor_text(client.get("/apps/old/descriptor").text)


def test_db_app_pages_do_not_leak_credentials(ctx):
    client, service, *_ = ctx
    login(client)
    token = csrf(client, "/apps/new")
    client.post("/apps", data={"csrf": token, "descriptor": descriptor_yaml()})
    client.post(
        "/apps/crm/accounts",
        data={"csrf": token, "user_key": "carol", "cred_username": "cdupont", "cred_password": SECRET},
    )
    assert service.secrets.entries[("crm", "carol")]["password"] == SECRET
    for path in ("/", "/apps/crm", "/apps/crm/descriptor", "/apps/crm/history", "/users/carol"):
        assert_no_leak(client.get(path).text)
    r = client.post("/apps/crm/delete", data={"csrf": token, "revision": "1"})
    assert "comptes" in client.get(r.headers["location"]).text


def test_brand_assets_are_public_and_used(ctx):
    client, *_ = ctx
    r = client.get("/static/logo-64.png")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    assert client.get("/static/banner.webp").status_code == 200
    assert client.get("/static/../web.py").status_code == 404
    page = client.get("/logged-out").text
    assert 'src="/static/banner.webp"' in page and 'href="/static/favicon-32.png"' in page


# --- Recorder (bouton « Analyser une page de login ») ----------------------------------

from sesame_admin.recorder import RecorderError, RecordingResult  # noqa: E402


class FakeRecorder:
    def __init__(self):
        self.calls = []
        self.result = RecordingResult(
            yaml="apiVersion: sesame/v1\n# descripteur proposé\n",
            summary=["formulaire : form#login"],
            todo=["spec.public.host : hôte public exposé par Sesame"],
            warnings=["login_submitted_by_javascript"],
            blocking=[],
            valid=False,
            errors=[],
        )
        self.error: str | None = None

    async def analyze(self, login_url, *, probe_failure=False):
        self.calls.append((login_url, probe_failure))
        if self.error:
            raise RecorderError(self.error)
        return self.result


def ctx_with_recorder(apps, recorder):
    audit = MemoryAuditSink()
    service = make_service(apps, audit)
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
        recorder=recorder,
    )
    client = TestClient(app, base_url="https://admin.test", follow_redirects=False)
    return client, service, audit


def test_analyze_prefills_editor_and_audits(apps):
    recorder = FakeRecorder()
    client, _, audit = ctx_with_recorder(apps, recorder)
    login(client)
    assert "Analyser une page de login" in client.get("/apps/new").text
    token = csrf(client, "/apps/new")
    r = client.post(
        "/apps/analyze",
        data={"csrf": token, "login_url": "https://crm.interne/login", "probe_failure": "on"},
    )
    assert r.status_code == 200
    assert "descripteur proposé" in r.text  # YAML pré-rempli dans l'éditeur
    assert "login_submitted_by_javascript" in r.text  # notes affichées
    assert recorder.calls == [("https://crm.interne/login", True)]
    assert audit.events[-1].action == "descriptor_recorded"
    assert audit.events[-1].outcome == "success"
    assert audit.events[-1].reason == "crm.interne"  # hôte seulement, pas l'URL complète


def test_analyze_reports_recorder_error(apps):
    recorder = FakeRecorder()
    recorder.error = "recorder injoignable (ConnectError)"
    client, _, audit = ctx_with_recorder(apps, recorder)
    login(client)
    token = csrf(client, "/apps/new")
    r = client.post("/apps/analyze", data={"csrf": token, "login_url": "https://crm.interne/login"})
    assert r.status_code == 303 and r.headers["location"] == "/apps/new"
    assert "Analyse impossible" in client.get("/apps/new").text
    assert audit.events[-1].action == "descriptor_recorded" and audit.events[-1].outcome == "failure"


def test_analyze_rejects_bad_url(apps):
    recorder = FakeRecorder()
    client, _, _ = ctx_with_recorder(apps, recorder)
    login(client)
    token = csrf(client, "/apps/new")
    r = client.post("/apps/analyze", data={"csrf": token, "login_url": "ftp://x/login"})
    assert r.status_code == 303
    assert recorder.calls == []
    assert "URL de login invalide" in client.get("/apps/new").text


def test_analyze_requires_csrf(apps):
    recorder = FakeRecorder()
    client, _, _ = ctx_with_recorder(apps, recorder)
    login(client)
    r = client.post("/apps/analyze", data={"csrf": "forged", "login_url": "https://crm.interne/login"})
    assert r.status_code == 400 and recorder.calls == []


def test_analyze_hidden_when_recorder_disabled(ctx):
    client, _, _, _ = ctx
    login(client)
    page = client.get("/apps/new").text
    assert "Analyser une page de login" not in page
    token = csrf(client, "/apps/new")
    r = client.post("/apps/analyze", data={"csrf": token, "login_url": "https://crm.interne/login"})
    assert r.status_code == 404
