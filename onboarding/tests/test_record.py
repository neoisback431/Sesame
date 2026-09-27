# SPDX-License-Identifier: Apache-2.0
"""Recorder : analyse d'une page de login dans un navigateur headless, sans identifiant.

Ignorés si aucun Chromium utilisable (``SESAME_ONBOARD_CHROMIUM`` ou navigateurs Playwright).
"""

import glob
import os
import re

import pytest
from flask import Flask, Response
from sesame_onboarding import descriptors, record

from .conftest import ROOT, create_app, js_only_app, serve

playwright = pytest.importorskip("playwright.sync_api")

DUMMY_USER, DUMMY_PASSWORD = "sesame-recorder-test", "Dummy-Pw-7731-never-shown"


def chromium_path() -> str | None:
    explicit = os.environ.get("SESAME_ONBOARD_CHROMIUM")
    if explicit:
        return explicit
    found = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))
    return found[-1] if found else None


@pytest.fixture(scope="module")
def browser():
    with playwright.sync_playwright() as p:
        try:
            b = p.chromium.launch(executable_path=chromium_path())
        except playwright.Error as e:
            pytest.skip(f"Chromium indisponible : {str(e).splitlines()[0]}")
        yield b
        b.close()


@pytest.fixture(autouse=True)
def fixed_dummy(monkeypatch):
    monkeypatch.setattr(record, "dummy_credentials", lambda: (DUMMY_USER, DUMMY_PASSWORD))


class Recorder:
    """Appli servie en processus, avec le journal des requêtes reçues."""

    def __init__(self, app):
        self.requests: list[tuple[str, str]] = []
        inner = app.wsgi_app

        def wsgi(environ, start_response):
            self.requests.append((environ["REQUEST_METHOD"], environ["PATH_INFO"]))
            return inner(environ, start_response)

        app.wsgi_app = wsgi
        self.app = app
        self.srv, self.base = serve(app)

    def posts(self) -> list[str]:
        return [path for method, path in self.requests if method != "GET"]


@pytest.fixture
def fake():
    app = create_app(users={"amartin": "Pw-real"}, session_ttl=60)
    r = Recorder(app)
    yield r
    r.srv.shutdown()


def run(url, client, browser, **kw):
    return record.record(url, client, browser, timeout=10, **kw)


def test_fake_app_without_any_login_attempt(fake, client, browser):
    rec = run(f"{fake.base}/login", client, browser)
    assert fake.posts() == [], "la soumission est interceptée : rien n'atteint l'appli"
    assert rec.blocking == [] and rec.raw_form_found
    assert (rec.form_selector, rec.username_field, rec.password_field) == (
        "form#login-form",
        "username",
        "password",
    )
    assert rec.hidden_fields == ["csrf_token", "lang"]
    assert rec.csrf == [{"source": "hidden_input", "name": "csrf_token"}]
    assert rec.submission.method == "POST" and rec.submission.encoding == "form"
    assert set(rec.submission.field_names) == {"csrf_token", "lang", "username", "password"}
    assert (rec.protected_status, rec.protected_location) == (302, "/login")
    assert rec.failure is None

    draft = record.to_descriptor(rec, app_id="fake-app", groups=["fake-app-users"])
    assert descriptors.validate(draft.document) == []
    reference = descriptors.load(ROOT / "descriptors" / "fake-app.yaml")
    login = draft.document["spec"]["login"]
    assert login["form_selector"] == reference["spec"]["login"]["form_selector"]
    assert login["fields"] == reference["spec"]["login"]["fields"]
    assert login["csrf"] == reference["spec"]["login"]["csrf"]
    fp = draft.document["spec"]["health"]["form_fingerprint"]
    assert fp == reference["spec"]["health"]["form_fingerprint"]
    expiry = draft.document["spec"]["expiry"]["any_of"][0]["location_matches"]
    assert re.search(expiry, "/login") and re.search(expiry, f"{fake.base}/login?next=/")
    assert any("session.cookies" in t for t in draft.todo)


def test_failure_probe_observes_the_rejection(fake, client, browser):
    rec = run(f"{fake.base}/login", client, browser, probe_failure=True)
    assert fake.posts() == ["/login"], "une seule tentative, avec l'identifiant factice"
    assert rec.failure.status == 401 and rec.failure.message == "Identifiants invalides"
    failure = record.to_descriptor(rec).document["spec"]["login"]["failure"]
    assert failure == {"any_of": [{"status": [401], "body_contains": "Identifiants invalides"}]}


def test_generated_descriptor_logs_in_with_verify(fake, client, browser):
    """Complété du seul cookie de session, le descripteur proposé rejoue un vrai login."""
    from sesame_onboarding import verify

    rec = run(f"{fake.base}/login", client, browser, probe_failure=True)
    draft = record.to_descriptor(rec, session_cookie="FAKEAPPSESSID")
    result = verify.verify(draft.document, {"username": "amartin", "password": "Pw-real"}, client)
    assert result.ok, result
    wrong = verify.verify(draft.document, {"username": "amartin", "password": "nope"}, client)
    assert wrong.reason == "login_rejected"


def spa_app() -> Flask:
    """Login en JavaScript : JSON par fetch, jeton CSRF d'une balise meta envoyé en en-tête."""
    app = Flask(__name__)

    @app.get("/signin")
    def page():
        return (
            '<html><head><title>Portail RH</title><meta name="csrf-token" content="meta-tok-5531">'
            "</head><body><form id=f><input name=email type=email autocomplete=username>"
            "<input type=password name=secret><button>Entrer</button></form><script>"
            "document.getElementById('f').addEventListener('submit', e => { e.preventDefault();"
            "fetch('/api/session', {method: 'POST', headers: {'Content-Type': 'application/json',"
            "'X-CSRF-Token': document.querySelector('meta[name=csrf-token]').content},"
            "body: JSON.stringify({email: e.target.email.value, secret: e.target.secret.value,"
            "tz: 'Europe/Paris'})}); });</script></body></html>"
        )

    @app.post("/api/session")
    def session():
        return Response('{"error":"bad"}', status=401, content_type="application/json")

    @app.get("/")
    def home():
        return Response("", status=401)

    return app


def test_javascript_login_is_analyzed_without_leaking_values(client, browser):
    spa = Recorder(spa_app())
    try:
        rec = run(f"{spa.base}/signin", client, browser)
    finally:
        spa.srv.shutdown()
    assert spa.posts() == []
    assert (rec.username_field, rec.password_field, rec.form_selector) == ("email", "secret", "form#f")
    assert rec.encoding == "json" and rec.action == "/api/session"
    assert rec.csrf == [{"source": "meta", "name": "csrf-token", "send_as": {"header": "x-csrf-token"}}]
    assert "login_submitted_by_javascript" in rec.warnings
    assert "fields_added_on_submit: tz" in rec.warnings
    draft = record.to_descriptor(rec, app_id="rh")
    assert descriptors.validate(draft.document) == []
    assert draft.document["metadata"]["name"] == "Portail RH"

    # Un identifiant fourni en camelCase est normalisé (schéma : minuscules-tirets).
    normalized = record.to_descriptor(rec, app_id="monAppli")
    assert normalized.document["metadata"]["id"] == "monappli"
    assert descriptors.validate(normalized.document) == []
    assert any("normalisé" in item for item in normalized.todo)
    assert {"status": [401]} in draft.document["spec"]["expiry"]["any_of"]
    text = record.render(draft, rec) + "\n".join(record.summary(rec)) + repr(rec)
    assert "meta-tok-5531" not in text and DUMMY_PASSWORD not in text and DUMMY_USER not in text


def test_form_built_by_javascript_is_blocking(client, browser):
    app = js_only_app()

    @app.get("/")
    def home():
        return Response("", status=302, headers={"location": "/login"})

    # La page n'appelle qu'une fonction absente : on la fournit pour construire le formulaire.
    inner = app.view_functions["page"]
    app.view_functions["page"] = lambda: inner().replace(
        "<script>",
        "<script>function renderLoginForm(){document.getElementById('root').innerHTML="
        "'<form method=post><input name=u><input type=password name=p></form>'}</script><script>",
    )
    srv, base = serve(app)
    try:
        rec = run(f"{base}/login", client, browser)
    finally:
        srv.shutdown()
    assert rec.password_field == "p"
    assert "login_form_not_found_in_raw_html" in rec.blocking


def test_login_page_on_another_origin_is_blocking(client, browser):
    target = Recorder(spa_app())
    app = Flask(__name__)

    @app.get("/login")
    def away():
        return Response("", status=302, headers={"location": f"{target.base}/signin"})

    srv, base = serve(app)
    try:
        rec = run(f"{base}/login", client, browser)
    finally:
        srv.shutdown()
        target.srv.shutdown()
    assert rec.blocking == ["login_page_redirects_away"] and rec.password_field is None


def test_invalid_url_is_refused(client, browser):
    with pytest.raises(record.RecordError):
        run("file:///etc/passwd", client, browser)


def test_failure_message_echoing_the_dummy_login_is_ignored(client, browser):
    app = Flask(__name__)

    @app.get("/login")
    def page():
        return "<form method=post><input name=user><input type=password name=pw><button>OK</button></form>"

    @app.post("/login")
    def submit():
        from flask import request as req

        name = req.form.get("user", "")
        return Response(f'<p class="error">Compte {name} inconnu</p>', status=403)

    target = Recorder(app)
    try:
        rec = run(f"{target.base}/login", client, browser, probe_failure=True)
    finally:
        target.srv.shutdown()
    assert target.posts() == ["/login"]
    assert rec.failure.status == 403 and rec.failure.message is None
    assert record.to_descriptor(rec).document["spec"]["login"]["failure"] == {"any_of": [{"status": [403]}]}
