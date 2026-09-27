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

    # Sans groupe : pas de spec.access (le compte suffit, ADR 0017) ; hôte public sous le
    # domaine configuré des applis (un exemple non résolu ferait échouer le navigateur).
    open_draft = record.to_descriptor(rec, app_id="crm", apps_domain="sesame.localhost:8443")
    assert descriptors.validate(open_draft.document) == []
    assert "access" not in open_draft.document["spec"]
    assert open_draft.document["spec"]["public"]["host"] == "crm.sesame.localhost:8443"
    assert not any("spec.public.host" in t for t in open_draft.todo)


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


def test_form_built_by_javascript_without_submission_is_blocking(client, browser):
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
    # Formulaire absent du HTML servi et aucune soumission observée (pas de bouton) : la
    # cible du rejeu sans formulaire est inconnue, c'est bloquant.
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


# --- Connexion réelle avec un compte de test (ADR 0019) --------------------------------


def test_test_account_completes_the_descriptor(fake, client, browser):
    """Formulaire classique : cookie de session et succès observés, descripteur rejouable tel quel."""
    from sesame_onboarding import verify

    rec = run(f"{fake.base}/login", client, browser, credentials=("amartin", "Pw-real"))
    assert fake.posts() == ["/login"], "une seule connexion réelle"
    assert rec.login.logged_in and rec.login.status == 302
    assert rec.login.session_cookies == ["FAKEAPPSESSID"]
    draft = record.to_descriptor(rec)
    assert "start_path" not in draft.document["spec"]["public"], "racine atteinte : rien à préciser"
    doc = draft.document
    assert descriptors.validate(doc) == []
    assert doc["spec"]["session"]["cookies"] == ["FAKEAPPSESSID"]
    assert doc["spec"]["login"]["success"]["any_of"][0]["cookie_set"] == "FAKEAPPSESSID"
    assert not any("spec.login.success" in t or "spec.session.cookies" in t for t in draft.todo)
    assert verify.verify(doc, {"username": "amartin", "password": "Pw-real"}, client).ok
    text = record.render(draft, rec) + "\n".join(record.summary(rec)) + repr(rec)
    assert "Pw-real" not in text and "amartin" not in text


def xsrf_spa_app() -> Flask:
    """SPA : jeton dans un cookie XSRF-TOKEN renvoyé en en-tête, JSON aux champs renommés,
    réponse 200 JSON qui pose le cookie de session."""
    app = Flask(__name__)
    tokens: set[str] = set()
    sessions: set[str] = set()

    @app.get("/login")
    def page():
        tok = f"xsrf-{len(tokens)}-7c1e9a"
        tokens.add(tok)
        html = (
            "<html><head><title>Famille</title></head><body><form id=f><input name=email type=email>"
            "<input type=password name=pass><button>Entrer</button></form><script>"
            "document.getElementById('f').addEventListener('submit', e => { e.preventDefault();"
            "const t = document.cookie.split('; ').find(c => c.startsWith('XSRF-TOKEN=')).split('=')[1];"
            "fetch('/api/auth/login', {method: 'POST', headers: {'Content-Type': 'application/json',"
            "'X-XSRF-TOKEN': t}, body: JSON.stringify({login: e.target.email.value,"
            "pwd: e.target.pass.value, remember: 'true'})}).then(r => { if (r.ok) location.href = '/'; });"
            "});</script></body></html>"
        )
        resp = Response(html)
        resp.set_cookie("XSRF-TOKEN", tok)
        return resp

    @app.post("/api/auth/login")
    def login():
        from flask import request

        if request.headers.get("X-XSRF-TOKEN") not in tokens or request.cookies.get(
            "XSRF-TOKEN"
        ) != request.headers.get("X-XSRF-TOKEN"):
            return Response(
                '{"error":"Jeton de sécurité invalide, rechargez la page."}',
                403,
                content_type="application/json",
            )
        body = request.get_json(silent=True) or {}
        if (body.get("login"), body.get("pwd")) != ("amartin@example.org", "Pw-SPA-real"):
            return Response('{"error":"bad"}', 401, content_type="application/json")
        sid = f"s{len(sessions)}"
        sessions.add(sid)
        resp = Response('{"ok":true}', content_type="application/json")
        resp.set_cookie("app_session", sid, httponly=True)
        return resp

    @app.get("/")
    def home():
        from flask import request

        if request.cookies.get("app_session") in sessions:
            return "<h1>Bienvenue</h1>"
        return Response("", 302, {"Location": "/login"})

    return app


def test_test_account_handles_javascript_login_with_cookie_token(client, browser):
    from sesame_onboarding import verify

    spa = Recorder(xsrf_spa_app())
    try:
        rec = run(f"{spa.base}/login", client, browser, credentials=("amartin@example.org", "Pw-SPA-real"))
        draft = record.to_descriptor(rec, app_id="famille")
        doc = draft.document
        login = doc["spec"]["login"]
        assert descriptors.validate(doc) == [], descriptors.validate(doc)
        assert (login["action"], login["encoding"]) == ("/api/auth/login", "json")
        assert login["csrf"] == [
            {"source": "cookie", "name": "XSRF-TOKEN", "send_as": {"header": "x-xsrf-token"}}
        ]
        assert login["fields"] == {
            "login": {"from_secret": "username"},
            "pwd": {"from_secret": "password"},
            "remember": {"value": "true"},
        }
        assert login["include_hidden_inputs"] is False
        assert doc["spec"]["session"]["cookies"] == ["app_session"]
        assert login["success"] == {"any_of": [{"status": [200], "cookie_set": "app_session"}]}
        creds = {"username": "amartin@example.org", "password": "Pw-SPA-real"}
        assert verify.verify(doc, creds, client).ok
        wrong = verify.verify(doc, {**creds, "password": "nope"}, client)
        assert not wrong.ok
    finally:
        spa.srv.shutdown()
    text = record.render(draft, rec) + "\n".join(record.summary(rec)) + repr(rec)
    assert "Pw-SPA-real" not in text and "amartin@example.org" not in text and "xsrf-0-7c1e9a" not in text


def inline_token_app() -> Flask:
    """Jeton seulement dans un script inline, envoyé en en-tête X-Csrf."""
    app = Flask(__name__)
    issued: set[str] = set()

    @app.get("/login")
    def page():
        tok = f"inl{len(issued)}Z9f3kQ2"
        issued.add(tok)
        return (
            f'<html><body><script>window.APP = {{csrfToken: "{tok}"}};</script>'
            "<form id=f><input name=user><input type=password name=password><button>Go</button></form>"
            "<script>document.getElementById('f').addEventListener('submit', e => { e.preventDefault();"
            "fetch('/session', {method: 'POST', headers: {'X-Csrf': window.APP.csrfToken,"
            "'Content-Type': 'application/x-www-form-urlencoded'},"
            "body: new URLSearchParams(new FormData(e.target))}).then(() => location.href = '/'); });"
            "</script></body></html>"
        )

    @app.post("/session")
    def session():
        from flask import request

        if request.headers.get("X-Csrf") not in issued:
            return Response("csrf", 403)
        if (request.form.get("user"), request.form.get("password")) != ("bob", "Pw-inline"):
            return Response("bad", 401)
        resp = Response("", 204)
        resp.set_cookie("SID", "ok-session")
        return resp

    @app.get("/")
    def home():
        from flask import request

        return (
            "ok" if request.cookies.get("SID") == "ok-session" else Response("", 302, {"Location": "/login"})
        )

    return app


def test_test_account_finds_a_token_in_an_inline_script(client, browser):
    from sesame_onboarding import verify

    app = Recorder(inline_token_app())
    try:
        rec = run(f"{app.base}/login", client, browser, credentials=("bob", "Pw-inline"))
        doc = record.to_descriptor(rec, app_id="inline").document
        token = doc["spec"]["login"]["csrf"][0]
        assert (token["source"], token["send_as"]) == ("regex", {"header": "x-csrf"})
        assert descriptors.validate(doc) == [], descriptors.validate(doc)
        assert verify.verify(doc, {"username": "bob", "password": "Pw-inline"}, client).ok
    finally:
        app.srv.shutdown()
    assert "inl0Z9f3kQ2" not in repr(rec) + record.render(record.to_descriptor(rec), rec)


def test_wrong_test_account_is_reported(fake, client, browser):
    rec = run(f"{fake.base}/login", client, browser, credentials=("amartin", "wrong"))
    assert rec.login is not None and not rec.login.logged_in
    assert any("test_login_still_on_login_page" in w for w in rec.warnings)
    assert any("spec.login.success" in t for t in record.to_descriptor(rec).todo)


def api_token_app() -> Flask:
    """Comme familly-chat : jeton lié à la session, obtenu par GET /api/csrf-token, envoyé en
    en-tête x-csrf-token avec un login JSON."""
    from flask import request

    app = Flask(__name__)
    by_session: dict[str, str] = {}
    logged: set[str] = set()

    @app.get("/login")
    def page():
        sid = f"pre{len(by_session)}"
        by_session[sid] = f"api-tok-{len(by_session)}-9d2f"
        resp = Response(
            "<html><body><form id=f><input name=username><input type=password name=password>"
            "<button>Connexion</button></form><script>"
            "let tok; fetch('/api/csrf-token').then(r => r.json()).then(j => tok = j.csrfToken);"
            "document.getElementById('f').addEventListener('submit', e => { e.preventDefault();"
            "fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json',"
            "'x-csrf-token': tok}, body: JSON.stringify({username: e.target.username.value,"
            "password: e.target.password.value})}).then(r => { if (r.ok) location.href = '/chat'; });"
            "});</script></body></html>"
        )
        resp.set_cookie("chat.sid", sid)
        return resp

    @app.get("/api/csrf-token")
    def token():
        sid = request.cookies.get("chat.sid")
        if sid not in by_session:
            return Response('{"error":"no session"}', 401, content_type="application/json")
        return {"csrfToken": by_session[sid]}

    @app.post("/api/login")
    def login():
        sid = request.cookies.get("chat.sid")
        if sid not in by_session or request.headers.get("x-csrf-token") != by_session[sid]:
            return Response(
                '{"error":"Jeton de sécurité invalide, rechargez la page."}',
                403,
                content_type="application/json",
            )
        body = request.get_json(silent=True) or {}
        if (body.get("username"), body.get("password")) != ("alice", "Pw-chat"):
            return Response('{"error":"Identifiants invalides"}', 401, content_type="application/json")
        logged.add(sid)
        resp = Response('{"ok":true}', content_type="application/json")
        resp.set_cookie("chat.sid", sid + "-auth")
        logged.add(sid + "-auth")
        return resp

    @app.get("/chat")
    def chat():
        return (
            "chat" if request.cookies.get("chat.sid") in logged else Response("", 302, {"Location": "/login"})
        )

    # Comme familly-chat : la racine affiche le login même une fois connecté.
    app.add_url_rule("/", "root", page)
    return app


def test_test_account_handles_a_token_obtained_from_an_api(client, browser):
    from sesame_onboarding import verify

    app = Recorder(api_token_app())
    try:
        rec = run(f"{app.base}/login", client, browser, credentials=("alice", "Pw-chat"))
        draft = record.to_descriptor(rec, app_id="familly-chat")
        doc = draft.document
        assert descriptors.validate(doc) == [], descriptors.validate(doc)
        assert doc["spec"]["login"]["csrf"] == [
            {
                "source": "endpoint",
                "url": "/api/csrf-token",
                "name": "csrfToken",
                "send_as": {"header": "x-csrf-token"},
            }
        ]
        assert not any(w.startswith("csrf_") for w in rec.warnings), rec.warnings
        assert doc["spec"]["session"]["cookies"] == ["chat.sid"]
        assert doc["spec"]["public"]["start_path"] == "/chat", "tuile vers la page atteinte après connexion"
        assert verify.verify(doc, {"username": "alice", "password": "Pw-chat"}, client).ok
        assert verify.verify(doc, {"username": "alice", "password": "nope"}, client).reason != "ok"
    finally:
        app.srv.shutdown()
    assert "api-tok-" not in repr(rec) + record.render(draft, rec) + "\n".join(record.summary(rec))


def test_login_form_rendered_late_by_javascript_is_found(client, browser):
    """Formulaire inséré par le JavaScript après le chargement (SPA lente) : attendu, pas manqué."""
    app = Flask(__name__)

    @app.get("/login")
    def page():
        return (
            "<html><body><div id=root>Chargement…</div><script>setTimeout(() => {"
            "document.getElementById('root').innerHTML = '<form id=late action=/login method=post>"
            "<input name=user><input type=password name=pw><button>OK</button></form>'; }, 1500);"
            "</script></body></html>"
        )

    @app.post("/login")
    def submit():
        return Response("", 401)

    srv = Recorder(app)
    try:
        rec = run(f"{srv.base}/login", client, browser)
    finally:
        srv.srv.shutdown()
    assert (rec.form_selector, rec.password_field) == ("form#late", "pw")
    assert "login_form_not_found" not in rec.blocking
    assert not rec.use_form, "formulaire absent du HTML servi : rejeu sans formulaire"


def react_app() -> Flask:
    """Comme YAST : page React, champs sans attribut name, login JSON, puis /dashboard."""
    from flask import request

    app = Flask(__name__)
    sessions: set[str] = set()

    @app.get("/login")
    def page():
        return (
            "<html><body><div id=root></div><script>setTimeout(() => {"
            "document.getElementById('root').innerHTML = '<form class=space-y-4><div><label>Email</label>"
            "<input type=email required></div><div><label>Mot de passe</label><input type=password required>"
            "</div><button type=submit>Se connecter</button></form>';"
            "document.querySelector('form').addEventListener('submit', e => { e.preventDefault();"
            "const [m, p] = e.target.querySelectorAll('input');"
            "fetch('/api/auth/login', {method: 'POST', headers: {'Content-Type': 'application/json'},"
            "body: JSON.stringify({email: m.value, password: p.value})})"
            ".then(r => { if (r.ok) location.href = '/dashboard'; }); }); }, 300);</script></body></html>"
        )

    @app.post("/api/auth/login")
    def login():
        body = request.get_json(silent=True) or {}
        if (body.get("email"), body.get("password")) != ("admin@yast.test", "Pw-yast"):
            return Response('{"error":"Identifiants invalides"}', 401, content_type="application/json")
        sid = f"t{len(sessions)}"
        sessions.add(sid)
        resp = Response('{"ok":true}', content_type="application/json")
        resp.set_cookie("token", sid, httponly=True)
        return resp

    @app.get("/dashboard")
    def dashboard():
        if request.cookies.get("token") in sessions:
            return "<h1>Tableau de bord</h1>"
        return Response("", 302, {"Location": "/login"})

    app.add_url_rule("/", "root", page)
    return app


def test_react_form_with_unnamed_fields(client, browser):
    """Champs sans name, formulaire construit en JavaScript : noms réels lus dans la requête."""
    from sesame_onboarding import verify

    app = Recorder(react_app())
    try:
        dry = run(f"{app.base}/login", client, browser)
        assert (dry.username_field, dry.password_field) == ("#0", "#1")
        assert dry.blocking == [], dry.blocking
        dry_login = record.to_descriptor(dry).document["spec"]["login"]
        assert dry_login["fields"] == {
            "email": {"from_secret": "username"},
            "password": {"from_secret": "password"},
        }
        assert (dry_login["use_form"], dry_login["action"], dry_login["encoding"]) == (
            False,
            "/api/auth/login",
            "json",
        )

        rec = run(f"{app.base}/login", client, browser, credentials=("admin@yast.test", "Pw-yast"))
        doc = record.to_descriptor(rec, app_id="yast").document
        assert descriptors.validate(doc) == [], descriptors.validate(doc)
        assert doc["spec"]["session"]["cookies"] == ["token"]
        assert doc["spec"]["public"]["start_path"] == "/dashboard"
        creds = {"username": "admin@yast.test", "password": "Pw-yast"}
        assert verify.verify(doc, creds, client).ok
        assert not verify.verify(doc, {**creds, "password": "nope"}, client).ok
    finally:
        app.srv.shutdown()
    assert "#0" not in str(doc["spec"]["login"]["fields"])


def test_token_based_session_is_reported_by_name(client, browser):
    """Comme YAST : jeton renvoyé dans la réponse JSON, aucun cookie. Signalé, sans valeur."""
    from flask import request

    app = Flask(__name__)
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjJ9.c2lnbmF0dXJlLXRlc3Q"

    @app.get("/login")
    def page():
        return (
            "<html><body><form id=f><input type=email><input type=password><button>OK</button></form>"
            "<script>document.getElementById('f').addEventListener('submit', e => { e.preventDefault();"
            "const [m, p] = e.target.querySelectorAll('input');"
            "fetch('/api/auth/login', {method: 'POST', headers: {'Content-Type': 'application/json'},"
            "body: JSON.stringify({email: m.value, password: p.value})}).then(r => r.json())"
            ".then(j => { window.token = j.accessToken; document.body.innerHTML = '<h1>OK</h1>'; }); });"
            "</script></body></html>"
        )

    @app.post("/api/auth/login")
    def login():
        body = request.get_json(silent=True) or {}
        if body.get("password") != "Pw-tok":
            return Response('{"error":"bad"}', 401, content_type="application/json")
        return {"accessToken": jwt, "refreshToken": "r" * 40, "user": {"id": 2, "name": "kevin"}}

    srv = Recorder(app)
    try:
        rec = run(f"{srv.base}/login", client, browser, credentials=("k@yast.test", "Pw-tok"))
    finally:
        srv.srv.shutdown()
    blocking = " ".join(rec.blocking)
    assert "session_token_in_response: accessToken, refreshToken" in blocking, rec.blocking
    text = repr(rec) + "\n".join(record.summary(rec)) + record.render(record.to_descriptor(rec), rec)
    assert jwt not in text and "r" * 40 not in text


def test_handoff_descriptor_for_a_token_session(client, browser):
    """Avec handoff=True, une session par jeton produit un descripteur handoff valide,
    local_storage sur les champs de jeton détectés, sans cookie (ADR 0020)."""
    app = Recorder(token_session_app())
    try:
        rec = run(f"{app.base}/login", client, browser, credentials=("k@yast.test", "Pw-tok"))
    finally:
        app.srv.shutdown()
    assert rec.session_token_keys, "jeton détecté"
    doc = record.to_descriptor(rec, app_id="yast", handoff=True).document
    assert descriptors.validate(doc) == [], descriptors.validate(doc)
    session = doc["spec"]["session"]
    assert session["mode"] == "handoff"
    assert "cookies" not in session
    keys = [i["key"] for i in session["handoff"]["local_storage"]]
    assert "accessToken" in keys or "refreshToken" in keys
    # Sans handoff : reste bloquant (proxy ne gère pas), pas de mode handoff.
    proxy_doc = record.to_descriptor(rec, app_id="yast").document
    assert proxy_doc["spec"]["session"].get("mode", "proxy") == "proxy"


def token_session_app() -> Flask:
    from flask import request

    app = Flask(__name__)
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjJ9.c2lnbmF0dXJlLXlhc3Q"

    @app.get("/login")
    def page():
        return (
            "<html><body><form id=f><input type=email><input type=password><button>OK</button></form>"
            "<script>document.getElementById('f').addEventListener('submit', e => { e.preventDefault();"
            "const [m, p] = e.target.querySelectorAll('input');"
            "fetch('/api/auth/login', {method: 'POST', headers: {'Content-Type': 'application/json'},"
            "body: JSON.stringify({email: m.value, password: p.value})}).then(r => r.json())"
            ".then(j => { window.token = j.accessToken; document.body.innerHTML = '<h1>OK</h1>'; }); });"
            "</script></body></html>"
        )

    @app.post("/api/auth/login")
    def login():
        body = request.get_json(silent=True) or {}
        if body.get("password") != "Pw-tok":
            return Response('{"error":"bad"}', 401, content_type="application/json")
        return {"accessToken": jwt, "refreshToken": "r" * 40}

    return app
