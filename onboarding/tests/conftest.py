# SPDX-License-Identifier: Apache-2.0
"""Applis cibles servies en processus (WSGI), et descripteurs de test."""

import copy
import sys
import threading
from pathlib import Path

import httpx
import pytest
from flask import Flask, Response, request
from sesame_onboarding import descriptors
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "dev" / "fake-app"))

from fake_app.app import create_app  # noqa: E402

APP_PASSWORD = "Pw-ONBOARD-4242"


def serve(app):
    srv = make_server("127.0.0.1", 0, app)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


@pytest.fixture
def fake_app():
    srv, base = serve(create_app(users={"amartin": APP_PASSWORD}, session_ttl=60))
    yield base
    srv.shutdown()


@pytest.fixture
def fake_descriptor(fake_app):
    d = copy.deepcopy(descriptors.load(ROOT / "descriptors" / "fake-app.yaml"))
    d["spec"]["upstream"]["base_url"] = fake_app
    return d


def meta_csrf_app() -> Flask:
    """Jeton CSRF dans une balise meta, renvoyé en en-tête ; succès en 200 + cookie."""
    app = Flask(__name__)

    @app.get("/signin")
    def page():
        resp = Response(
            '<html><head><meta name="csrf-token" content="tok-9"></head><body>'
            '<form method="post" action="/signin"><input name="login">'
            '<input type="password" name="pwd"><input type="checkbox" name="remember" value="1"></form>'
            "</body></html>"
        )
        return resp

    @app.post("/signin")
    def submit():
        if request.headers.get("X-CSRF-Token") != "tok-9":
            return Response("csrf", status=403)
        if request.form.get("login") != "u1" or request.form.get("pwd") != APP_PASSWORD:
            return Response("Mot de passe incorrect")
        resp = Response("Bienvenue")
        resp.set_cookie("SID", "s-1")
        return resp

    return app


def js_only_app() -> Flask:
    app = Flask(__name__)

    @app.get("/login")
    def page():
        return "<html><body><div id=root></div><script>renderLoginForm()</script></body></html>"

    return app


@pytest.fixture
def client():
    with httpx.Client(follow_redirects=False, timeout=5, trust_env=False) as c:
        yield c
