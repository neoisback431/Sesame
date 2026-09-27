# SPDX-License-Identifier: Apache-2.0
"""Appli factice : sessions et jetons CSRF gardés en mémoire (un seul worker)."""

from __future__ import annotations

import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from html import escape

from flask import Flask, Response, jsonify, redirect, request

SESSION_COOKIE = "FAKEAPPSESSID"
PRELOGIN_COOKIE = "FAKEAPPPRE"


@dataclass
class Store:
    users: dict[str, str]
    session_ttl: int
    # identifiant de session -> (utilisateur, expiration)
    sessions: dict[str, tuple[str, float]] = field(default_factory=dict)
    # identifiant de pré-session -> jeton CSRF attendu
    csrf: dict[str, str] = field(default_factory=dict)

    def user_for(self, sid: str | None) -> str | None:
        if not sid or sid not in self.sessions:
            return None
        user, expires = self.sessions[sid]
        if time.monotonic() > expires:
            del self.sessions[sid]
            return None
        return user


def parse_users(raw: str) -> dict[str, str]:
    users = {}
    for entry in filter(None, (e.strip() for e in raw.split(","))):
        name, _, password = entry.partition(":")
        if name and password:
            users[name] = password
    return users


def page(title: str, body: str, status: int = 200) -> Response:
    html = (
        '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
        f"<title>{escape(title)}</title></head><body>{body}</body></html>"
    )
    return Response(html, status=status, mimetype="text/html")


def create_app(users: dict[str, str] | None = None, session_ttl: int | None = None) -> Flask:
    app = Flask(__name__)
    store = Store(
        users=users if users is not None else parse_users(os.environ.get("FAKE_APP_USERS", "")),
        session_ttl=(
            session_ttl if session_ttl is not None else int(os.environ.get("FAKE_APP_SESSION_TTL", "300"))
        ),
    )
    app.extensions["fake_app_store"] = store
    # URL interne volontairement absolue dans les pages, pour tester la réécriture.
    internal_url = os.environ.get("FAKE_APP_INTERNAL_URL", "http://fake-app:8000")

    def current_user() -> str | None:
        return store.user_for(request.cookies.get(SESSION_COOKIE))

    def login_form(error: str = "", status: int = 200) -> Response:
        pre_id = secrets.token_urlsafe(16)
        token = secrets.token_urlsafe(32)
        store.csrf[pre_id] = token
        message = f'<p class="error">{escape(error)}</p>' if error else ""
        resp = page(
            "Connexion",
            "<h1>Connexion</h1>"
            f"{message}"
            '<form id="search-form" action="/search" method="get"><input name="q"></form>'
            '<form id="login-form" action="/login" method="post">'
            f'<input type="hidden" name="csrf_token" value="{token}">'
            '<input type="hidden" name="lang" value="fr">'
            '<label>Utilisateur <input name="username"></label>'
            '<label>Mot de passe <input type="password" name="password"></label>'
            '<button type="submit">Se connecter</button>'
            "</form>",
            status=status,
        )
        resp.set_cookie(PRELOGIN_COOKIE, pre_id, httponly=True, samesite="Lax")
        return resp

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/login")
    def login_get():
        return login_form()

    @app.post("/login")
    def login_post():
        expected = store.csrf.pop(request.cookies.get(PRELOGIN_COOKIE, ""), None)
        submitted = request.form.get("csrf_token", "")
        if expected is None or not hmac.compare_digest(expected, submitted):
            return page("Erreur", "<h1>Jeton CSRF invalide</h1>", status=403)
        if request.form.get("lang") != "fr":
            return page("Erreur", "<h1>Champ caché manquant</h1>", status=400)
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        known = store.users.get(username)
        if known is None or not hmac.compare_digest(known, password):
            return login_form("Identifiants invalides", status=401)
        sid = secrets.token_urlsafe(32)
        store.sessions[sid] = (username, time.monotonic() + store.session_ttl)
        resp = redirect("/", code=302)
        resp.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="Lax")
        resp.delete_cookie(PRELOGIN_COOKIE)
        return resp

    @app.get("/logout")
    def logout():
        store.sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
        resp = redirect("/login", code=302)
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    @app.get("/")
    def home():
        user = current_user()
        if user is None:
            return redirect("/login", code=302)
        return page(
            "Accueil",
            f"<h1>Bonjour {escape(user)}</h1>"
            f'<p><a href="{internal_url}/account">Mon compte (URL absolue)</a></p>'
            '<p><a href="/logout">Se déconnecter</a></p>',
        )

    @app.get("/account")
    def account():
        user = current_user()
        if user is None:
            return redirect("/login", code=302)
        return page("Compte", f"<h1>Compte de {escape(user)}</h1>")

    @app.get("/api/whoami")
    def whoami():
        user = current_user()
        if user is None:
            return jsonify(error="unauthenticated"), 401
        return jsonify(user=user)

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8000)
