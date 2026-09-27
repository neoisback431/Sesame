# SPDX-License-Identifier: Apache-2.0
import re
import time

import pytest
from fake_app.app import PRELOGIN_COOKIE, SESSION_COOKIE, create_app, parse_users


@pytest.fixture
def client():
    return create_app(users={"alice": "alice-pw"}, session_ttl=60).test_client()


def csrf_token(client) -> str:
    html = client.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, password="alice-pw", token=None):
    token = token if token is not None else csrf_token(client)
    return client.post(
        "/login",
        data={"csrf_token": token, "lang": "fr", "username": "alice", "password": password},
    )


def test_parse_users():
    assert parse_users("alice:a, bob:b:c,,bad") == {"alice": "a", "bob": "b:c"}


def test_unauthenticated_redirects_to_login(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/login"
    assert client.get("/api/whoami").status_code == 401


def test_login_success_sets_session(client):
    resp = login(client)
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/"
    assert client.get_cookie(SESSION_COOKIE) is not None
    assert client.get("/api/whoami").get_json() == {"user": "alice"}


def test_login_rejects_bad_csrf(client):
    csrf_token(client)
    assert login(client, token="forged").status_code == 403


def test_csrf_token_is_single_use(client):
    token = csrf_token(client)
    assert login(client, token=token).status_code == 302
    client.set_cookie(PRELOGIN_COOKIE, "replayed")
    assert login(client, token=token).status_code == 403


def test_login_rejects_bad_password(client):
    resp = login(client, password="wrong")
    assert resp.status_code == 401
    assert "Identifiants invalides" in resp.get_data(as_text=True)


def test_session_expires():
    client = create_app(users={"alice": "alice-pw"}, session_ttl=0).test_client()
    login(client)
    time.sleep(0.01)
    assert client.get("/").status_code == 302


def test_logout_invalidates_session(client):
    login(client)
    client.get("/logout")
    assert client.get("/api/whoami").status_code == 401
