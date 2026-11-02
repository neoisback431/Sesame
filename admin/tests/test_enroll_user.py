# SPDX-License-Identifier: Apache-2.0
"""Enrôlement d'un utilisateur par sa clé SSO, avant sa première connexion (ADR 0035)."""

import pytest
from fastapi.testclient import TestClient
from sesame_admin.audit import MemoryAuditSink
from sesame_admin.ports import UserProfile
from sesame_admin.web import create_app

from .conftest import make_service
from .test_web import FakeAuth, csrf, login

KEY = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"


@pytest.fixture
def web(apps):
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
    )
    client = TestClient(app, base_url="https://admin.test", follow_redirects=False)
    login(client)
    return client, service, audit


def test_enrolled_user_is_listed_and_proposed_without_any_login(web):
    client, service, audit = web
    token = csrf(client, "/users")
    r = client.post(
        "/users",
        data={"csrf": token, "user_key": f" {KEY} ", "display_name": "Dana Roy", "email": "d@example.org"},
    )
    assert r.status_code == 303 and r.headers["location"] == f"/users/{KEY}"
    assert service.accounts.profiles[KEY] == UserProfile("Dana Roy", "d@example.org")
    assert (audit.events[-1].action, audit.events[-1].outcome) == ("user_enrolled", "success")
    assert audit.events[-1].target_user == KEY

    listing = client.get("/users").text
    assert "Dana Roy" in listing and KEY in listing  # connu bien que sans compte
    assert KEY in client.get("/apps/fake-app").text  # proposé au provisionnement
    detail = client.get(f"/users/{KEY}").text
    assert f"/apps/fake-app?user_key={KEY}" in detail  # accès direct au formulaire de compte


def test_enrolling_again_keeps_known_name_and_email(web):
    client, service, _ = web
    token = csrf(client, "/users")
    client.post(
        "/users", data={"csrf": token, "user_key": KEY, "display_name": "Dana Roy", "email": "d@example.org"}
    )
    client.post("/users", data={"csrf": token, "user_key": KEY})
    assert service.accounts.profiles[KEY] == UserProfile("Dana Roy", "d@example.org")


@pytest.mark.parametrize(
    "data", [{"user_key": "a b"}, {"user_key": "../x"}, {"user_key": KEY, "email": "pas-un-mail"}]
)
def test_invalid_input_is_refused_and_nothing_is_stored(web, data):
    client, service, audit = web
    token = csrf(client, "/users")
    r = client.post("/users", data={"csrf": token, **data})
    assert r.status_code == 303 and r.headers["location"] == "/users"
    assert service.accounts.profiles == {}
    assert all(e.action != "user_enrolled" for e in audit.events)


def test_csrf_is_required(web):
    client, service, _ = web
    r = client.post("/users", data={"csrf": "forged", "user_key": KEY})
    assert r.status_code == 303 and r.headers["location"] == "/users"
    assert service.accounts.profiles == {}
