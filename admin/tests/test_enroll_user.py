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


# --- Enrôlement par e-mail, rattaché à la première connexion (ADR 0036) ---------------------


def post_email(client, email, token=None, **extra):
    token = token or csrf(client, "/users")
    return client.post("/users", data={"csrf": token, "mode": "email", "email": email, **extra})


def test_email_enrolment_stores_the_lowercase_email_as_key_and_audits(web):
    client, service, audit = web
    r = post_email(client, "Dana.Roy@Example.org", display_name="Dana Roy")
    assert r.status_code == 303 and r.headers["location"] == "/users/dana.roy@example.org"
    key = "dana.roy@example.org"
    assert service.accounts.profiles[key] == UserProfile("Dana Roy", key)
    assert key in service.accounts.enrolment_entries
    event = audit.events[-1]
    assert (event.action, event.outcome, event.reason, event.target_user) == (
        "user_enrolled",
        "success",
        "email",
        key,
    )
    page = client.get(f"/users/{key}").text
    assert "en attente de première connexion" in page
    assert f"/apps/fake-app?user_key={key}" in page  # comptes ajoutés sous la clé e-mail
    assert key in client.get("/users").text


def test_a_claimed_enrolment_shows_when_it_was_linked(web):
    from datetime import UTC, datetime

    from sesame_admin.ports import Enrolment

    client, service, _ = web
    post_email(client, "dana@example.org")
    old = service.accounts.enrolment_entries["dana@example.org"]
    service.accounts.enrolment_entries["dana@example.org"] = Enrolment(
        old.match_value, old.created_at, datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
    )
    page = client.get("/users/dana@example.org").text
    assert "rattaché à son identité SSO le 2026-11-07 09:30" in page


def test_email_enrolment_refuses_a_known_or_already_enrolled_email(web):
    client, service, audit = web
    service.accounts.profiles["oid-existing"] = UserProfile("Eve", "Eve@Example.org")
    assert post_email(client, "eve@example.org").headers["location"] == "/users"
    assert "eve@example.org" not in service.accounts.enrolment_entries
    assert audit.events[-1].outcome == "failure" and audit.events[-1].reason == "email_already_known"

    assert post_email(client, "dana@example.org").headers["location"] == "/users/dana@example.org"
    assert post_email(client, "DANA@example.org").headers["location"] == "/users"
    assert len(service.accounts.enrolment_entries) == 1


@pytest.mark.parametrize(
    "email", ["", "pas-un-mail", "a@b", "a b@example.org", "a@@example.org", "é@example.org"]
)
def test_email_enrolment_refuses_malformed_addresses(web, email):
    client, service, audit = web
    r = post_email(client, email)
    assert r.status_code == 303 and r.headers["location"] == "/users"
    assert service.accounts.enrolment_entries == {} and service.accounts.profiles == {}
    assert all(e.action != "user_enrolled" for e in audit.events)


def test_unknown_mode_is_refused(web):
    client, service, _ = web
    token = csrf(client, "/users")
    r = client.post("/users", data={"csrf": token, "mode": "x", "user_key": KEY})
    assert r.headers["location"] == "/users" and service.accounts.profiles == {}


def test_enrolment_page_does_not_escape_user_input_unsafely(web):
    client, service, _ = web
    post_email(client, "x@example.org", display_name="<script>alert(1)</script>")
    page = client.get("/users/x@example.org").text
    assert "<script>alert(1)" not in page and "&lt;script&gt;" in page


# --- Suppression d'un utilisateur ------------------------------------------------------------


def seed_user_with_accounts(service, key="dana@example.org"):
    from datetime import UTC, datetime

    from sesame_admin.ports import Account

    now = datetime.now(UTC)
    for app, acc, default in (
        ("fake-app", "default", True),
        ("fake-app", "admin", False),
        ("gone-app", "default", True),
    ):
        k = (app, key) if acc == "default" else (app, key, acc)
        service.accounts.accounts[k] = Account(app, key, "active", None, None, now, acc, None, default)
        service.secrets.entries[k] = {"username": "u", "password": "p"}
    service.accounts.profiles[key] = UserProfile("Dana", key)
    service.accounts.app_sessions[("fake-app", key)] = 2
    return key


def test_delete_user_erases_accounts_secrets_profile_and_enrolment(web):
    client, service, audit = web
    post_email(client, "dana@example.org")
    key = seed_user_with_accounts(service)
    token = csrf(client, f"/users/{key}")
    r = client.post(f"/users/{key}/delete", data={"csrf": token})
    assert r.status_code == 303 and r.headers["location"] == "/users"
    assert service.accounts.accounts == {} and service.secrets.entries == {}
    assert service.accounts.profiles == {} and service.accounts.enrolment_entries == {}
    assert service.accounts.app_sessions == {}
    actions = [(e.action, e.app_id, e.target_user) for e in audit.events]
    # Y compris le compte d'une appli dont le descripteur a disparu ; un événement par identifiant.
    assert actions.count(("credential_deleted", "gone-app", key)) == 1
    assert sum(a[0] == "credential_deleted" for a in actions) == 3
    assert audit.events[-1].action == "user_deleted" and audit.events[-1].reason == "accounts:3"
    assert f'href="/users/{key}"' not in client.get("/users").text


def test_delete_user_is_idempotent_and_requires_csrf(web):
    client, service, audit = web
    key = seed_user_with_accounts(service)
    r = client.post(f"/users/{key}/delete", data={"csrf": "forged"})
    assert r.headers["location"] == f"/users/{key}" and len(service.accounts.accounts) == 3
    token = csrf(client, f"/users/{key}")
    assert client.post(f"/users/{key}/delete", data={"csrf": token}).headers["location"] == "/users"
    assert client.post(f"/users/{key}/delete", data={"csrf": token}).headers["location"] == "/users"
    assert audit.events[-1].reason == "accounts:0"


def test_delete_user_stops_when_the_vault_is_down_and_keeps_the_registry(web, monkeypatch):
    from sesame_admin.ports import Unavailable

    client, service, audit = web
    key = seed_user_with_accounts(service)

    async def down(*args, **kwargs):
        raise Unavailable("coffre injoignable")

    monkeypatch.setattr(service.secrets, "delete_credential", down)
    token = csrf(client, f"/users/{key}")
    r = client.post(f"/users/{key}/delete", data={"csrf": token})
    assert r.headers["location"] == f"/users/{key}"
    assert len(service.accounts.accounts) == 3 and key in service.accounts.profiles
    assert (audit.events[-1].action, audit.events[-1].outcome) == ("credential_deleted", "failure")
    assert all(e.action != "user_deleted" for e in audit.events)


def test_user_page_offers_the_deletion(web):
    client, service, _ = web
    key = seed_user_with_accounts(service)
    page = client.get(f"/users/{key}").text
    assert f'action="/users/{key}/delete"' in page
