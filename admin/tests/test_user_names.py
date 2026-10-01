# SPDX-License-Identifier: Apache-2.0
"""Noms et e-mails des utilisateurs dans l'administration (ADR 0031)."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sesame_admin.audit import MemoryAuditSink
from sesame_admin.ports import Account, Unavailable, UserProfile
from sesame_admin.web import create_app

from .conftest import make_service
from .test_web import FakeAuth, login

KEY = "CmPymIROfTM_CDtsZjAmW95gHfJ_JOzAKoVY75UQ534"


@pytest.fixture
def web(apps):
    audit = MemoryAuditSink()
    service = make_service(apps, audit)
    now = datetime.now(UTC)
    service.accounts.accounts[("fake-app", KEY)] = Account("fake-app", KEY, "active", None, None, now)
    service.accounts.accounts[("fake-app", "inconnu")] = Account(
        "fake-app", "inconnu", "active", None, None, now
    )
    service.accounts.profiles[KEY] = UserProfile("Alice Martin", "alice@example.org")
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
    return client, service


def test_users_page_shows_the_name_first_and_the_key_below(web):
    client, _ = web
    page = client.get("/users").text
    assert "<strong>Alice Martin</strong>" in page
    assert "alice@example.org" in page
    assert f'<code class="muted">{KEY}</code>' in page
    # Personne encore jamais connectée : la clé seule.
    assert "<code>inconnu</code>" in page and "<strong>inconnu" not in page


@pytest.mark.parametrize("query", ["martin", "ALICE@EXAMPLE", KEY[:12]])
def test_search_matches_name_email_and_key(web, query):
    client, _ = web
    page = client.get("/users", params={"q": query}).text
    assert "Alice Martin" in page and "inconnu" not in page


def test_user_page_is_titled_by_the_name(web):
    client, _ = web
    page = client.get(f"/users/{KEY}").text
    assert "<title>" in page and "Alice Martin" in page.split("</title>")[0]
    assert "<h1>Comptes de <strong>Alice Martin</strong>" in page


def test_account_page_lists_names_and_labels_the_suggestions(web):
    client, _ = web
    page = client.get("/apps/fake-app").text
    assert "<strong>Alice Martin</strong>" in page
    assert f'<option value="{KEY}" label="Alice Martin">' in page


def test_email_stands_in_when_the_name_is_unknown(web):
    client, service = web
    service.accounts.profiles[KEY] = UserProfile(None, "alice@example.org")
    assert "<strong>alice@example.org</strong>" in client.get("/users").text


def test_names_are_escaped(web):
    client, service = web
    service.accounts.profiles[KEY] = UserProfile("<script>alert(1)</script>", None)
    for path in ("/users", f"/users/{KEY}", "/apps/fake-app"):
        page = client.get(path).text
        assert "<script>alert(1)" not in page and "&lt;script&gt;" in page


def test_a_profile_lookup_failure_never_breaks_the_page(web, monkeypatch):
    client, service = web

    async def down(keys):
        raise Unavailable("base injoignable")

    monkeypatch.setattr(service.accounts, "user_profiles", down)
    for path in ("/users", f"/users/{KEY}", "/apps/fake-app", "/requests"):
        r = client.get(path)
        assert r.status_code == 200, path
    assert f"<code>{KEY}</code>" in client.get("/users").text
