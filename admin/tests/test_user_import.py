# SPDX-License-Identifier: Apache-2.0
"""Import d'utilisateurs avant leur première connexion (ADR 0032)."""

import asyncio
import re

import pytest
from fastapi.testclient import TestClient
from sesame_admin import user_import
from sesame_admin.audit import MemoryAuditSink
from sesame_admin.ports import UserProfile
from sesame_admin.service import InvalidInput
from sesame_admin.web import create_app

from .conftest import ADMIN, make_service
from .test_web import FakeAuth, login

OID = "3f2a9c1e-0000-4000-8000-000000000001"
CID = "cid-test"


def run(coro):
    return asyncio.run(coro)


# --- Analyse ------------------------------------------------------------------------


def test_parse_accepts_the_three_separators_and_optional_columns():
    text = f"{OID},Alice Martin,alice@exemple.org\nbob;Bob Durand;bob@exemple.org\ncarol\tCarol\ndave\n"
    p = user_import.parse(text)
    assert [(e.user_key, e.display_name, e.email) for e in p.entries] == [
        (OID, "Alice Martin", "alice@exemple.org"),
        ("bob", "Bob Durand", "bob@exemple.org"),
        ("carol", "Carol", None),
        ("dave", None, None),
    ]
    assert p.rejected == 0 and p.errors == []


def test_parse_skips_header_comments_and_blank_lines_and_handles_quotes():
    p = user_import.parse('clé,nom,e-mail\n\n# commentaire\n"alice","Martin, Alice",a@x.org\n')
    assert [(e.user_key, e.display_name) for e in p.entries] == [("alice", "Martin, Alice")]


def test_parse_reports_each_bad_line_without_dropping_the_good_ones():
    p = user_import.parse("ok,Ok\nmauvaise clé,X\nbob,Bob,pas-un-email\ncar,Car\x07ol\n../x\n")
    assert [e.user_key for e in p.entries] == ["ok"]
    assert p.rejected == 4
    assert [e.split(" :")[0] for e in p.errors] == ["ligne 2", "ligne 3", "ligne 4", "ligne 5"]


def test_parse_merges_duplicates_keeping_known_values():
    p = user_import.parse("a,Alice,a@x.org\na,,\na,Alicia\n")
    assert [(e.display_name, e.email) for e in p.entries] == [("Alicia", "a@x.org")]


def test_parse_limits():
    with pytest.raises(user_import.ImportTooLarge):
        user_import.parse("x\n" * (user_import.MAX_LINES + 1))
    with pytest.raises(user_import.ImportTooLarge):
        user_import.parse("a" * (user_import.MAX_BYTES + 1))
    many = user_import.parse("\n".join("mauvaise clé" for _ in range(100)))
    assert many.rejected == 100 and len(many.errors) == user_import.MAX_REPORTED_ERRORS


# --- Service ------------------------------------------------------------------------


@pytest.fixture
def svc(apps):
    audit = MemoryAuditSink()
    return make_service(apps, audit), audit


def test_import_creates_then_updates_without_overwriting_known_values(svc):
    service, audit = svc
    out = run(service.import_users(ADMIN, f"{OID},Alice Martin,alice@exemple.org\nbob", CID))
    assert (out.created, out.updated, out.rejected) == (2, 0, 0)
    assert service.accounts.profiles[OID] == UserProfile("Alice Martin", "alice@exemple.org")
    out = run(service.import_users(ADMIN, f"{OID}\nbob,Bob", CID))
    assert (out.created, out.updated) == (0, 2)
    assert service.accounts.profiles[OID] == UserProfile("Alice Martin", "alice@exemple.org")
    assert service.accounts.profiles["bob"] == UserProfile("Bob", None)
    events = [(e.action, e.outcome, e.reason) for e in audit.events]
    assert events[0] == ("users_imported", "success", "created=2;updated=0;rejected=0")
    assert events[1][2] == "created=0;updated=2;rejected=0"
    assert all(e.actor == ADMIN.actor and e.correlation_id == CID for e in audit.events)


def test_import_creates_no_account_and_no_secret(svc):
    service, _ = svc
    run(service.import_users(ADMIN, f"{OID},Alice", CID))
    assert service.accounts.accounts == {} and service.secrets.entries == {}


def test_imported_users_are_known_searchable_and_suggested(svc):
    service, _ = svc
    run(service.import_users(ADMIN, f"{OID},Alice Martin,alice@exemple.org", CID))
    assert OID in run(service.accounts.known_users(10))
    assert run(service.accounts.search_users("martin", 10)) == [(OID, {})]
    assert run(service.accounts.search_users("introuvable", 10)) == []


def test_import_with_nothing_valid_is_refused_and_audited(svc):
    service, audit = svc
    with pytest.raises(InvalidInput, match="Aucun utilisateur valide"):
        run(service.import_users(ADMIN, "mauvaise clé\n", CID))
    assert [(e.action, e.outcome) for e in audit.events] == [("users_imported", "failure")]
    assert service.accounts.profiles == {}


def test_oversized_import_is_refused_and_audited(svc):
    service, audit = svc
    with pytest.raises(InvalidInput, match="lignes"):
        run(service.import_users(ADMIN, "a\n" * (user_import.MAX_LINES + 1), CID))
    assert audit.events[0].reason == "too_large"


# --- Pages --------------------------------------------------------------------------


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
    return client, service


def csrf(client):
    return re.search(r'name="csrf" value="([^"]+)"', client.get("/users/import").text).group(1)


def test_form_names_the_claim_and_requires_a_session(web, apps):
    client, _ = web
    page = client.get("/users/import").text
    assert "<code>preferred_username</code>" in page and "Object Id" in page
    anonymous = TestClient(client.app, base_url="https://admin.test", follow_redirects=False)
    assert anonymous.get("/users/import").status_code == 302
    assert anonymous.post("/users/import", data={"users": "a"}).status_code == 403


def test_import_page_flow_then_listing(web):
    client, service = web
    r = client.post(
        "/users/import",
        data={"csrf": csrf(client), "users": f"{OID},Alice Martin,alice@exemple.org\nmauvaise clé,X"},
    )
    assert r.status_code == 200
    assert "1 utilisateur(s) ajouté(s), 0 mis à jour, 1 ligne(s) refusée(s)" in r.text
    assert "ligne 2" in r.text
    listing = client.get("/users").text
    assert "<strong>Alice Martin</strong>" in listing and "aucun compte" in listing


def test_import_rejects_a_bad_csrf_token_and_writes_nothing(web):
    client, service = web
    r = client.post("/users/import", data={"csrf": "faux", "users": f"{OID},Alice"})
    assert r.status_code == 400 and "CSRF" in r.text
    assert service.accounts.profiles == {}


def test_import_page_escapes_what_it_echoes(web):
    client, _ = web
    r = client.post("/users/import", data={"csrf": csrf(client), "users": "<script>alert(1)</script>,x"})
    assert r.status_code == 400
    assert "<script>alert(1)" not in r.text and "&lt;script&gt;" in r.text
