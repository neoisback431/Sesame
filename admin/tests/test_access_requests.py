# SPDX-License-Identifier: Apache-2.0
"""Demandes d'accès (ADR 0029) : file d'attente, activation, refus, clôture automatique."""

import asyncio
import re
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sesame_admin.audit import MemoryAuditSink
from sesame_admin.memory import MemoryAccessRequestStore
from sesame_admin.ports import Account
from sesame_admin.service import InvalidInput
from sesame_admin.web import create_app

from .conftest import ADMIN, make_service
from .test_web import SECRET, FakeAuth, login

CID = "cid-test"


def put_pending(service, app_id="fake-app", user="bob"):
    """État laissé par le proxy après une demande avec identifiants : compte en attente + secret."""
    service.accounts.accounts[(app_id, user)] = Account(
        app_id, user, "pending", "access_request", None, datetime.now(UTC)
    )
    service.secrets.entries[(app_id, user)] = {"username": "bob-app", "password": SECRET}
    service.requests.submit(app_id, user, "credentials")


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def svc(apps):
    audit = MemoryAuditSink()
    service = make_service(apps, audit)
    assert isinstance(service.requests, MemoryAccessRequestStore)
    return service, audit


def test_approve_activates_the_pending_account_and_closes_the_request(svc):
    service, audit = svc
    put_pending(service)
    run(service.approve_access(ADMIN, "fake-app", "bob", CID))
    assert service.accounts.accounts[("fake-app", "bob")].status == "active"
    assert service.requests.resolved[("fake-app", "bob")] == "approved"
    assert service.secrets.entries[("fake-app", "bob")]["password"] == SECRET  # non touché
    actions = [(e.action, e.outcome) for e in audit.events]
    assert ("access_request_approved", "success") in actions
    assert ("account_status_changed", "success") in actions
    assert SECRET not in repr(audit.events)


def test_approve_refuses_anything_but_a_pending_credentials_request(svc):
    service, _ = svc
    with pytest.raises(InvalidInput):  # pas de demande
        run(service.approve_access(ADMIN, "fake-app", "bob", CID))
    service.requests.submit("fake-app", "bob", "no_account")
    with pytest.raises(InvalidInput):  # demande « sans compte » : rien à activer
        run(service.approve_access(ADMIN, "fake-app", "bob", CID))
    put_pending(service, user="carol")
    run(service.accounts.set_status("fake-app", "carol", "active", None))
    with pytest.raises(InvalidInput):  # compte plus en attente
        run(service.approve_access(ADMIN, "fake-app", "carol", CID))


def test_reject_credentials_deletes_secret_and_pending_account(svc):
    service, audit = svc
    put_pending(service)
    run(service.reject_access(ADMIN, "fake-app", "bob", CID))
    assert ("fake-app", "bob") not in service.secrets.entries
    assert ("fake-app", "bob") not in service.accounts.accounts
    assert service.requests.resolved[("fake-app", "bob")] == "rejected"
    assert ("access_request_rejected", "success") in [(e.action, e.outcome) for e in audit.events]
    assert "credential_deleted" in [e.action for e in audit.events]


def test_reject_never_touches_a_non_pending_account(svc):
    service, _ = svc
    put_pending(service)
    run(service.accounts.set_status("fake-app", "bob", "active", None))  # clôt la demande
    service.requests.submit("fake-app", "bob", "credentials")  # demande rouverte à la main
    with pytest.raises(InvalidInput):
        run(service.reject_access(ADMIN, "fake-app", "bob", CID))
    assert service.accounts.accounts[("fake-app", "bob")].status == "active"
    assert ("fake-app", "bob") in service.secrets.entries


def test_reject_no_account_request_only_closes_it(svc):
    service, _ = svc
    service.requests.submit("fake-app", "dave", "no_account", "besoin du CRM")
    run(service.reject_access(ADMIN, "fake-app", "dave", CID))
    assert service.requests.resolved[("fake-app", "dave")] == "rejected"
    assert not service.secrets.entries


def test_provisioning_fulfils_a_no_account_request(svc):
    service, audit = svc
    service.requests.submit("fake-app", "dave", "no_account")
    run(service.provision(ADMIN, "fake-app", "dave", {"username": "dave-app", "password": SECRET}, CID))
    assert service.requests.resolved[("fake-app", "dave")] == "fulfilled"
    assert service.accounts.accounts[("fake-app", "dave")].status == "active"
    assert ("access_request_fulfilled", "success") in [(e.action, e.outcome) for e in audit.events]
    assert SECRET not in repr(audit.events)


def test_activating_or_deleting_by_the_account_pages_closes_the_request(svc):
    service, _ = svc
    put_pending(service)
    run(service.set_status(ADMIN, "fake-app", "bob", "active", CID))
    assert service.requests.resolved[("fake-app", "bob")] == "approved"
    put_pending(service, user="carol")
    run(service.delete(ADMIN, "fake-app", "carol", CID))
    assert service.requests.resolved[("fake-app", "carol")] == "rejected"


def test_bulk_disable_covers_pending_accounts_and_closes_requests(svc):
    service, _ = svc
    put_pending(service)
    assert run(service.disable_all(ADMIN, "bob", CID)) == 1
    assert service.accounts.accounts[("fake-app", "bob")].status == "disabled"
    assert service.requests.resolved[("fake-app", "bob")] == "rejected"


# --- Pages ---------------------------------------------------------------------------


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


def token(client, path="/requests"):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(path).text).group(1)


def test_requests_page_lists_both_kinds_without_secrets(web):
    client, service, _ = web
    assert "Aucune demande en attente" in client.get("/requests").text
    put_pending(service)
    service.requests.submit("fake-app", "dave", "no_account", "besoin <b>du</b> CRM")
    page = client.get("/requests").text
    assert "identifiants fournis" in page and "sans compte" in page
    assert "besoin &lt;b&gt;du&lt;/b&gt; CRM" in page  # échappé
    assert "Activer" in page and "Créer le compte" in page
    assert "user_key=dave" in page
    assert SECRET not in page and "bob-app" not in page
    only = client.get("/requests?kind=no_account").text
    assert "dave" in only and "bob" not in only
    assert "2 demande(s) d'accès en attente" in client.get("/").text


def test_approve_and_reject_through_the_pages_require_csrf(web):
    client, service, audit = web
    put_pending(service)
    t = token(client)
    r = client.post("/requests/fake-app/bob/approve", data={"csrf": "faux"})
    assert r.status_code == 303 and "Jeton CSRF" in client.get("/requests").text
    assert service.accounts.accounts[("fake-app", "bob")].status == "pending"

    r = client.post("/requests/fake-app/bob/approve", data={"csrf": t})
    assert r.status_code == 303 and r.headers["location"] == "/requests"
    assert "activé sur" in client.get("/requests").text
    assert service.accounts.accounts[("fake-app", "bob")].status == "active"

    put_pending(service, user="eve")
    client.post("/requests/fake-app/eve/reject", data={"csrf": t})
    assert ("fake-app", "eve") not in service.secrets.entries
    assert SECRET not in repr(audit.events)


def test_non_admin_cannot_use_the_request_pages(apps):
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
    assert client.get("/requests").status_code == 302
    assert client.post("/requests/fake-app/bob/approve", data={}).status_code == 403


def test_account_page_prefills_the_requested_user_and_shows_pending(web):
    client, service, _ = web
    put_pending(service)
    page = client.get("/apps/fake-app?user_key=dave").text
    assert 'value="dave"' in page
    assert "en attente" in page and ">Activer<" in page
    assert 'value="&quot;&gt;' not in client.get('/apps/fake-app?user_key="><script>').text
    assert "<script>" not in client.get('/apps/fake-app?user_key="><script>').text
