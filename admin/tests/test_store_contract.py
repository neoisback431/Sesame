# SPDX-License-Identifier: Apache-2.0
"""Même suite de contrat pour toutes les implémentations du registre des comptes.

PostgreSQL : activé si ``SESAME_TEST_DATABASE_URL`` est définie ; le schéma est
créé à partir des migrations Rust s'il est absent.
"""

import base64
import json
import os
import uuid

import pytest
from sesame_admin.memory import (
    MemoryAccessRequestStore,
    MemoryAccountStore,
    MemoryDescriptorStore,
    MemoryNotificationStore,
)
from sesame_admin.ports import Conflict, NotFound, NotificationSettings
from sesame_admin.store_postgres import (
    PostgresAccessRequestStore,
    PostgresAccountStore,
    PostgresDescriptorStore,
    PostgresNotificationStore,
)

from .conftest import ROOT

MIGRATIONS = ROOT / "crates" / "sesame-store-postgres" / "migrations"


async def postgres_store():
    dsn = os.environ.get("SESAME_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("SESAME_TEST_DATABASE_URL absente")
    store = PostgresAccountStore(dsn)
    pool = await store.pool()
    exists = await pool.fetchval("SELECT to_regclass('app_accounts') IS NOT NULL")
    if not exists:
        for sql in sorted(MIGRATIONS.glob("*.sql")):
            await pool.execute(sql.read_text())
    return store


@pytest.fixture(params=["memory", "postgres"])
async def store(request):
    if request.param == "memory":
        yield MemoryAccountStore()
        return
    s = await postgres_store()
    yield s
    await s.close()


async def test_account_store_contract(store):
    app, user = f"app-{uuid.uuid4().hex[:8]}", "carol"
    assert await store.get_account(app, user) is None
    assert await store.list_accounts(app) == []

    await store.upsert_active(app, user)
    await store.upsert_active(app, "dave")
    a = await store.get_account(app, user)
    assert a.status == "active" and a.status_reason is None
    assert [x.user_key for x in await store.list_accounts(app)] == ["carol", "dave"]

    await store.set_status(app, user, "failed", "login_rejected")
    a = await store.get_account(app, user)
    assert (a.status, a.status_reason) == ("failed", "login_rejected")
    assert (await store.count_by_app())[app] == {"active": 1, "failed": 1}

    await store.upsert_active(app, user)
    assert (await store.get_account(app, user)).status == "active"

    with pytest.raises(NotFound):
        await store.set_status(app, "personne", "disabled", None)
    await store.delete_account(app, user)
    assert await store.get_account(app, user) is None
    with pytest.raises(NotFound):
        await store.delete_account(app, user)
    await store.delete_account(app, "dave")


async def seed_app_session(store, app_id: str, user_key: str) -> None:
    """Session applicative ouverte, créée comme le feraient le portail et le proxy."""
    if isinstance(store, MemoryAccountStore):
        store.app_sessions[(app_id, user_key)] = store.app_sessions.get((app_id, user_key), 0) + 1
        return
    pool = await store.pool()
    sid = uuid.uuid4().hex
    await pool.execute(
        """INSERT INTO portal_sessions (id_hash, issuer, subject, user_key, created_at, expires_at)
           VALUES ($1, 'https://idp.test', 'sub', $2, now(), now() + interval '1 hour')""",
        sid,
        user_key,
    )
    await pool.execute(
        """INSERT INTO app_sessions (portal_session, app_id, cookies, created_at, last_used_at, expires_at)
           VALUES ($1, $2, '\\x00', now(), now(), now() + interval '1 hour')""",
        sid,
        app_id,
    )


async def test_user_views_and_session_revocation_contract(store):
    tag = uuid.uuid4().hex[:8]
    user, other = f"erin-{tag}", f"frank-{tag}"
    for app in ("app-a", "app-b"):
        await store.upsert_active(f"{app}-{tag}", user)
    await store.upsert_active(f"app-a-{tag}", other)
    await store.set_status(f"app-b-{tag}", user, "failed", "login_rejected")

    accounts = await store.list_user_accounts(user)
    assert [a.app_id for a in accounts] == [f"app-a-{tag}", f"app-b-{tag}"]
    assert await store.list_user_accounts("personne-" + tag) == []

    found = dict(await store.search_users(f"ERIN-{tag}", 10))
    assert found == {user: {"active": 1, "failed": 1}}
    assert {u for u, _ in await store.search_users(tag, 10)} == {user, other}
    assert await store.search_users("%", 10) == []  # jokers SQL échappés

    # known_users : titulaires d'un compte + personnes déjà connectées au portail (sans compte).
    ghost = f"ghost-{tag}"
    if isinstance(store, MemoryAccountStore):
        store.portal_users.add(ghost)
    else:
        await (await store.pool()).execute(
            """INSERT INTO portal_sessions (id_hash, issuer, subject, user_key, created_at, expires_at)
               VALUES ($1, 'https://idp.test', 'sub', $2, now(), now() + interval '1 hour')""",
            uuid.uuid4().hex,
            ghost,
        )
    known = await store.known_users(10000)
    assert {user, other, ghost} <= set(known)
    assert known == sorted(known) and len(known) == len(set(known))  # trié, sans doublon

    await seed_app_session(store, f"app-a-{tag}", user)
    await seed_app_session(store, f"app-a-{tag}", other)
    assert await store.revoke_app_sessions(f"app-a-{tag}", user) == 1
    assert await store.revoke_app_sessions(f"app-a-{tag}", user) == 0
    assert await store.revoke_app_sessions(f"app-a-{tag}", other) == 1

    for app, u in ((f"app-a-{tag}", user), (f"app-b-{tag}", user), (f"app-a-{tag}", other)):
        await store.delete_account(app, u)


@pytest.fixture(params=["memory", "postgres"])
async def descriptors(request):
    if request.param == "memory":
        yield MemoryDescriptorStore()
        return
    accounts = await postgres_store()  # crée le schéma si besoin
    await accounts.close()
    s = PostgresDescriptorStore(os.environ["SESAME_TEST_DATABASE_URL"])
    yield s
    await s.close()


def document(app_id: str, host: str, name: str = "A") -> dict:
    return {"metadata": {"id": app_id, "name": name, "revision": 99}, "spec": {"public": {"host": host}}}


async def test_descriptor_store_contract(descriptors):
    tag = uuid.uuid4().hex[:8]
    app, other = f"app-{tag}", f"other-{tag}"
    assert await descriptors.get_descriptor(app) is None

    assert await descriptors.create_descriptor(app, document(app, f"{tag}.test"), "admin") == 1
    found = await descriptors.get_descriptor(app)
    assert (found.revision, found.updated_by) == (1, "admin")
    assert found.document["metadata"]["revision"] == 1  # tenue égale à la révision en base
    assert app in [d.app_id for d in await descriptors.list_descriptors()]
    with pytest.raises(Conflict):
        await descriptors.create_descriptor(app, document(app, f"x-{tag}.test"), "admin")
    with pytest.raises(Conflict):  # une appli par nom d'hôte
        await descriptors.create_descriptor(other, document(other, f"{tag}.test"), "admin")

    assert await descriptors.update_descriptor(app, document(app, f"{tag}.test", "B"), "bob", 1) == 2
    found = await descriptors.get_descriptor(app)
    assert (found.revision, found.document["metadata"], found.updated_by) == (
        2,
        {"id": app, "name": "B", "revision": 2},
        "bob",
    )
    with pytest.raises(Conflict):  # révision périmée
        await descriptors.update_descriptor(app, document(app, f"{tag}.test", "C"), "bob", 1)
    with pytest.raises(NotFound):
        await descriptors.update_descriptor(other, document(other, f"o-{tag}.test"), "bob", 1)
    await descriptors.create_descriptor(other, document(other, f"o-{tag}.test"), "admin")
    with pytest.raises(Conflict):
        await descriptors.update_descriptor(other, document(other, f"{tag}.test"), "bob", 1)

    with pytest.raises(Conflict):
        await descriptors.delete_descriptor(app, "carol", 1)
    await descriptors.delete_descriptor(app, "carol", 2)
    assert await descriptors.get_descriptor(app) is None
    with pytest.raises(NotFound):
        await descriptors.delete_descriptor(app, "carol", 2)

    history = await descriptors.history(app)
    assert [(h.action, h.revision, h.changed_by) for h in history] == [
        ("deleted", 2, "carol"),
        ("updated", 2, "bob"),
        ("created", 1, "admin"),
    ]
    assert history[0].document is None and history[1].document["metadata"]["name"] == "B"
    # Recréée après suppression : la révision repart de 1, l'historique continue.
    assert await descriptors.create_descriptor(app, document(app, f"{tag}.test"), "admin") == 1
    assert len(await descriptors.history(app)) == 4
    for a in (app, other):
        await descriptors.delete_descriptor(a, "admin", 1)


async def test_diagnostic_contract(store):
    """Diagnostic écrit par le proxy (document JSON du ReplayDiagnostic Rust), lu par l'admin,
    supprimé avec le compte."""
    app, user = f"app-{uuid.uuid4().hex[:8]}", "erin"
    await store.upsert_active(app, user)
    assert await store.get_diagnostic(app, user) is None
    doc = {
        "app_id": app, "user_key": user, "correlation_id": "cid-1", "reason": "login_rejected",
        "step": "login_submit", "method": "POST", "url": "http://app/login",
        "sent_fields": ["username", "password"], "status": 401,
        "headers": [["set-cookie", "sid=***"]], "body": "refusé é", "body_truncated": False,
        "at": 1_800_000_000,
    }  # fmt: skip
    if isinstance(store, MemoryAccountStore):
        store.diagnostics[(app, user)] = doc
    else:
        await (await store.pool()).execute(
            "INSERT INTO replay_diagnostics (app_id, user_key, document) VALUES ($1, $2, $3::jsonb)",
            app, user, json.dumps(doc),
        )  # fmt: skip
    d = await store.get_diagnostic(app, user)
    assert (d.reason, d.status, d.body, d.headers) == (
        "login_rejected",
        401,
        "refusé é",
        (("set-cookie", "sid=***"),),
    )
    assert d.sent_fields == ("username", "password") and d.at.year == 2027
    await store.delete_account(app, user)
    assert await store.get_diagnostic(app, user) is None


@pytest.fixture(params=["memory", "postgres"])
async def secrets(request):
    from sesame_admin.crypto import SecretCipher
    from sesame_admin.memory import MemorySecretWriter
    from sesame_admin.store_postgres import PostgresSecretWriter

    if request.param == "memory":
        yield MemorySecretWriter()
        return
    accounts = await postgres_store()  # crée le schéma si besoin
    await accounts.close()
    key = base64.b64encode(bytes(range(32))).decode()
    s = PostgresSecretWriter(os.environ["SESAME_TEST_DATABASE_URL"], SecretCipher(key))
    yield s
    await s.close()


async def test_secret_writer_contract(secrets):
    """Coffre en écriture seule (ADR 0021) : aucune méthode de lecture n'existe, mais on
    peut vérifier ici, en test, que l'écriture, le remplacement et la suppression sont
    corrects — via l'accès direct à la table réservé aux tests."""
    from sesame_admin.crypto import field_aad
    from sesame_admin.memory import MemorySecretWriter

    app, user = f"app-{uuid.uuid4().hex[:8]}", "carol"
    await secrets.write_credential(app, user, {"username": "cdupont", "password": "pw-1"})

    if isinstance(secrets, MemorySecretWriter):
        assert secrets.entries[(app, user)] == {"username": "cdupont", "password": "pw-1"}
    else:
        rows = await (await secrets.pool()).fetch(
            "SELECT key, ciphertext FROM app_secrets WHERE app_id = $1 AND user_key = $2", app, user
        )
        values = {
            r["key"]: secrets._cipher.decrypt(r["ciphertext"], field_aad(app, user, r["key"])) for r in rows
        }
        assert values == {"username": "cdupont", "password": "pw-1"}

    # Remplace l'ensemble des champs (comme un PUT KV v2 de Vault).
    await secrets.write_credential(app, user, {"password": "pw-2"})
    if isinstance(secrets, MemorySecretWriter):
        assert secrets.entries[(app, user)] == {"password": "pw-2"}
    else:
        rows = await (await secrets.pool()).fetch(
            "SELECT key FROM app_secrets WHERE app_id = $1 AND user_key = $2", app, user
        )
        assert {r["key"] for r in rows} == {"password"}

    await secrets.delete_credential(app, user)
    if isinstance(secrets, MemorySecretWriter):
        assert (app, user) not in secrets.entries
    else:
        rows = await (await secrets.pool()).fetch(
            "SELECT key FROM app_secrets WHERE app_id = $1 AND user_key = $2", app, user
        )
        assert rows == []


@pytest.fixture(params=["memory", "postgres"])
async def requests_store(request):
    """Magasin des demandes d'accès + une fonction qui en dépose une, comme le portail."""
    if request.param == "memory":
        s = MemoryAccessRequestStore()

        async def submit(app, user, kind, note=None):
            s.submit(app, user, kind, note)

        yield s, submit
        return
    accounts = await postgres_store()
    pool = await accounts.pool()
    s = PostgresAccessRequestStore(accounts._db)  # même pool que le registre

    async def submit(app, user, kind, note=None):
        await pool.execute(
            """INSERT INTO access_requests (app_id, user_key, kind, note) VALUES ($1, $2, $3, $4)
               ON CONFLICT (app_id, user_key) DO UPDATE
               SET kind = $3, note = $4, status = 'open', created_at = now(), resolved_at = NULL""",
            app,
            user,
            kind,
            note,
        )

    yield s, submit
    await accounts.close()


async def test_access_request_store_contract(requests_store):
    store, submit = requests_store
    app = f"app-{uuid.uuid4().hex[:8]}"
    before = await store.count_open()
    assert await store.get_open(app, "bob") is None

    await submit(app, "bob", "no_account", "besoin du CRM")
    await submit(app, "carol", "credentials")
    assert await store.count_open() == before + 2
    mine = [r for r in await store.list_open() if r.app_id == app]
    assert [(r.user_key, r.kind, r.note) for r in mine] == [
        ("bob", "no_account", "besoin du CRM"),
        ("carol", "credentials", None),
    ]
    assert (await store.get_open(app, "bob")).kind == "no_account"

    assert await store.resolve(app, "bob", "fulfilled", "admin") is True
    assert await store.resolve(app, "bob", "fulfilled", "admin") is False, "déjà clôturée"
    assert await store.get_open(app, "bob") is None
    assert await store.count_open() == before + 1

    # Une nouvelle demande après clôture rouvre le couple.
    await submit(app, "bob", "credentials")
    assert (await store.get_open(app, "bob")).kind == "credentials"
    for user in ("bob", "carol"):
        assert await store.resolve(app, user, "rejected", "admin")


async def test_pending_status_round_trips(store):
    app = f"app-{uuid.uuid4().hex[:8]}"
    await store.upsert_active(app, "erin")
    await store.set_status(app, "erin", "pending", "access_request")
    a = await store.get_account(app, "erin")
    assert (a.status, a.status_reason) == ("pending", "access_request")
    assert (await store.count_by_app())[app] == {"pending": 1}
    await store.delete_account(app, "erin")


@pytest.fixture(params=["memory", "postgres"])
async def notification_store(request):
    """Magasin des notifications + une fonction de dépôt, comme le portail et le proxy."""
    if request.param == "memory":
        s = MemoryNotificationStore()

        async def deposit(event, app, user, reason):
            s.deposit(event, app, user, reason)

        yield s, deposit
        return
    accounts = await postgres_store()
    pool = await accounts.pool()
    s = PostgresNotificationStore(accounts._db)

    async def deposit(event, app, user, reason):
        await pool.execute(
            "INSERT INTO notifications (event, app_id, user_key, reason) VALUES ($1, $2, $3, $4)",
            event,
            app,
            user,
            reason,
        )

    yield s, deposit
    await pool.execute("DELETE FROM notifications")
    await accounts.close()


async def test_notification_settings_round_trip(notification_store):
    store, _ = notification_store
    saved = NotificationSettings(
        enabled=True,
        smtp_host="smtp.example.org",
        smtp_port=465,
        smtp_security="tls",
        smtp_user="sesame",
        from_address="sesame@example.org",
        recipients=("a@example.org", "b@example.org"),
        events=("account_failed",),
    )
    await store.save_settings(saved, "admin")
    got = await store.get_settings()
    assert (got.enabled, got.smtp_host, got.smtp_port, got.smtp_security, got.smtp_user) == (
        True,
        "smtp.example.org",
        465,
        "tls",
        "sesame",
    )
    assert got.recipients == ("a@example.org", "b@example.org") and got.events == ("account_failed",)
    assert got.updated_by == "admin" and got.updated_at is not None
    await store.save_settings(NotificationSettings(), "admin")
    assert (await store.get_settings()).enabled is False


async def test_notification_outbox_lifecycle(notification_store):
    store, deposit = notification_store
    app = f"app-{uuid.uuid4().hex[:8]}"
    await deposit("account_failed", app, "alice", "login_rejected")
    await store.enqueue("admin_sensitive", app, "bob", "account_deleted", "issuer|admin")

    claimed = [n for n in await store.claim_pending(50) if n.app_id == app]
    assert [(n.event, n.user_key, n.actor) for n in claimed] == [
        ("account_failed", "alice", None),
        ("admin_sensitive", "bob", "issuer|admin"),
    ]
    # Bail : un événement pris n'est pas repris tout de suite (le mémoire n'a pas de bail).
    if isinstance(store, PostgresNotificationStore):
        assert [n for n in await store.claim_pending(50) if n.app_id == app] == []

    first, second = claimed
    await store.mark(first.id, "sent", None)
    await store.mark(second.id, "retry", "smtp_connect")
    recent = {n.id: n for n in await store.recent(50)}
    assert (recent[first.id].status, recent[first.id].sent_at is not None) == ("sent", True)
    assert (recent[second.id].status, recent[second.id].attempts, recent[second.id].last_error) == (
        "pending",
        1,
        "smtp_connect",
    )
    await store.mark(second.id, "failed", "smtp_connect")
    assert {n.id: n for n in await store.recent(50)}[second.id].status == "failed"
    assert await store.purge(30) == 0  # rien d'assez ancien
