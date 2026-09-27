# SPDX-License-Identifier: Apache-2.0
"""Même suite de contrat pour toutes les implémentations du registre des comptes.

PostgreSQL : activé si ``SESAME_TEST_DATABASE_URL`` est définie ; le schéma est
créé à partir des migrations Rust s'il est absent.
"""

import os
import uuid

import pytest
from sesame_admin.memory import MemoryAccountStore
from sesame_admin.ports import NotFound
from sesame_admin.store_postgres import PostgresAccountStore

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

    await seed_app_session(store, f"app-a-{tag}", user)
    await seed_app_session(store, f"app-a-{tag}", other)
    assert await store.revoke_app_sessions(f"app-a-{tag}", user) == 1
    assert await store.revoke_app_sessions(f"app-a-{tag}", user) == 0
    assert await store.revoke_app_sessions(f"app-a-{tag}", other) == 1

    for app, u in ((f"app-a-{tag}", user), (f"app-b-{tag}", user), (f"app-a-{tag}", other)):
        await store.delete_account(app, u)
