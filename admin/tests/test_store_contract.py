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
