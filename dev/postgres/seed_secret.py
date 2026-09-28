#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Coffre de secrets de dev (ADR 0021) : déclare le couple (fake-app, alice), chiffré
avec la même clé que le proxy et l'admin. Valeurs de DEV UNIQUEMENT.

Attend que la migration `app_secrets` ait tourné (portail ou proxy, au démarrage) :
mêmes tables, pas de dépendance Docker supplémentaire à exprimer.
"""

import asyncio
import os
import time

import asyncpg
from sesame_admin.crypto import SecretCipher, field_aad

APP_ID, USER_KEY = "fake-app", "alice"
FIELDS = {"username": "amartin", "password": "dev-amartin-app-password"}


async def main() -> None:
    dsn = os.environ["SESAME_DATABASE_URL"]
    cipher = SecretCipher(os.environ["SESAME_SECRETS_ENCRYPTION_KEY"])
    deadline = time.monotonic() + 60
    conn = None
    while conn is None:
        try:
            conn = await asyncpg.connect(dsn)
            await conn.execute("SELECT 1 FROM app_secrets LIMIT 1")
        except (OSError, asyncpg.PostgresError):
            if conn is not None:
                await conn.close()
            conn = None
            if time.monotonic() > deadline:
                raise
            await asyncio.sleep(1)
    try:
        for key, value in FIELDS.items():
            ciphertext = cipher.encrypt(value, field_aad(APP_ID, USER_KEY, key))
            await conn.execute(
                """INSERT INTO app_secrets (app_id, user_key, key, ciphertext) VALUES ($1, $2, $3, $4)
                   ON CONFLICT (app_id, user_key, key) DO UPDATE SET ciphertext = $4, updated_at = now()""",
                APP_ID,
                USER_KEY,
                key,
                ciphertext,
            )
    finally:
        await conn.close()
    print("Coffre de secrets initialisé (fake-app/alice)")


if __name__ == "__main__":
    asyncio.run(main())
