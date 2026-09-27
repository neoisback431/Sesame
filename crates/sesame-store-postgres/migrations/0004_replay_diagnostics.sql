-- SPDX-License-Identifier: Apache-2.0
-- Diagnostic du dernier rejeu en échec d'un compte (ADR 0018), écrit par le proxy si
-- SESAME_REPLAY_DEBUG est activé, lu par l'administration. Valeurs du coffre et des
-- cookies masquées par le proxy avant écriture. Supprimé avec le compte.
CREATE TABLE replay_diagnostics (
    app_id     TEXT NOT NULL,
    user_key   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    document   JSONB NOT NULL,
    PRIMARY KEY (app_id, user_key),
    FOREIGN KEY (app_id, user_key) REFERENCES app_accounts (app_id, user_key) ON DELETE CASCADE
);
