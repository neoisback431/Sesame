-- SPDX-License-Identifier: Apache-2.0
-- Coffre de secrets PostgreSQL (ADR 0021), implémentation par défaut de SecretStore :
-- une ligne par champ (`username`, `password`…), valeur chiffrée (AES-256-GCM par le
-- proxy en lecture et l'admin en écriture, clé SESAME_SECRETS_ENCRYPTION_KEY, jamais
-- stockée en base). Aucune contrainte vers app_accounts : l'admin écrit le secret avant
-- le compte (même opération) ; la suppression du compte supprime aussi le secret,
-- explicitement, côté application.
CREATE TABLE app_secrets (
    app_id     TEXT NOT NULL,
    user_key   TEXT NOT NULL,
    key        TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, user_key, key)
);
