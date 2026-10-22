#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Registre des comptes de dev : attend les migrations (appliquées par le portail
# ou le proxy au démarrage, jusqu'aux comptes multiples, ADR 0034), puis déclare le
# compte par défaut d'alice sur l'appli factice.
set -eu
PSQL="psql -h postgres -U sesame -d sesame -v ON_ERROR_STOP=1 -q"
until $PSQL -c 'SELECT account_id FROM app_accounts LIMIT 1' >/dev/null 2>&1; do sleep 1; done
$PSQL <<'SQL'
INSERT INTO app_accounts (app_id, user_key, account_id, is_default, status)
VALUES ('fake-app', 'alice', 'default', true, 'active')
ON CONFLICT (app_id, user_key, account_id) DO UPDATE
SET status = 'active', status_reason = NULL, updated_at = now();
SQL
echo "Registre des comptes initialisé"
