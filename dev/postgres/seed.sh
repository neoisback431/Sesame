#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Registre des comptes de dev : attend les migrations (appliquées par le portail
# ou le proxy au démarrage), puis déclare le compte d'alice sur l'appli factice.
set -eu
PSQL="psql -h postgres -U sesame -d sesame -v ON_ERROR_STOP=1 -q"
until $PSQL -c 'SELECT 1 FROM app_accounts LIMIT 1' >/dev/null 2>&1; do sleep 1; done
$PSQL <<'SQL'
INSERT INTO app_accounts (app_id, user_key, status) VALUES ('fake-app', 'alice', 'active')
ON CONFLICT (app_id, user_key) DO UPDATE SET status = 'active', status_reason = NULL, updated_at = now();
SQL
echo "Registre des comptes initialisé"
