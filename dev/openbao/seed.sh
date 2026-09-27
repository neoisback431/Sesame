#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Initialise OpenBao en mode dev : AppRoles du proxy (lecture) et de l'admin
# (écriture sans lecture), identifiants de test.
# Valeurs de DEV UNIQUEMENT, connues de tous.
set -eu

until bao status >/dev/null 2>&1; do sleep 1; done

# Idempotent : relancer le seed ne doit pas échouer sur un secret-id existant.
custom_secret_id() {
  role="$1"; sid="$2"
  if bao write -format=json "auth/approle/role/$role/secret-id/lookup" secret_id="$sid" 2>/dev/null | grep -q '"data"'; then
    return 0
  fi
  bao write "auth/approle/role/$role/custom-secret-id" secret_id="$sid" >/dev/null
}

bao auth list | grep -q '^approle/' || bao auth enable approle
bao policy write sesame-proxy /seed/proxy-policy.hcl
bao write auth/approle/role/sesame-proxy \
  token_policies=sesame-proxy token_ttl=1h token_max_ttl=4h secret_id_ttl=0
bao write auth/approle/role/sesame-proxy/role-id role_id="${PROXY_ROLE_ID}"
custom_secret_id sesame-proxy "${PROXY_SECRET_ID}"

bao policy write sesame-admin /seed/admin-policy.hcl
bao write auth/approle/role/sesame-admin \
  token_policies=sesame-admin token_ttl=1h token_max_ttl=4h secret_id_ttl=0
bao write auth/approle/role/sesame-admin/role-id role_id="${ADMIN_ROLE_ID}"
custom_secret_id sesame-admin "${ADMIN_SECRET_ID}"

# Couple (fake-app, alice) : le compte applicatif diffère du compte SSO.
bao kv put secret/sesame/apps/fake-app/users/alice \
  username=amartin password=dev-amartin-app-password >/dev/null

echo "OpenBao initialisé"
