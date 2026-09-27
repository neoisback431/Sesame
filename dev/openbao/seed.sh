#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Initialise OpenBao en mode dev : AppRole du proxy + identifiants de test.
# Valeurs de DEV UNIQUEMENT, connues de tous.
set -eu

until bao status >/dev/null 2>&1; do sleep 1; done

bao auth list | grep -q '^approle/' || bao auth enable approle
bao policy write sesame-proxy /seed/proxy-policy.hcl
bao write auth/approle/role/sesame-proxy \
  token_policies=sesame-proxy token_ttl=1h token_max_ttl=4h secret_id_ttl=0
bao write auth/approle/role/sesame-proxy/role-id role_id="${PROXY_ROLE_ID}"
bao write auth/approle/role/sesame-proxy/custom-secret-id secret_id="${PROXY_SECRET_ID}" >/dev/null

# Couple (fake-app, alice) : le compte applicatif diffère du compte SSO.
bao kv put secret/sesame/apps/fake-app/users/alice \
  username=amartin password=dev-amartin-app-password >/dev/null

echo "OpenBao initialisé"
