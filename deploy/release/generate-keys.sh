#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Crée .env à partir de .env.example s'il n'existe pas, puis remplit les clés et mots de
# passe encore vides avec des valeurs aléatoires. Relançable sans risque : une valeur déjà
# renseignée n'est jamais remplacée.
set -eu
cd "$(dirname "$0")"
command -v openssl >/dev/null || { echo "openssl est requis" >&2; exit 1; }

if [ ! -f .env ]; then
  cp .env.example .env
  echo ".env créé à partir de .env.example"
fi
chmod 600 .env

fill() {
  name=$1
  value=$2
  if grep -q "^${name}=." .env; then
    return 0
  fi
  if grep -q "^${name}=\$" .env; then
    awk -v n="$name" -v v="$value" 'BEGIN { FS = "=" } $0 == n "=" { print n "=" v; next } { print }' \
      .env > .env.tmp && mv .env.tmp .env
  else
    printf '%s=%s\n' "$name" "$value" >> .env
  fi
  chmod 600 .env
  echo "  $name généré"
}

# Mot de passe en hexadécimal : il figure dans une URL de connexion PostgreSQL.
fill POSTGRES_PASSWORD "$(openssl rand -hex 24)"
# Clés de chiffrement : 32 octets aléatoires en base64.
fill SESAME_PORTAL_STATE_KEY "$(openssl rand -base64 32)"
fill SESAME_SESSION_ENCRYPTION_KEY "$(openssl rand -base64 32)"
fill SESAME_SECRETS_ENCRYPTION_KEY "$(openssl rand -base64 32)"
fill SESAME_ADMIN_SESSION_KEY "$(openssl rand -hex 32)"
fill SESAME_RECORDER_TOKEN "$(openssl rand -hex 32)"
fill SESAME_INTERNAL_TOKEN "$(openssl rand -hex 32)"

echo "Terminé. Renseignez maintenant la section 1 de .env (domaine et fournisseur d'identité)."
