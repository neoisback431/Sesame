# Configuration

Les services se configurent uniquement par variables d'environnement. Les variables marquées 🔒 sont sensibles : elles ne sont jamais journalisées. En production, injectez-les depuis votre gestionnaire de secrets.

Durées au format `30s`, `15m`, `8h`. Clés de chiffrement : 32 octets aléatoires encodés en base64 (`openssl rand -base64 32`).

## Portail (`sesame-portal`)

| Variable | Défaut | Rôle |
|---|---|---|
| `SESAME_PORTAL_LISTEN` | `0.0.0.0:8080` | Adresse d'écoute |
| `SESAME_PUBLIC_URL` | requis | URL publique du portail, ex. `https://sesame.example` |
| `SESAME_COOKIE_NAME` | `sesame_session` | Nom du cookie de session portail |
| `SESAME_COOKIE_DOMAIN` | aucun | Domaine parent du cookie, pour que les sous-domaines des applis le reçoivent, ex. `sesame.example` |
| `SESAME_SESSION_TTL` | `8h` | Durée de vie d'une session portail |
| `SESAME_DESCRIPTORS_DIR` | `descriptors` | Dossier des descripteurs d'applis |
| `SESAME_DATABASE_URL` 🔒 | requis | Connexion PostgreSQL |
| `SESAME_PORTAL_STATE_KEY` 🔒 | requis | Clé chiffrant l'état OIDC temporaire |
| `SESAME_CA_FILE` | aucun | CA supplémentaire (PEM) pour joindre le fournisseur d'identité |
| `SESAME_OIDC_ISSUER` | requis | URL de l'émetteur OIDC (discovery) |
| `SESAME_OIDC_CLIENT_ID` | requis | Identifiant du client OIDC |
| `SESAME_OIDC_CLIENT_SECRET` 🔒 | requis | Secret du client OIDC |
| `SESAME_OIDC_SCOPES` | `openid profile email` | Scopes demandés |
| `SESAME_OIDC_USER_KEY_CLAIM` | `sub` | Claim servant de clé utilisateur (coffre, registre). Pour Entra ID : `oid` |
| `SESAME_OIDC_GROUPS_CLAIM` | `groups` | Claim portant les groupes. Absent = aucun groupe |

URL de redirection à déclarer chez le fournisseur d'identité : `<SESAME_PUBLIC_URL>/auth/callback`.

## Moteur de proxy (`sesame-proxy`)

| Variable | Défaut | Rôle |
|---|---|---|
| `SESAME_PROXY_LISTEN` | `0.0.0.0:8081` | Adresse d'écoute |
| `SESAME_PORTAL_URL` | requis | URL publique du portail (redirections de connexion, liens de retour) |
| `SESAME_COOKIE_NAME` | `sesame_session` | Identique au portail |
| `SESAME_COOKIE_DOMAIN` | aucun | Identique au portail |
| `SESAME_DESCRIPTORS_DIR` | `descriptors` | Dossier des descripteurs d'applis |
| `SESAME_DATABASE_URL` 🔒 | requis | Connexion PostgreSQL |
| `SESAME_SESSION_ENCRYPTION_KEY` 🔒 | requis | Clé chiffrant les cookies applicatifs au repos |
| `SESAME_CA_FILE` | aucun | CA supplémentaire (PEM) pour joindre les applis et le coffre |
| `SESAME_MAX_BODY_BYTES` | `33554432` | Taille maximale d'un corps de requête relayé |
| `SESAME_SECRET_STORE` | `openbao` | Implémentation du coffre : `openbao` ou `vault` (même API) |
| `SESAME_OPENBAO_ADDR` | requis | URL du coffre |
| `SESAME_OPENBAO_MOUNT` | `secret` | Point de montage KV v2 |
| `SESAME_OPENBAO_PATH_PREFIX` | `sesame/apps` | Préfixe : `<mount>/<prefix>/<app_id>/users/<user_key>` |
| `SESAME_OPENBAO_ROLE_ID` | requis | AppRole du proxy |
| `SESAME_OPENBAO_SECRET_ID` 🔒 | requis | Secret de l'AppRole |
| `SESAME_OPENBAO_NAMESPACE` | aucun | Espace de noms, le cas échéant |

## UI d'administration (`sesame-admin`)

| Variable | Défaut | Rôle |
|---|---|---|
| `SESAME_ADMIN_LISTEN` | `0.0.0.0:8000` | Adresse d'écoute |
| `SESAME_ADMIN_PUBLIC_URL` | requis | URL publique, ex. `https://admin.sesame.example` |
| `SESAME_ADMIN_SESSION_KEY` 🔒 | requis | Clé de signature du cookie de session (longue chaîne aléatoire) |
| `SESAME_ADMIN_SESSION_TTL_SECS` | `3600` | Durée de la session d'administration |
| `SESAME_ADMIN_GROUP` | `sesame-admins` | Groupe (claim) requis pour accéder à l'UI |
| `SESAME_DESCRIPTORS_DIR` | `descriptors` | Dossier des descripteurs (lecture seule) |
| `SESAME_SCHEMA_FILE` | `schemas/app-descriptor.schema.json` | Schéma JSON des descripteurs |
| `SESAME_DATABASE_URL` 🔒 | requis | Connexion PostgreSQL (registre des comptes) |
| `SESAME_CA_FILE` | aucun | CA supplémentaire (PEM) pour joindre le fournisseur d'identité et le coffre |
| `SESAME_OIDC_ISSUER`, `SESAME_OIDC_CLIENT_ID`, `SESAME_OIDC_CLIENT_SECRET` 🔒, `SESAME_OIDC_SCOPES`, `SESAME_OIDC_USER_KEY_CLAIM`, `SESAME_OIDC_GROUPS_CLAIM` | comme le portail | Client OIDC **dédié** à l'administration |
| `SESAME_OPENBAO_ADDR`, `SESAME_OPENBAO_MOUNT`, `SESAME_OPENBAO_PATH_PREFIX`, `SESAME_OPENBAO_NAMESPACE` | comme le proxy | Coffre |
| `SESAME_OPENBAO_ROLE_ID`, `SESAME_OPENBAO_SECRET_ID` 🔒 | requis | AppRole **de l'admin** (écriture sans lecture) |

URL de redirection à déclarer chez le fournisseur d'identité : `<SESAME_ADMIN_PUBLIC_URL>/auth/callback`.

## Commun

| Variable | Défaut | Rôle |
|---|---|---|
| `RUST_LOG` | `info` | Niveau des logs JSON (`tracing`) |

Les lignes d'audit sont écrites sur stdout avec `"log_type":"audit"`, pour que la chaîne de collecte les route vers le journal d'audit dédié.
