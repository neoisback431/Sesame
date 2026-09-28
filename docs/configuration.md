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
| `SESAME_DESCRIPTORS_DIR` | `descriptors` | Dossier des descripteurs en fichiers (Git, chargés au démarrage ; un fichier invalide empêche le démarrage). Absent : aucun descripteur en fichier |
| `SESAME_DESCRIPTORS_RELOAD` | `10s` | Intervalle de vérification des descripteurs en base (créés dans l'administration). Le catalogue n'est rechargé que s'il a changé ; une appli créée, modifiée ou supprimée est prise en compte sans redémarrage |
| `SESAME_DATABASE_URL` 🔒 | requis | Connexion PostgreSQL |
| `SESAME_PORTAL_STATE_KEY` 🔒 | requis | Clé chiffrant l'état OIDC temporaire |
| `SESAME_CA_FILE` | aucun | CA supplémentaire (PEM) pour joindre le fournisseur d'identité |
| `SESAME_OIDC_ISSUER` | requis | URL de l'émetteur OIDC (discovery) |
| `SESAME_OIDC_CLIENT_ID` | requis | Identifiant du client OIDC |
| `SESAME_OIDC_CLIENT_SECRET` 🔒 | requis | Secret du client OIDC |
| `SESAME_OIDC_SCOPES` | `openid profile email` | Scopes demandés |
| `SESAME_OIDC_USER_KEY_CLAIM` | `sub` | Claim servant de clé utilisateur (coffre, registre). Pour Entra ID : `oid` |
| `SESAME_OIDC_GROUPS_CLAIM` | `groups` | Claim portant les groupes. Absent = aucun groupe |
| `SESAME_OIDC_LOGOUT` | `false` | `true` : la déconnexion ferme aussi la session chez le fournisseur d'identité (RP-Initiated Logout). Sans `end_session_endpoint` dans la discovery, déconnexion locale seulement (avertissement au démarrage) |

URL de redirection à déclarer chez le fournisseur d'identité : `<SESAME_PUBLIC_URL>/auth/callback`. Avec `SESAME_OIDC_LOGOUT`, déclarer aussi l'URL de retour après déconnexion : `<SESAME_PUBLIC_URL>/auth/logged-out`.

## Moteur de proxy (`sesame-proxy`)

| Variable | Défaut | Rôle |
|---|---|---|
| `SESAME_PROXY_LISTEN` | `0.0.0.0:8081` | Adresse d'écoute |
| `SESAME_PORTAL_URL` | requis | URL publique du portail (redirections de connexion, liens de retour) |
| `SESAME_COOKIE_NAME` | `sesame_session` | Identique au portail |
| `SESAME_COOKIE_DOMAIN` | aucun | Identique au portail |
| `SESAME_DESCRIPTORS_DIR` | `descriptors` | Identique au portail |
| `SESAME_DESCRIPTORS_RELOAD` | `10s` | Identique au portail |
| `SESAME_REPLAY_DEBUG` | `false` | Conserve, pour chaque compte, la dernière réponse de l'appli lors d'un rejeu en échec (statut, en-têtes, corps tronqué à 64 Ko), consultable dans l'administration (« Voir la réponse de l'appli »). Valeurs du coffre (brutes et encodées) et valeurs des cookies masquées. Activé en dev ; à n'activer en production qu'en connaissance de cause (ADR 0018) |
| `SESAME_DATABASE_URL` 🔒 | requis | Connexion PostgreSQL |
| `SESAME_SESSION_ENCRYPTION_KEY` 🔒 | requis | Clé chiffrant les cookies applicatifs au repos |
| `SESAME_CA_FILE` | aucun | CA supplémentaire (PEM) pour joindre les applis et le coffre |
| `SESAME_MAX_BODY_BYTES` | `33554432` | Taille maximale d'un corps de requête relayé |
| `SESAME_SECRET_STORE` | `postgres` | Implémentation du coffre : `postgres` (ADR 0021, table `app_secrets` du même PostgreSQL, pas de brique externe supplémentaire), ou `openbao` / `vault` (même API) |
| `SESAME_SECRETS_ENCRYPTION_KEY` 🔒 | requis si `postgres` | Clé (32 octets, base64) chiffrant les secrets dans `app_secrets`. **Identique** à celle de l'admin (`SESAME_SECRETS_ENCRYPTION_KEY`), **distincte** de `SESAME_SESSION_ENCRYPTION_KEY` |
| `SESAME_OPENBAO_ADDR` | requis si `openbao`/`vault` | URL du coffre |
| `SESAME_OPENBAO_MOUNT` | `secret` | Point de montage KV v2 |
| `SESAME_OPENBAO_PATH_PREFIX` | `sesame/apps` | Préfixe : `<mount>/<prefix>/<app_id>/users/<user_key>` |
| `SESAME_OPENBAO_ROLE_ID` | requis si `openbao`/`vault` | AppRole du proxy |
| `SESAME_OPENBAO_SECRET_ID` 🔒 | requis si `openbao`/`vault` | Secret de l'AppRole |
| `SESAME_OPENBAO_NAMESPACE` | aucun | Espace de noms, le cas échéant |

En mode `postgres` (par défaut), le rôle PostgreSQL du proxy n'a besoin que du droit
`SELECT` sur `app_secrets` ; recommandé en production, non forcé par le code (ADR 0021).

## UI d'administration (`sesame-admin`)

| Variable | Défaut | Rôle |
|---|---|---|
| `SESAME_ADMIN_LISTEN` | `0.0.0.0:8000` | Adresse d'écoute |
| `SESAME_ADMIN_PUBLIC_URL` | requis | URL publique, ex. `https://admin.sesame.example` |
| `SESAME_ADMIN_SESSION_KEY` 🔒 | requis | Clé de signature du cookie de session (longue chaîne aléatoire) |
| `SESAME_ADMIN_SESSION_TTL_SECS` | `3600` | Durée de la session d'administration |
| `SESAME_ADMIN_GROUP` | `sesame-admins` | Groupe (claim) requis pour accéder à l'UI |
| `SESAME_DESCRIPTORS_DIR` | `descriptors` | Dossier des descripteurs en fichiers, affichés en lecture seule |
| `SESAME_SCHEMA_FILE` | `schemas/app-descriptor.schema.json` | Schéma JSON contre lequel sont validés les descripteurs saisis dans l'éditeur |
| `SESAME_DATABASE_URL` 🔒 | requis | Connexion PostgreSQL (registre des comptes, descripteurs en base) |
| `SESAME_CA_FILE` | aucun | CA supplémentaire (PEM) pour joindre le fournisseur d'identité et le coffre |
| `SESAME_OIDC_ISSUER`, `SESAME_OIDC_CLIENT_ID`, `SESAME_OIDC_CLIENT_SECRET` 🔒, `SESAME_OIDC_SCOPES`, `SESAME_OIDC_USER_KEY_CLAIM`, `SESAME_OIDC_GROUPS_CLAIM` | comme le portail | Client OIDC **dédié** à l'administration |
| `SESAME_SECRET_STORE` | `postgres` | Comme le proxy ; les deux doivent être configurés de la même façon |
| `SESAME_SECRETS_ENCRYPTION_KEY` 🔒 | requis si `postgres` | **Identique** à celle du proxy (ADR 0021) : l'admin chiffre, le proxy déchiffre. En production, écrire avec un rôle PostgreSQL sans droit `SELECT` sur `app_secrets` (recommandé, non forcé par le code) |
| `SESAME_OPENBAO_ADDR`, `SESAME_OPENBAO_MOUNT`, `SESAME_OPENBAO_PATH_PREFIX`, `SESAME_OPENBAO_NAMESPACE` | comme le proxy | Coffre, si `SESAME_SECRET_STORE=openbao`/`vault` |
| `SESAME_OPENBAO_ROLE_ID`, `SESAME_OPENBAO_SECRET_ID` 🔒 | requis si `openbao`/`vault` | AppRole **de l'admin** (écriture sans lecture) |
| `SESAME_RECORDER_URL` | aucun | URL du service recorder interne, ex. `http://recorder:8090`. Active le bouton « Analyser une page de login » |
| `SESAME_RECORDER_TOKEN` 🔒 | aucun | Jeton partagé avec le recorder. Le bouton n'apparaît que si l'URL **et** le jeton sont fournis |

URL de redirection à déclarer chez le fournisseur d'identité : `<SESAME_ADMIN_PUBLIC_URL>/auth/callback`.

## Service recorder (`sesame-recorder`)

Service HTTP **interne** d'analyse d'une page de login, appelé par l'administration (ADR 0016). Jamais exposé via Nginx.

| Variable | Défaut | Rôle |
|---|---|---|
| `SESAME_RECORDER_LISTEN` | `0.0.0.0:8090` | Adresse d'écoute |
| `SESAME_RECORDER_TOKEN` 🔒 | requis | Jeton attendu (`Authorization: Bearer`), partagé avec l'admin |
| `SESAME_RECORDER_SCHEMA` | schéma par défaut | Schéma JSON de validation du descripteur proposé |
| `SESAME_RECORDER_TIMEOUT` | `20` | Délai (s) d'analyse d'une page |
| `SESAME_APPS_DOMAIN` | aucun | Domaine des applis exposées par Sesame (ex. `sesame.localhost:8443` en dev, `apps.example.org` en production) : l'hôte public proposé est `<id>.<domaine>`. Doit être résolu (DNS) vers Nginx. Absent : `<id>.sesame.example`, signalé à corriger. Lu aussi par `sesame-onboard record` |
| `SESAME_CA_FILE` | aucun | CA supplémentaire (PEM) pour joindre les applis en TLS |
| `SESAME_RECORDER_INSECURE` | `false` | Ne pas vérifier TLS (dev uniquement) |
| `SESAME_ONBOARD_CHROMIUM` | aucun | Exécutable Chromium, si ce n'est pas celui de l'image |

Aucune allowlist anti-SSRF : le recorder ouvre l'URL fournie (choix de l'exploitant, voir ADR 0016). Garde-fous : service interne, jeton obligatoire, déclencheur réservé aux administrateurs, audit de chaque analyse.

## Outil d'embarquement (`sesame-onboard`)

| Variable | Rôle |
|---|---|
| `SESAME_ONBOARD_<CLÉ>` 🔒 | Identifiants du compte de test pour `verify`, une variable par clé de `credentials.keys` (ex. `SESAME_ONBOARD_USERNAME`, `SESAME_ONBOARD_PASSWORD`). À défaut, saisie masquée |
| `SESAME_ONBOARD_CHROMIUM` | Exécutable Chromium du recorder (`record`), si ce n'est pas celui installé par Playwright |

Options : `--schema` (schéma JSON), `--ca-file`, `--insecure` (dev uniquement), `--timeout`. `health`, `fingerprint` et `record` n'utilisent aucun identifiant.

Options de `record` : `--base-url`, `--protected-path` (page protégée sondée, `/` par défaut), `--probe-failure` (envoie une connexion factice pour observer l'échec), `--id`, `--name`, `--public-host`, `--group` / `--user` (répétables), `--session-cookie`, `--chromium`, `-o` (fichier de sortie). Le recorder nécessite l'extra `capture` (`pip install 'sesame-onboarding[capture]'`, puis `playwright install chromium`) ou l'image `recorder` (`make record`). `--ca-file` ne s'applique pas au navigateur : utiliser le magasin de certificats du système ou, en dev, `--insecure`.

## Commun

| Variable | Défaut | Rôle |
|---|---|---|
| `RUST_LOG` | `info` | Niveau des logs JSON (`tracing`) |

Les lignes d'audit sont écrites sur stdout avec `"log_type":"audit"`, pour que la chaîne de collecte les route vers le journal d'audit dédié.
