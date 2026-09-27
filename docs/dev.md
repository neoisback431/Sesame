# Environnement de dev

## Prérequis

- Docker avec Compose v2
- `openssl`, `make`
- Pour développer hors conteneurs : Rust stable (≥ 1.85) et [`uv`](https://docs.astral.sh/uv/) (Python ≥ 3.11)

## Démarrer

```sh
make up          # génère le certificat de dev puis lance docker compose
```

| URL | Service |
|---|---|
| https://fake-app.sesame.localhost:8443 | Appli factice, via le moteur de proxy |
| https://sesame.localhost:8443 | Portail |
| https://idp.sesame.localhost:8443 | Keycloak (admin de la console : `kcadmin` / `kcadmin`) |
| http://127.0.0.1:8200 | OpenBao (jeton root de dev : `dev-root-token`) |

Le certificat est signé par une CA de dev, `deploy/nginx/certs/ca.crt`. Importez-la dans le navigateur, ou acceptez l'avertissement.

Les navigateurs résolvent `*.localhost` vers la boucle locale. Pour les outils en ligne de commande sous Linux, ajoutez si besoin dans `/etc/hosts` :

```
127.0.0.1 sesame.localhost idp.sesame.localhost fake-app.sesame.localhost
```

## Comptes de dev

Toutes les valeurs ci-dessous sont publiques et réservées au dev.

| Compte SSO (Keycloak) | Mot de passe | Groupes | Compte applicatif (coffre) |
|---|---|---|---|
| `alice` | `alice` | `fake-app-users` | `amartin` / `dev-amartin-app-password` |
| `bob` | `bob` | aucun (accès refusé à l'appli factice) | aucun |
| `admin` | `admin` | `sesame-admins` | aucun |

Le compte applicatif d'alice (`amartin`) diffère de son compte SSO. alice ne le connaît pas : seul le proxy le lit dans le coffre (`secret/sesame/apps/fake-app/users/alice`).

## Services

| Service | Rôle en dev |
|---|---|
| `nginx` | TLS, routage par nom d'hôte. Porte des alias réseau pour que les conteneurs joignent l'IdP et le portail par les mêmes URLs que le navigateur, donc avec le même `issuer` OIDC. |
| `portal`, `proxy` | Services Rust. Squelettes à ce stade : `/healthz`, et chargement des descripteurs pour le proxy. |
| `postgres` | Magasin de sessions |
| `openbao` + `openbao-seed` | Coffre en mode dev. Le seed crée l'AppRole du proxy (lecture seule) et les identifiants de test. |
| `keycloak` | Fournisseur OIDC de dev, realm importé depuis `dev/keycloak/sesame-realm.json` |
| `fake-app` | Appli cible : formulaire de login, jeton CSRF à usage unique, champ caché, session serveur de 5 min. Aucun port publié. |

## Commandes

```sh
make test                  # tests Rust + Python
make lint                  # fmt, clippy, ruff, validation des descripteurs
make validate-descriptors
make deny                  # licences des dépendances Rust (nécessite cargo-deny)
make down
```
