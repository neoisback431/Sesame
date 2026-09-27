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
| https://sesame.localhost:8443 | Portail : page « Mes applications » |
| https://fake-app.sesame.localhost:8443 | Appli factice, via le moteur de proxy |
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
| `portal` | Portail : connexion OIDC, session, page « Mes applications ». Redémarre tant que Nginx n'est pas prêt (discovery OIDC). |
| `proxy` | Moteur de proxy : rejeu du login, injection de session, expiration. |
| `postgres` | Magasin de sessions et registre des comptes (migrations appliquées au démarrage du portail et du proxy) |
| `db-seed` | Déclare le compte d'alice sur l'appli factice dans le registre des comptes |
| `openbao` + `openbao-seed` | Coffre en mode dev. Le seed crée l'AppRole du proxy (lecture seule) et les identifiants de test. |
| `keycloak` | Fournisseur OIDC de dev, realm importé depuis `dev/keycloak/sesame-realm.json` |
| `fake-app` | Appli cible : formulaire de login, jeton CSRF à usage unique, champ caché, session serveur de 5 min. Aucun port publié. |

## Parcours à essayer

1. Ouvrez https://sesame.localhost:8443 et connectez-vous avec `alice` / `alice`.
2. La page « Mes applications » affiche « Appli factice ». Cliquez dessus : vous arrivez connecté en tant qu'`amartin`, sans avoir saisi ce compte.
3. Avec `bob` / `bob`, aucune tuile n'apparaît et l'accès direct à l'appli est refusé.
4. `docker compose restart fake-app` fait perdre ses sessions à l'appli. Rechargez la page : Sesame rejoue le login sans que vous le voyiez.
5. `docker compose logs proxy | grep audit` montre les événements d'audit (lecture du coffre, rejeu, expiration).

## Commandes

```sh
make test                  # tests Rust + Python
make test-postgres         # tests de contrat du magasin sur une base PostgreSQL jetable
make e2e                   # parcours bout en bout Playwright (après make up)
make lint                  # fmt, clippy, ruff, validation des descripteurs
make validate-descriptors
make deny                  # licences des dépendances Rust (nécessite cargo-deny)
make down
```
