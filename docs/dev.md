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
| https://admin.sesame.localhost:8443 | Administration (compte `admin`) |
| https://idp.sesame.localhost:8443 | Keycloak (admin de la console : `kcadmin` / `kcadmin`) |
| http://127.0.0.1:8200 | OpenBao (jeton root de dev : `dev-root-token`) |

Le certificat est signé par une CA de dev, `deploy/nginx/certs/ca.crt`. Importez-la dans le navigateur, ou acceptez l'avertissement.

Les navigateurs résolvent `*.localhost` vers la boucle locale. Pour les outils en ligne de commande sous Linux, ajoutez si besoin dans `/etc/hosts` :

```
127.0.0.1 sesame.localhost idp.sesame.localhost fake-app.sesame.localhost admin.sesame.localhost fake-app-bis.sesame.localhost
```

## Comptes de dev

Toutes les valeurs ci-dessous sont publiques et réservées au dev.

| Compte SSO (Keycloak) | Mot de passe | Groupes | Compte applicatif (coffre) |
|---|---|---|---|
| `alice` | `alice` | `fake-app-users` | `amartin` / `dev-amartin-app-password` |
| `bob` | `bob` | aucun (accès refusé à l'appli factice) | aucun |
| `carol` | `carol` | `fake-app-users` | aucun au départ : à enregistrer dans l'admin avec `cdupont` / `dev-cdupont-app-password` |
| `admin` | `admin` | `sesame-admins` (accès à l'administration) | aucun |

Le compte applicatif d'alice (`amartin`) diffère de son compte SSO. alice ne le connaît pas : seul le proxy le lit dans le coffre (`secret/sesame/apps/fake-app/users/alice`).

## Services

| Service | Rôle en dev |
|---|---|
| `nginx` | TLS, routage par nom d'hôte. Porte des alias réseau pour que les conteneurs joignent l'IdP et le portail par les mêmes URLs que le navigateur, donc avec le même `issuer` OIDC. |
| `portal` | Portail : connexion OIDC, session, page « Mes applications ». Redémarre tant que Nginx n'est pas prêt (discovery OIDC). |
| `proxy` | Moteur de proxy : rejeu du login, injection de session, expiration. |
| `postgres` | Magasin de sessions et registre des comptes (migrations appliquées au démarrage du portail et du proxy) |
| `db-seed` | Déclare le compte d'alice sur l'appli factice dans le registre des comptes (raccourci de dev) |
| `admin` | UI d'administration (Python) : registre des comptes et identifiants applicatifs |
| `openbao` + `openbao-seed` | Coffre en mode dev. Le seed (idempotent) crée l'AppRole du proxy (lecture seule), celui de l'admin (écriture sans lecture) et les identifiants de test. |
| `keycloak` | Fournisseur OIDC de dev, realm importé depuis `dev/keycloak/sesame-realm.json` |
| `health` | Test de santé des formulaires de login (profil `tools`, lancé à la demande : `make health`) |
| `fake-app` | Appli cible : formulaire de login, jeton CSRF à usage unique, champ caché, session serveur de 5 min. Aucun port publié. |

## Parcours à essayer

1. Ouvrez https://sesame.localhost:8443 et connectez-vous avec `alice` / `alice`.
2. La page « Mes applications » affiche « Appli factice ». Cliquez dessus : vous arrivez connecté en tant qu'`amartin`, sans avoir saisi ce compte.
3. Avec `bob` / `bob`, aucune tuile n'apparaît et l'accès direct à l'appli est refusé.
4. `docker compose restart fake-app` fait perdre ses sessions à l'appli. Rechargez la page : Sesame rejoue le login sans que vous le voyiez.
5. Avec `carol` / `carol`, aucune tuile : elle est habilitée mais n'a pas de compte. Dans https://admin.sesame.localhost:8443 (`admin` / `admin`), ouvrez « Appli factice » et enregistrez `carol` avec `cdupont` / `dev-cdupont-app-password`. Rechargez le portail de carol : la tuile apparaît.
6. Dans l'administration, « Nouvelle application » crée une appli sans redémarrage : par exemple `fake-app-bis`, hôte public `fake-app-bis.sesame.localhost:8443`, URL `http://fake-app:8000`, groupe `fake-app-users`, sélecteur `form#login-form`, champ CSRF `csrf_token`, cookie `FAKEAPPSESSID`. Après un compte enregistré pour `alice`, la tuile apparaît dans son portail sous une dizaine de secondes (`SESAME_DESCRIPTORS_RELOAD`).
7. `docker compose logs proxy admin | grep audit` montre les événements d'audit (lecture du coffre, rejeu, expiration, actions d'administration).

## Commandes

```sh
make test                  # tests Rust + Python (appli factice, admin, embarquement)
make test-postgres         # tests de contrat du magasin sur une base PostgreSQL jetable
make e2e                   # parcours bout en bout Playwright (après make up)
make health                # test de santé des formulaires de login (après make up)
make lint                  # fmt, clippy, ruff, validation des descripteurs
make validate-descriptors
make deny                  # licences des dépendances Rust (cargo-deny) et Python
make down
```

## Embarquer une appli

```sh
cp descriptors/TEMPLATE.yaml.example descriptors/mon-appli.yaml   # puis compléter
make validate-descriptors
cd onboarding
uv run sesame-onboard verify ../descriptors/mon-appli.yaml        # compte de test demandé
uv run sesame-onboard fingerprint ../descriptors/mon-appli.yaml   # empreinte à reporter
```

`verify` et `fingerprint` doivent pouvoir joindre `spec.upstream.base_url`. Pour une appli de l'environnement de dev, lancez-les dans le réseau du compose, par exemple `docker compose run --rm --entrypoint sesame-onboard health --schema /etc/sesame/app-descriptor.schema.json fingerprint /etc/sesame/descriptors/fake-app.yaml`.
