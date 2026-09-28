# Environnement de dev

## Prérequis

- Docker avec Compose v2
- `openssl`, `make`
- Pour développer hors conteneurs : Rust stable (≥ 1.85) et [`uv`](https://docs.astral.sh/uv/) (Python ≥ 3.11)

## Démarrer

```sh
make up           # génère le certificat de dev puis lance docker compose (sans l'appli factice)
make up-demo      # comme make up, avec en plus l'appli factice de démo (profil demo)
```

`make up` suffit pour le cœur de Sesame (portail, proxy, admin, coffre, IdP). L'appli
factice, le compte de dev d'alice et sa connexion applicative sont **facultatifs**
(profil Compose `demo`) : `make up-demo`, ou `docker compose --profile demo up`. Le
« Parcours à essayer » ci-dessous, `make health`, `make e2e` et `make record` en
supposent le démarrage.

| URL | Service |
|---|---|
| https://sesame.localhost:8443 | Portail : page « Mes applications » |
| https://fake-app.sesame.localhost:8443 | Appli factice, via le moteur de proxy (`make up-demo`) |
| https://admin.sesame.localhost:8443 | Administration (compte `admin`) |
| https://idp.sesame.localhost:8443 | Keycloak (admin de la console : `kcadmin` / `kcadmin`) |

Le certificat est signé par une CA de dev, `deploy/nginx/certs/ca.crt`. Importez-la dans le navigateur, ou acceptez l'avertissement.

Les navigateurs résolvent `*.localhost` vers la boucle locale. Pour les outils en ligne de commande sous Linux, ajoutez si besoin dans `/etc/hosts` :

```
127.0.0.1 sesame.localhost idp.sesame.localhost fake-app.sesame.localhost admin.sesame.localhost fake-app-bis.sesame.localhost
```

## Comptes de dev

Toutes les valeurs ci-dessous sont publiques et réservées au dev. Le compte applicatif d'alice n'existe qu'avec `make up-demo` (profil `demo`).

| Compte SSO (Keycloak) | Mot de passe | Groupes | Compte applicatif (coffre) |
|---|---|---|---|
| `alice` | `alice` | `fake-app-users` | `amartin` / `dev-amartin-app-password` |
| `bob` | `bob` | aucun (accès refusé à l'appli factice) | aucun |
| `carol` | `carol` | `fake-app-users` | aucun au départ : à enregistrer dans l'admin avec `cdupont` / `dev-cdupont-app-password` |
| `admin` | `admin` | `sesame-admins` (accès à l'administration ; lien « Administration » sur « Mes applications ») | aucun |

Le compte applicatif d'alice (`amartin`) diffère de son compte SSO. alice ne le connaît pas : seul le proxy le lit dans le coffre (table `app_secrets`, ADR 0021 ; `secret/sesame/apps/fake-app/users/alice` avec `docker-compose.openbao.yml`).

## Services

| Service | Rôle en dev |
|---|---|
| `nginx` | TLS, routage par nom d'hôte. Porte des alias réseau pour que les conteneurs joignent l'IdP et le portail par les mêmes URLs que le navigateur, donc avec le même `issuer` OIDC. |
| `portal` | Portail : connexion OIDC, session, page « Mes applications ». Redémarre tant que Nginx n'est pas prêt (discovery OIDC). |
| `proxy` | Moteur de proxy : rejeu du login, injection de session (ou remise en mode handoff), expiration. Diagnostic des rejeux activé (`SESAME_REPLAY_DEBUG=true`). |
| `postgres` | Magasin de sessions et registre des comptes (migrations appliquées au démarrage du portail et du proxy) |
| `db-seed` | Facultatif (profil `demo`) : déclare le compte d'alice sur l'appli factice dans le registre des comptes (raccourci de dev) |
| `admin` | UI d'administration (Python) : registre des comptes et identifiants applicatifs |
| `secrets-seed` | Facultatif (profil `demo`) : écrit le couple (fake-app, alice) chiffré dans `app_secrets`, avec la clé du proxy et de l'admin. |
| `keycloak` | Fournisseur OIDC de dev, realm importé depuis `dev/keycloak/sesame-realm.json` |
| `health` | Test de santé des formulaires de login (profils `tools` + `demo`, lancé à la demande : `make health`) |
| `recorder` | Service HTTP interne d'analyse d'une page de login (Chromium headless, image Playwright). Appelé par l'admin (« Analyser une page de login ») ; aussi `make record URL=…` en ligne de commande. Jeton de dev : `dev-recorder-token`. |
| `fake-app` | Facultatif (profil `demo`) : appli cible, formulaire de login, jeton CSRF à usage unique, champ caché, session serveur de 5 min. Aucun port publié. |

Coffre de secrets : PostgreSQL par défaut (ci-dessus), sans service supplémentaire. Pour
démontrer l'implémentation alternative OpenBao / Vault (ADR 0007, ADR 0021) :
`docker compose -f docker-compose.yml -f docker-compose.openbao.yml up`, qui ajoute
`openbao` + `openbao-seed` et bascule `proxy` / `admin` sur `SESAME_SECRET_STORE=openbao`
(jeton root de dev sur http://127.0.0.1:8200 : `dev-root-token`).

## Parcours à essayer

Nécessite `make up-demo` (appli factice, profil `demo`).

1. Ouvrez https://sesame.localhost:8443 et connectez-vous avec `alice` / `alice`.
2. La page « Mes applications » affiche « Appli factice ». Cliquez dessus : un **nouvel onglet** s'ouvre, vous arrivez connecté en tant qu'`amartin`, sans avoir saisi ce compte. Revenez à l'onglet du portail et cliquez **« Déconnecter »** sur la tuile : la session applicative est coupée (`app_sessions` vidée pour cette appli) sans vous déconnecter du portail ; un nouveau clic sur la tuile rejoue le login, transparent.
3. Avec `bob` / `bob`, aucune tuile n'apparaît et l'accès direct à l'appli est refusé.
4. Connectez-vous avec `admin` / `admin` : un bouton **« Administration »** apparaît en haut de la page (groupe `sesame-admins`), absent pour `alice` et `bob`. Il mène à https://admin.sesame.localhost:8443.
5. `docker compose restart fake-app` fait perdre ses sessions à l'appli. Rechargez la page : Sesame rejoue le login sans que vous le voyiez.
6. Avec `carol` / `carol`, la tuile apparaît **grisée** : elle est habilitée mais n'a pas de compte (ADR 0022). Dans https://admin.sesame.localhost:8443 (`admin` / `admin`), ouvrez « Appli factice » et enregistrez `carol` avec `cdupont` / `dev-cdupont-app-password`. Rechargez le portail de carol : la tuile devient cliquable.
7. Dans l'administration, « Nouvelle application » crée une appli sans redémarrage : par exemple `fake-app-bis`, hôte public `fake-app-bis.sesame.localhost:8443`, URL `http://fake-app:8000`, groupe `fake-app-users` (facultatif : sans groupe, le compte suffit), sélecteur `form#login-form`, champ CSRF `csrf_token`, cookie `FAKEAPPSESSID`. Après un compte enregistré pour `alice`, la tuile apparaît dans son portail sous une dizaine de secondes (`SESAME_DESCRIPTORS_RELOAD`).
8. Dans « Nouvelle application », le bouton **« Analyser une page de login »** avec `http://fake-app:8000/login` interroge le service recorder et pré-remplit l'éditeur avec un descripteur proposé (à relire, notamment le cookie de session). Avec le compte de test `amartin` / `dev-amartin-app-password`, le recorder se connecte réellement et propose un descripteur complet (cookie de session et succès observés). La case « Mode handoff » rédige un descripteur en mode remise (ADR 0020). En ligne de commande : `make record URL=http://fake-app:8000/login ARGS="--id fake-app --probe-failure"` (ajouter `--test-account` pour le compte de test, `--handoff` pour le mode remise).
9. Enregistrez pour carol un mot de passe erroné : à son clic, le rejeu échoue (page neutre, compte `failed`). Dans l'administration, « Voir la réponse de l'appli » sur la ligne du compte montre la réponse de l'appli, identifiants et cookies masqués (ADR 0018).
10. `docker compose logs proxy admin | grep audit` montre les événements d'audit (lecture du coffre, rejeu, expiration, actions d'administration).

## Commandes

```sh
make test                  # tests rapides : Rust + Python, sans navigateur (~10 s)
make test-full             # tests complets : + tests Playwright du recorder + contrat PostgreSQL (si Docker)
make test-postgres         # tests de contrat du magasin sur une base PostgreSQL jetable
make e2e                   # parcours bout en bout Playwright (après make up-demo)
make health                # test de santé des formulaires de login (après make up-demo)
make record URL=…        # recorder : analyse une page de login, propose un descripteur (après make up)
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
