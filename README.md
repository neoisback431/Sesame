<p align="center"><img src="ressources/SesamBaniere.png" alt="SEsame : la clé d'un accès universel" width="640"></p>

# Sesame

Portail SSO à injection de credentials côté serveur, pour les applications web qui n'offrent qu'un formulaire login / mot de passe.

L'utilisateur s'authentifie une fois auprès du fournisseur d'identité de son organisation (OIDC : Entra ID, Keycloak, Okta…). Sesame rejoue ensuite, côté serveur, la connexion à chaque application avec des identifiants lus dans un coffre de secrets (OpenBao, Vault…). **Aucun mot de passe applicatif ni cookie de session applicatif n'atteint le navigateur.**

> État : MVP. Connexion OIDC, page « Mes applications », rejeu du login (formulaire HTML ou page construite en JavaScript), injection de session et détection d'expiration fonctionnent de bout en bout sur l'appli factice. Un mode « remise » (handoff), facultatif, couvre les applis qui gardent leur session dans le navigateur. L'UI d'administration gère les applis (fichiers Git ou base, rechargées à chaud), le registre des comptes, les identifiants applicatifs et le diagnostic des rejeux en échec. L'embarquement fournit `sesame-onboard` : recorder (analyse d'une page de login, avec compte de test facultatif, aussi appelable depuis l'administration), vérification d'un descripteur et test de santé des formulaires de login.

## Documentation

- [Architecture](docs/architecture.md)
- [Descripteur d'appli](docs/descriptor.md)
- [Configuration](docs/configuration.md)
- [Environnement de dev](docs/dev.md)
- [Décisions d'architecture](docs/decisions/)

## Démarrage rapide

```sh
make up
# puis https://sesame.localhost:8443 (alice / alice)
```

## Structure du dépôt

| Dossier | Contenu |
|---|---|
| `crates/sesame-core` | Cœur Rust : modèle des descripteurs, interfaces des briques externes, types secrets, audit |
| `crates/sesame-portal` | Portail d'authentification (Rust) |
| `crates/sesame-proxy` | Moteur de proxy (Rust) |
| `crates/sesame-store-postgres` | Magasin de sessions, registre des comptes, descripteurs en base et diagnostics (PostgreSQL) |
| `crates/sesame-secrets-openbao` | Coffre OpenBao / Vault |
| `onboarding/` | Embarquement : `sesame-onboard` (recorder, vérification, empreinte, test de santé) et service `sesame-recorder` |
| `admin/` | UI web d'administration (Python, FastAPI) |
| `schemas/` | Schéma JSON du descripteur d'appli |
| `descriptors/` | Descripteurs d'applis (YAML versionné) |
| `deploy/` | Nginx, Dockerfiles |
| `dev/` | Appli factice, realm Keycloak, seed OpenBao |
| `docs/` | Architecture, configuration, décisions |
| `tests/e2e/` | Tests bout en bout (Playwright) |
| `scripts/` | Outillage (validation des descripteurs…) |

## Licence

[Apache-2.0](LICENSE)
