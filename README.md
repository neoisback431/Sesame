# Sesame

Portail SSO à injection de credentials côté serveur, pour les applications web qui n'offrent qu'un formulaire login / mot de passe.

L'utilisateur s'authentifie une fois auprès du fournisseur d'identité de son organisation (OIDC : Entra ID, Keycloak, Okta…). Sesame rejoue ensuite, côté serveur, la connexion à chaque application avec des identifiants lus dans un coffre de secrets (OpenBao, Vault…). **Aucun mot de passe applicatif ni cookie de session applicatif n'atteint le navigateur.**

> État : MVP. Connexion OIDC, page « Mes applications », rejeu du login, injection de session et détection d'expiration fonctionnent de bout en bout sur l'appli factice. L'UI d'administration et le module d'embarquement restent à faire.

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
| `crates/sesame-store-postgres` | Magasin de sessions et registre des comptes PostgreSQL |
| `crates/sesame-secrets-openbao` | Coffre OpenBao / Vault |
| `onboarding/` | Module d'embarquement (Python, Playwright) |
| `admin/` | UI web d'administration (Python) |
| `schemas/` | Schéma JSON du descripteur d'appli |
| `descriptors/` | Descripteurs d'applis (YAML versionné) |
| `deploy/` | Nginx, Dockerfiles |
| `dev/` | Appli factice, realm Keycloak, seed OpenBao |
| `docs/` | Architecture, configuration, décisions |
| `tests/e2e/` | Tests bout en bout (Playwright) |
| `scripts/` | Outillage (validation des descripteurs…) |

## Licence

[Apache-2.0](LICENSE)
