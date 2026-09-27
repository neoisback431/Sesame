# Sesame

Portail SSO à injection de credentials côté serveur, pour les applications web qui n'offrent qu'un formulaire login / mot de passe.

L'utilisateur s'authentifie une fois auprès du fournisseur d'identité de son organisation (OIDC : Entra ID, Keycloak, Okta…). Sesame rejoue ensuite, côté serveur, la connexion à chaque application avec des identifiants lus dans un coffre de secrets (OpenBao, Vault…). **Aucun mot de passe applicatif ni cookie de session applicatif n'atteint le navigateur.**

> État : initialisation. Le schéma des descripteurs, l'environnement de dev et les interfaces du cœur sont en place ; le moteur de proxy (rejeu, injection de session) est en cours.

## Documentation

- [Architecture](docs/architecture.md)
- [Descripteur d'appli](docs/descriptor.md)
- [Environnement de dev](docs/dev.md)
- [Décisions d'architecture](docs/decisions/)

## Démarrage rapide

```sh
make up
# puis https://fake-app.sesame.localhost:8443
```

## Structure du dépôt

| Dossier | Contenu |
|---|---|
| `crates/sesame-core` | Cœur Rust : modèle des descripteurs, interfaces des briques externes, types secrets, audit |
| `crates/sesame-portal` | Portail d'authentification (Rust) |
| `crates/sesame-proxy` | Moteur de proxy (Rust) |
| `onboarding/` | Module d'embarquement (Python, Playwright) |
| `admin/` | UI web d'administration (Python) |
| `schemas/` | Schéma JSON du descripteur d'appli |
| `descriptors/` | Descripteurs d'applis (YAML versionné) |
| `deploy/` | Nginx, Dockerfiles |
| `dev/` | Appli factice, realm Keycloak, seed OpenBao |
| `docs/` | Architecture, décisions |
| `scripts/` | Outillage (validation des descripteurs…) |

## Licence

[Apache-2.0](LICENSE)
