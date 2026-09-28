# Notes de version

Toutes les évolutions notables de Sesame. Format inspiré de
[Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ; versions conformes au
[versionnage sémantique](https://semver.org/lang/fr/) (en 0.x, une version mineure peut
contenir des changements incompatibles).

Notes détaillées de chaque version : [`docs/releases/`](docs/releases/).

## [Non publié]

- ☁️ **Kit AWS** `deploy/aws/` (aussi joint à chaque Release) : Terraform / OpenTofu, ECS Fargate, RDS PostgreSQL, ALB + certificat ACM, clés générées dans Secrets Manager, dans un VPC existant.
- 🐳 **Kit de déploiement** `deploy/release/` (aussi joint à chaque Release) : images publiées, un domaine, un fournisseur d'identité, clés générées par `generate-keys.sh`, Nginx configuré automatiquement. Installation en cinq étapes décrite dans le README.
- 🐳 Images de l'admin et du recorder autonomes : schéma des descripteurs intégré.
- 📚 README réécrit autour de l'installation, de la configuration minimale et de l'ajout d'une application.
- 🐳 `docker compose` ne lance plus que Sesame (portail, proxy, admin, recorder) avec PostgreSQL et Nginx : le Keycloak de dev devient facultatif (commenté dans `docker-compose.yml`, version autonome), et le fournisseur d'identité se branche par un fichier `.env` (voir `.env.example`).
- 🧰 Workflow de release : `actions/checkout@v5` (Node.js 24).

## [0.1.0] - 2026-09-28

Première version publique. Notes complètes : [docs/releases/v0.1.0.md](docs/releases/v0.1.0.md).

- ✨ Portail SSO **OIDC ou SAML 2.0**, page « Mes applications » (nouvel onglet, déconnexion par appli, tuile grisée sans compte), habilitations facultatives par groupes.
- 🔁 Moteur de proxy : rejeu côté serveur des formulaires HTML et des logins JavaScript, jetons CSRF (y compris par appel d'API), expiration et rejeu transparents, mode « remise » (handoff) facultatif.
- 🔒 Coffre PostgreSQL chiffré (AES-256-GCM) ou OpenBao / Vault, identifiants par utilisateur et par appli, audit de chaque accès, secrets jamais journalisés.
- 🛠️ Administration web : applis en fichiers Git ou en base (rechargement à chaud), registre des comptes, diagnostic des rejeux en échec.
- 🧭 Embarquement : recorder (avec compte de test facultatif), CLI `sesame-onboard` (`record`, `verify`, `fingerprint`, `health`).
- 🐳 Images `sesame-portal`, `sesame-proxy`, `sesame-admin`, `sesame-recorder` sur GitHub Container Registry.

[Non publié]: https://github.com/neoisback431/Sesame/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/neoisback431/Sesame/releases/tag/v0.1.0
