# Notes de version

Toutes les évolutions notables de Sesame. Format inspiré de
[Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ; versions conformes au
[versionnage sémantique](https://semver.org/lang/fr/) (en 0.x, une version mineure peut
contenir des changements incompatibles).

Notes détaillées de chaque version : [`docs/releases/`](docs/releases/).

## [Non publié]

- 🐛 **Recorder : pages de login sans `<form>`** (ex. n8n) : le blocage `password_field_outside_form` disparaît. Quand les champs sont dans des `<div>` (page construite en JavaScript, bouton `type=button`), le bloc qui contient le mot de passe, un bouton et l'identifiant est traité comme le formulaire : analyse, soumission factice interceptée et connexion avec compte de test fonctionnent, et le descripteur proposé utilise `use_form: false` avec la requête observée (JSON ou formulaire).

## [0.1.3] - 2026-10-05

- ✨ **Noms des utilisateurs dans l'administration** (ADR 0031) : « Alice Martin » (et son e-mail) à la place de la clé illisible (`oid` d'Entra). Le portail mémorise le nom et l'e-mail déclarés par le fournisseur d'identité à chaque connexion (table `users`, migration `0008`) ; la recherche porte aussi sur le nom et l'e-mail. Un utilisateur jamais connecté reste affiché par sa clé. ⚠️ Donnée personnelle conservée en base (nom, e-mail) ; les comptes existants se remplissent à la prochaine connexion de chacun.

- 🐛 **Identifiants d'appli réservés** : `new`, `admin` et `www` sont refusés (portail, proxy et administration). Le recorder déduisait l'identifiant du premier label de l'hôte de l'appli, donc `www.exemple.com` donnait `www` ; il ignore désormais les labels génériques (`www`, `login`, `sso`…), propose le suivant (`exemple`), signale que l'identifiant est déduit et à confirmer, et bloque l'enregistrement d'un identifiant réservé. ⚠️ Une appli déjà enregistrée sous un de ces identifiants est écartée au chargement : la recréer sous un autre identifiant.

- 📚 **Entra ID : groupes et GUID** précisés dans le README, `docs/configuration.md` (nouvelle section), les `.env.example` et le kit AWS : `SESAME_ADMIN_GROUP` est le **GUID** du groupe, pas son nom, et les groupes doivent être activés dans l'application Entra (« Configuration du jeton » → revendication de groupes, ou `"groupMembershipClaims": "SecurityGroup"` dans le manifeste).

## [0.1.2] - 2026-10-01

- 📧 **Notifications par mail** aux administrateurs (ADR 0030) : nouvelle demande d'accès, compte passé en échec, application injoignable, actions d'administration sensibles. Boîte d'envoi en base (le portail et le proxy déposent, l'admin expédie : un SMTP en panne ne bloque rien), reprise sur échec, regroupement des répétitions. Serveur SMTP, expéditeur, destinataires et événements réglables dans la console (page « Notifications », mail de test, historique) ; mot de passe SMTP dans `SESAME_SMTP_PASSWORD`, jamais en base. Migration `0007`.

- ✨ **Demandes d'accès** depuis une tuile grisée de « Mes applications » (ADR 0029) : « J'ai déjà un compte » (identifiants vérifiés par un rejeu de test puis enregistrés, compte `pending`, l'administrateur n'a qu'à activer) ou « Je n'ai pas de compte » (l'administrateur voit la demande et crée le compte). Nouvelle page « Demandes d'accès » dans l'administration, état de compte `pending`, service interne du proxy (`SESAME_INTERNAL_TOKEN`, `SESAME_PROXY_INTERNAL_URL`, `SESAME_PROXY_INTERNAL_LISTEN`), migration `0006`. **Mise à jour des kits** : relancez `generate-keys.sh` (nouveau jeton `SESAME_INTERNAL_TOKEN`) ; Terraform génère le jeton tout seul.

## [0.1.1] - 2026-09-29

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

[Non publié]: https://github.com/neoisback431/Sesame/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/neoisback431/Sesame/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/neoisback431/Sesame/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/neoisback431/Sesame/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/neoisback431/Sesame/releases/tag/v0.1.0
