# Sesame : portail SSO à injection de credentials côté serveur

## Contexte

Plusieurs applications web internes ne supportent aucun mécanisme d'authentification fédérée (ni SAML, ni OIDC, ni en-têtes d'identité). Elles n'offrent qu'un formulaire login / mot de passe.

L'objectif est de placer devant elles un portail SSO unique :

- l'utilisateur s'authentifie uniquement auprès du fournisseur d'identité de l'organisation (OIDC ; Microsoft Entra ID dans le déploiement de référence) ;
- il ne connaît jamais les identifiants applicatifs ;
- le portail rejoue la connexion aux applications côté serveur, de façon totalement transparente.

**Contexte réglementaire** : le déploiement de référence est un environnement de paiement soumis à PCI-DSS. Chaque accès à un secret doit être tracé.

**Projet destiné à être publié en open source.** Il doit rester utilisable par d'autres organisations, avec d'autres briques externes (voir « Indépendance vis-à-vis des briques externes »).

## Principes non négociables

1. Aucun mot de passe applicatif ne transite vers le navigateur, ni dans une réponse, ni dans un log, ni dans un message d'erreur.
2. Les secrets ne sortent du coffre qu'en mémoire du moteur de proxy, le temps du rejeu, puis sont effacés.
3. Les cookies de session applicatifs restent côté serveur (magasin de sessions). Le navigateur ne détient que le cookie de session du portail.
4. Toute lecture de secret et toute connexion rejouée produit un événement d'audit (qui, quelle appli, quand, résultat).
5. Aucune extension navigateur requise côté poste client.

### Conséquences pour le code (à respecter systématiquement)

- Ne jamais logger, sérialiser, ni inclure dans une erreur un credential, un cookie applicatif ou un jeton : utiliser des types dédiés dont la représentation texte est masquée (`***`).
- Capturer côté serveur **tous** les `Set-Cookie` émis par une appli cible : aucun n'atteint le navigateur.
- Retirer le cookie du portail (et l'en-tête `Authorization` du navigateur) avant de relayer une requête à une appli.
- Jetons de session portail stockés hachés ; cookies applicatifs chiffrés au repos.
- En cas d'échec de rejeu, page d'erreur générique avec identifiant de corrélation, jamais le contenu de la réponse de l'appli.
- Tout chemin de code qui lit le coffre de secrets ou déclenche un rejeu émet un événement d'audit, y compris en cas d'échec.
- Aucun secret réel dans le dépôt : uniquement des valeurs de dev explicites (appli factice, coffre en mode dev).
- Aucune donnée propre à une organisation dans le dépôt (noms d'hôtes internes, tenant IDs, noms de groupes réels, URLs d'applis réelles) : tout passe par la configuration.

## Indépendance vis-à-vis des briques externes

Le cœur (portail, proxy, rejeu, audit) ne dépend d'aucun fournisseur précis. Chaque brique externe est derrière une interface (trait Rust / protocole Python) avec des implémentations interchangeables, choisies par configuration.

| Brique | Interface | Implémentation de référence | Autres implémentations visées |
|---|---|---|---|
| Fournisseur d'identité | `IdentityProvider` : OIDC générique (discovery, `issuer`, `client_id`, mapping configurable des claims `sub` / `email` / `groups`) | Entra ID (simple configuration OIDC) | Keycloak, Authentik, Dex, Okta, Google ; Keycloak ou Dex en dev |
| Coffre de secrets | `SecretStore` : `get_credential(app, user)`, sans exposer de concept propre au coffre | Vault / OpenBao (KV v2, AppRole ; même client) | AWS Secrets Manager, Azure Key Vault, fichier chiffré (dev uniquement) |
| Magasin de sessions | `SessionStore` | PostgreSQL | En mémoire (tests) |
| Journal d'audit | `AuditSink` | Fichier JSON / stdout | PostgreSQL, syslog, SIEM |
| Observabilité | OpenTelemetry (OTLP) + logs JSON | Collecteur OTel | Datadog, Prometheus/Grafana, etc. via OTLP |

Règles :

- Aucun SDK ou type spécifique à un fournisseur hors de son module d'implémentation (ex. rien de Vault ni d'Entra dans le code du proxy).
- Les habilitations s'appuient sur des identifiants et groupes génériques issus des claims, jamais sur des API propriétaires (ex. pas de Microsoft Graph dans le cœur ; si nécessaire, un module optionnel).
- Les spécificités d'un fournisseur (claim `groups` d'Entra limité en taille, `oid` vs `sub`, etc.) sont gérées par configuration ou dans le module concerné.
- Chaque implémentation est testée contre la même suite de tests de contrat que l'interface.
- Ajouter un fournisseur ne doit pas nécessiter de modifier le cœur.
- Chaque nouvelle fonctionnalité touchant aux secrets s'accompagne d'un test vérifiant l'absence de fuite (réponse, logs, erreurs).

## Architecture cible

### 1. Portail d'authentification

- Authentification OIDC auprès d'un fournisseur d'identité configurable (Entra ID dans le déploiement de référence).
- Émet et valide la session portail (cookie sécurisé, `HttpOnly`, `Secure`, `SameSite`).
- Résout les habilitations : quel utilisateur / groupe (issu des claims) accède à quelle appli.
- Affiche la page « Mes applications » : applis pour lesquelles l'utilisateur est habilité **et** a un compte actif dans le registre des comptes. N'accède jamais au coffre.

### 2. Moteur de proxy (plan de données)

- Reverse proxy devant les applications cibles.
- À chaque requête : vérifie la session portail, cherche une session applicative active, sinon déclenche le rejeu.
- Rejeu : GET de la page de login, extraction des champs cachés / jetons CSRF, POST forgé selon le descripteur de l'appli, capture du cookie de session.
- Détecte l'expiration (redirection vers la page de login, codes de statut, marqueurs définis dans le descripteur) et rejoue automatiquement.
- Réécrit si nécessaire les redirections et URLs absolues des applis.

### 3. Coffre de secrets

- Derrière l'interface `SecretStore` ; implémentation de référence : Vault / OpenBao (API identique ; OpenBao en dev).
- Identifiants par couple (appli, utilisateur) (voir Décisions).
- Seul le moteur de proxy dispose d'un droit de lecture. Il s'authentifie auprès du coffre par un mécanisme machine (AppRole pour Vault, rôle IAM pour AWS, etc.).

### 4. Magasin de sessions

- Table de correspondance : session portail → sessions applicatives (cookies par appli).
- TTL, invalidation à la déconnexion du portail, purge des sessions expirées.
- Implémentation : PostgreSQL (voir Décisions).
- Contient aussi le **registre des comptes** (`app_accounts` : appli, utilisateur, état `active` / `failed` / `disabled`, sans aucun secret), alimenté par l'UI d'admin et mis à jour par le proxy après chaque rejeu.

### 5. Module d'embarquement

- Assistant qui, à partir d'une URL de login et d'un compte de test, pilote une connexion réelle via navigateur headless (Playwright).
- Capture : champs du formulaire, action, méthode, champs cachés, jetons CSRF, redirection post-login, nom du cookie de session, marqueurs d'expiration.
- Génère un descripteur d'appli (YAML/JSON versionné) soumis à validation humaine.
- Réutilisé en tâche périodique comme test de santé : alerte si le formulaire de login d'une appli a changé.
- Hors périmètre initial : login multi-étapes, captcha, MFA applicatif (à traiter au cas par cas).

### Fonctions transverses

- **Administration** : gestion des applis, descripteurs, habilitations, registre des comptes (écriture du secret dans le coffre et de l'entrée du registre dans la même opération).
- **Observabilité** : logs structurés JSON, métriques et traces via OpenTelemetry (exploitables notamment par Datadog), journal d'audit dédié.

## Flux nominal

1. L'utilisateur se connecte au portail en SSO (redirection OIDC vers le fournisseur d'identité → retour avec session portail).
2. Le portail affiche « Mes applications » (habilité + compte actif dans le registre).
3. Clic sur une tuile → adresse de l'appli **exposée par Sesame** (jamais l'adresse réelle). L'accès direct par favori / lien profond fonctionne aussi.
4. Le moteur de proxy cherche une session applicative dans le magasin. Absente ou expirée → vérification habilitation + compte `active` → lecture du credential dans le coffre → rejeu du login selon le descripteur → stockage du cookie applicatif. Échec → page d'erreur neutre + compte `failed`.
5. La requête est relayée à l'appli avec le cookie applicatif injecté ; la réponse revient au navigateur sans aucun secret.

Session expirée sur un `POST` : rejeu puis `303` vers la page d'origine (soumission perdue, pas de double soumission). Déconnexion du portail : toutes les sessions applicatives détruites ; déconnexion chez le fournisseur d'identité en option (désactivée par défaut). Aucun bandeau injecté dans les applis.

## Environnement et outillage

- Déploiement : Docker Compose pour le dev / la démo. Chaîne d'intégration : GitLab CI (le dépôt public étant sur GitHub, la CI doit rester portable : logique dans des scripts / `Makefile`, fichiers CI minces).
- Frontal TLS : Nginx.
- Cibles de déploiement possibles : on-premises (VMware) et AWS.

## Décisions

| Sujet | Décision | État |
|---|---|---|
| Langage | **Rust** pour le back (portail d'authentification + moteur de proxy) ; **Python** pour le reste (module d'embarquement Playwright, UI d'administration) | Tranché |
| Magasin de sessions | **PostgreSQL** (purge des sessions expirées à implémenter : tâche périodique ou `DELETE` sur `expires_at`) | Tranché |
| Modèle des credentials | **Par utilisateur** : un compte par couple (appli, utilisateur) dans le coffre | Tranché |
| Interface d'administration | **UI web dès le départ** (Python) ; authentifiée via le fournisseur d'identité, réservée à un groupe d'administrateurs, actions tracées dans l'audit | Tranché |
| Briques externes | **Découplées** : interfaces + implémentations interchangeables (voir section dédiée) | Tranché |
| Licence open source | **Apache-2.0** (`LICENSE`, `NOTICE`) | Tranché |
| Langue du projet | **Français** pour l'instant (docs, commentaires de conception) ; passage à l'anglais à réévaluer avant publication | Tranché |
| Coffre en dev | **OpenBao** (fork open source de Vault, même API) ; le code reste compatible Vault | Tranché |
| Routage | **Une appli par nom d'hôte**, cookie portail sur le domaine parent (retiré par le proxy avant relais) | Tranché |
| Parcours utilisateur | **Page « Mes applications »** dans le portail ; rejeu à l'arrivée sur l'appli, dans le proxy | Tranché |
| Registre des comptes | **Table PostgreSQL** sans secret (`AccountRegistry`), source : UI d'admin | Tranché |

Les décisions ont été prises le 2026-09-27. Consigner leur justification dans `docs/decisions/` (ADR). Toute nouvelle décision structurante est posée en question avant d'être codée, puis ajoutée à ce tableau.

## Première étape attendue (initialisation)

Étapes 1 à 4 faites ; étape 6 amorcée (`.gitlab-ci.yml`). Prochaine : 5, le MVP bout en bout.

1. Proposer la structure du dépôt (un dossier par bloc, dossier `descriptors/`, `deploy/`, `docs/`).
2. Rédiger `docs/architecture.md` et un schéma Mermaid des flux.
3. Définir le schéma du descripteur d'appli.
4. Mettre en place un `docker-compose.yml` de dev : Nginx, portail, proxy, OpenBao (mode dev), PostgreSQL, un fournisseur OIDC local (Keycloak ou Dex), et une appli factice avec un formulaire de login + CSRF pour les tests.
5. Implémenter un MVP bout en bout sur l'appli factice : login OIDC (fournisseur local en dev), page « Mes applications », registre des comptes, rejeu, injection de session.
6. Pipeline GitLab CI minimal : lint, tests, build des images.

## Structure du dépôt

| Dossier | Contenu |
|---|---|
| `crates/sesame-core` | Cœur Rust sans dépendance fournisseur : modèle des descripteurs (`descriptor.rs`), interfaces `SecretStore` / `SessionStore` / `AccountRegistry` / `AuditSink` (`ports.rs`), types secrets (`secret.rs`), identité, audit, logs |
| `crates/sesame-portal`, `crates/sesame-proxy` | Binaires Rust (squelettes : `/healthz`) |
| `onboarding/`, `admin/` | Paquets Python (squelettes) |
| `schemas/app-descriptor.schema.json` | Schéma du descripteur : **fait foi**, contrat entre Rust et Python |
| `descriptors/` | Descripteurs YAML (`fake-app.yaml` = exemple de référence, utilisé par les tests Rust) |
| `dev/` | Appli factice (Flask), realm Keycloak, seed OpenBao |
| `deploy/` | `nginx/nginx.conf`, `docker/rust.Dockerfile` (`--build-arg BIN=…`) |
| `docs/` | `architecture.md`, `descriptor.md`, `dev.md`, `decisions/` (ADR) |

Toute modification du schéma du descripteur se reporte dans `descriptor.rs`, `docs/descriptor.md` et `descriptors/fake-app.yaml`.

## Commandes

```sh
make test                  # cargo test + pytest (dev/fake-app)
make lint                  # cargo fmt --check, clippy -D warnings, ruff, validation des descripteurs
make validate-descriptors  # uv run scripts/validate_descriptors.py
make deny                  # licences des dépendances Rust (cargo-deny)
make up / make down        # environnement Docker Compose de dev (make dev-certs en préalable automatique)
```

Environnement de dev : voir `docs/dev.md` (URLs `*.sesame.localhost:8443`, comptes `alice` / `bob` / `admin`).

## Conventions de travail

- Documentation et commentaires de conception en français ; identifiants de code en anglais.
- Commits petits et ciblés, messages descriptifs.
- Licence Apache-2.0 : chaque fichier source commence par l'en-tête SPDX `SPDX-License-Identifier: Apache-2.0`.
- Dépendances : uniquement des licences compatibles Apache-2.0 (MIT, BSD, Apache-2.0, ISC, MPL-2.0…) ; pas de GPL/AGPL. Vérification en CI (`cargo deny` côté Rust, outil équivalent côté Python).
- Mettre à jour ce fichier quand l'architecture, les commandes de build/test ou les décisions évoluent.
