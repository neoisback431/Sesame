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
- Affiche la page « Mes applications » : applis pour lesquelles l'utilisateur a un compte actif dans le registre **et** (si le descripteur définit `spec.access`) y est habilité. `spec.access` est facultatif : sans lui, le compte suffit (ADR 0017). N'accède jamais au coffre.

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
2. Le portail affiche « Mes applications » (compte actif dans le registre, et habilitation `spec.access` si définie — facultative, ADR 0017).
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
| Habilitation | **Le compte suffit** : `spec.access` facultatif (absent/vide ⇒ tout utilisateur avec un compte actif) ; présent ⇒ restreint en plus par groupes/`users` (ADR 0017) | Tranché |
| UI d'admin | **FastAPI + Jinja2** (rendu serveur) ; AppRole admin en écriture sans lecture | Tranché |
| Emplacement des descripteurs | **Fichiers Git** (lecture seule) **et base** (créés / modifiés dans l'admin, historisés, rechargés à chaud) ; fichiers prioritaires en cas de conflit d'`id` ou d'hôte (ADR 0014) | Tranché |
| Déconnexion fournisseur | **RP-Initiated Logout** optionnel (`SESAME_OIDC_LOGOUT`) : `client_id` + `post_logout_redirect_uri`, **sans `id_token_hint`** (l'ID token n'est pas conservé) | Tranché |
| Embarquement | **CLI `sesame-onboard`** : `verify` (rejeu sans JavaScript, règles du proxy), `fingerprint`, `health` (empreinte du HTML brut, sans identifiants), `record` (recorder Playwright **sans identifiant**, soumission interceptée, sonde d'échec facultative ; ADR 0015) | Tranché |
| Diagnostic des rejeux | **`SESAME_REPLAY_DEBUG`** (proxy, désactivé par défaut, activé en dev) : dernière réponse de l'appli en cas d'échec (statut, en-têtes, corps 64 Ko), valeurs du coffre et des cookies masquées, visible dans l'admin ; rien vers le navigateur (ADR 0018) | Tranché |
| Recorder dans l'admin | **Service HTTP interne** `sesame-recorder` appelé par l'admin (jeton partagé), bouton « Analyser une page de login » pré-remplissant l'éditeur ; **aucune allowlist anti-SSRF** (choix de l'exploitant, garde-fous interne+jeton+admins+audit ; ADR 0016) | Tranché |

Les décisions ont été prises le 2026-09-27. Consigner leur justification dans `docs/decisions/` (ADR). Toute nouvelle décision structurante est posée en question avant d'être codée, puis ajoutée à ce tableau.

## Première étape attendue (initialisation)

Étapes 1 à 5 faites (MVP validé de bout en bout par `make e2e`) ; étape 6 en place (`.gitlab-ci.yml`, non exécutée faute de GitLab). UI d'administration v1 faite (comptes par appli et par utilisateur, désactivation en masse, révocation des sessions ouvertes à la désactivation). Embarquement fait (`verify`, `fingerprint`, `health`) ; recorder fait (`record`, ADR 0015) : analyse de la page de login dans Chromium headless **sans identifiant** (décision de l'utilisateur : mot de passe écarté pour l'instant), soumission factice interceptée, sonde d'échec facultative, descripteur proposé avec points à confirmer (cookie de session, succès). Déconnexion chez le fournisseur d'identité faite (`SESAME_OIDC_LOGOUT`, désactivée par défaut, activée en dev). Applis en base faites (décision de l'utilisateur, ADR 0014, remplace en partie l'ADR 0011) : migrations `0002_app_descriptors.sql` (descripteurs + historique) et `0003_app_descriptor_host.sql` (hôte public unique), `DescriptorStore` Rust (mémoire + PostgreSQL) et Python (concurrence optimiste par révision attendue), `sources.rs` (fusion fichiers Git en lecture seule + base, reproduite dans `admin/…/descriptors.py`), rechargement à chaud dans le portail et le proxy (`SESAME_DESCRIPTORS_RELOAD`, 10 s) ; dans l'admin : formulaire guidé → éditeur YAML (vérifier / enregistrer), historique des révisions, suppression refusée tant qu'il reste des comptes, audit `descriptor_created` / `descriptor_updated` / `descriptor_deleted` ; e2e (appli créée dans l'UI puis servie sans redémarrage). Limites connues : `sesame-onboard health` ne couvre que les fichiers. Recorder appelé depuis l'admin fait (ADR 0016) : service HTTP interne `sesame-recorder` (`onboarding/…/server.py`, image `recorder.Dockerfile`, jeton partagé `SESAME_RECORDER_TOKEN`, jamais exposé via Nginx), bouton « Analyser une page de login » sur `/apps/new` qui pré-remplit l'éditeur, audit `descriptor_recorded` (hôte seul). **Aucune allowlist anti-SSRF** (choix explicite de l'exploitant : applis internes ; garde-fous = service interne + jeton + admins + audit). `admin/…/recorder.py` = client HTTP. `make record` reste le mode CLI (entrypoint remplacé). Prochaines pistes ensuite : OpenTelemetry ; recorder avec compte de test (connexion réelle observée : cookie de session, succès) ; blocage optionnel des seules métadonnées cloud dans le recorder ; `health` sur les applis en base.

1. Proposer la structure du dépôt (un dossier par bloc, dossier `descriptors/`, `deploy/`, `docs/`).
2. Rédiger `docs/architecture.md` et un schéma Mermaid des flux.
3. Définir le schéma du descripteur d'appli.
4. Mettre en place un `docker-compose.yml` de dev : Nginx, portail, proxy, OpenBao (mode dev), PostgreSQL, un fournisseur OIDC local (Keycloak ou Dex), et une appli factice avec un formulaire de login + CSRF pour les tests.
5. Implémenter un MVP bout en bout sur l'appli factice : login OIDC (fournisseur local en dev), page « Mes applications », registre des comptes, rejeu, injection de session.
6. Pipeline GitLab CI minimal : lint, tests, build des images.

## Structure du dépôt

| Dossier | Contenu |
|---|---|
| `crates/sesame-core` | Cœur Rust sans dépendance fournisseur : modèle des descripteurs (`descriptor.rs`), interfaces `SecretStore` / `SessionStore` / `AccountRegistry` / `AuditSink` (`ports.rs`), types secrets (`secret.rs`), chiffrement / jetons (`crypto.rs`), implémentations en mémoire (`memory.rs`), tests de contrat (`contract.rs`, feature `contract`), identité, audit, config |
| `crates/sesame-portal` | Portail : OIDC (`oidc.rs`), page « Mes applications » (`catalog.rs`), session portail, `return_to` sûr |
| `crates/sesame-proxy` | Moteur de proxy : rejeu (`replay.rs`), formulaire / CSRF (`form.rs`), jar serveur (`jar.rs`), conditions (`matcher.rs`), réécriture (`rewrite.rs`), relais (`lib.rs`) |
| `crates/sesame-store-postgres` | `SessionStore` + `AccountRegistry` sur PostgreSQL, migrations dans `migrations/` |
| `crates/sesame-secrets-openbao` | `SecretStore` OpenBao / Vault (AppRole, KV v2), API HTTP sans SDK |
| `admin/` | UI d'administration (FastAPI) : `service.py` (opérations auditées), `web.py` (routes, CSRF, groupe admin), `auth.py` (OIDC Authlib), `ports.py` (`SecretWriter`, `AccountStore`, `DescriptorStore`), `descriptors.py` (validation miroir de `AppDescriptor::validate`, fusion, formulaire guidé), `recorder.py` (client HTTP du service recorder), `openbao.py`, `store_postgres.py` (asyncpg), `memory.py`, `templates/` |
| `onboarding/` | Embarquement (`sesame-onboard`) : `verify.py` (rejeu sans JavaScript, miroir de `replay.rs`), `fingerprint.py` (formulaire en HTML brut + empreinte), `health.py`, `record.py` (recorder Playwright, extra `capture`), `server.py` (service HTTP interne `sesame-recorder`, image `recorder.Dockerfile`), `matcher.py` (miroir de `matcher.rs`), `http.py`, `cli.py` |
| `schemas/app-descriptor.schema.json` | Schéma du descripteur : **fait foi**, contrat entre Rust et Python |
| `descriptors/` | Descripteurs YAML (`fake-app.yaml` = exemple de référence, utilisé par les tests Rust ; `TEMPLATE.yaml.example` = gabarit commenté, ignoré au chargement) |
| `dev/` | Appli factice (Flask), realm Keycloak, seed OpenBao, seed du registre des comptes |
| `ressources/` | Logo et bannière d'origine ; déclinaisons web générées par `scripts/build_web_assets.py` dans `crates/sesame-core/assets/` (embarquées, servies par le portail sous `/static/`, y compris pour les pages du proxy) et `admin/src/sesame_admin/static/` |
| `tests/e2e/` | Parcours bout en bout Playwright sur le compose de dev |
| `deploy/` | `nginx/nginx.conf`, `docker/rust.Dockerfile` (`--build-arg BIN=…`) |
| `docs/` | `architecture.md`, `descriptor.md`, `configuration.md` (variables d'environnement), `dev.md`, `decisions/` (ADR) |

Toute modification du schéma du descripteur se reporte dans `descriptor.rs`, `docs/descriptor.md`, `descriptors/fake-app.yaml` et `descriptors/TEMPLATE.yaml.example`. Toute évolution de la sémantique du rejeu ou des conditions se reporte des deux côtés : `crates/sesame-proxy` (Rust) et `onboarding/` (Python). Toute évolution de `AppDescriptor::validate` ou de la fusion (`sources.rs`) se reporte dans `admin/src/sesame_admin/descriptors.py`. Si le formulaire de l'appli factice change, mettre à jour son `form_fingerprint`.
Toute nouvelle variable d'environnement se documente dans `docs/configuration.md`.
Charte : couleurs reprises du logo (bleu nuit `#0a1f5c`, bleu `#1464c0`, cyan `#13b5cf`), définies dans `sesame_core::html::STYLE` et `admin/…/templates/base.html` : les garder alignées. Après modification d'une image de `ressources/`, relancer `uv run scripts/build_web_assets.py`. Les pages du proxy ne servent aucune ressource sur l'hôte d'une appli : elles pointent vers le portail.
UI d'admin : pas de `from __future__ import annotations` dans `web.py` (FastAPI doit résoudre l'alias local `Admin`) ; le schéma de base appartient aux migrations Rust ; le format d'audit Python doit rester identique à celui des services Rust (JSON compact, `"log_type":"audit"`).
Tests du proxy : banc commun dans `crates/sesame-proxy/tests/common/` (appli simulée + implémentations en mémoire) ; les tests de non-fuite des logs vivent dans un binaire de test séparé (`no_leak.rs`).

## Commandes

```sh
make test                  # cargo test + pytest (dev/fake-app, admin, onboarding)
make test-postgres         # tests de contrat PostgreSQL (Rust + Python) sur une base jetable (Docker)
make e2e                   # parcours bout en bout Playwright (après make up)
make health                # test de santé des formulaires de login (après make up)
make record URL=…        # recorder : analyse une page de login, propose un descripteur (après make up)
make lint                  # cargo fmt --check, clippy -D warnings, ruff, validation des descripteurs
make validate-descriptors  # uv run scripts/validate_descriptors.py
make deny                  # licences des dépendances Rust (cargo-deny) et Python (scripts/check_python_licenses.py)
make up / make down        # environnement Docker Compose de dev (make dev-certs en préalable automatique)
```

Environnement de dev : voir `docs/dev.md` (URLs `*.sesame.localhost:8443`, comptes `alice` / `bob` / `carol` / `admin`).

## Conventions de travail

- Documentation et commentaires de conception en français ; identifiants de code en anglais.
- Commits petits et ciblés, messages descriptifs.
- Licence Apache-2.0 : chaque fichier source commence par l'en-tête SPDX `SPDX-License-Identifier: Apache-2.0`.
- Dépendances : uniquement des licences compatibles Apache-2.0 (MIT, BSD, Apache-2.0, ISC, MPL-2.0…) ; pas de GPL/AGPL. Vérification en CI (`cargo deny` côté Rust, outil équivalent côté Python).
- Mettre à jour ce fichier quand l'architecture, les commandes de build/test ou les décisions évoluent.
