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
| Fournisseur d'identité | `IdentityProvider` : OIDC (discovery, `issuer`, `client_id`, mapping configurable des claims `sub` / `email` / `groups`) **ou** SAML 2.0 (mapping configurable d'attributs), un seul protocole actif par déploiement (`SESAME_IDP_PROTOCOL`, ADR 0024) | Entra ID (OIDC ou SAML) | Keycloak, Authentik, Dex, Okta, Google (OIDC) ; tout IdP SAML 2.0 générique ; Keycloak ou Dex en dev |
| Coffre de secrets | `SecretStore` : `get_credential(app, user)`, sans exposer de concept propre au coffre | **PostgreSQL** (`app_secrets`, AES-256-GCM, ADR 0021 ; pas de brique externe supplémentaire) | Vault / OpenBao (KV v2, AppRole), AWS Secrets Manager, Azure Key Vault, fichier chiffré (dev uniquement) |
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

- Authentification OIDC ou SAML 2.0 auprès d'un fournisseur d'identité configurable (Entra ID dans le déploiement de référence), un seul protocole actif par déploiement (ADR 0024).
- Émet et valide la session portail (cookie sécurisé, `HttpOnly`, `Secure`, `SameSite`).
- Résout les habilitations : quel utilisateur / groupe (issu des claims) accède à quelle appli.
- Affiche la page « Mes applications » : applis pour lesquelles l'utilisateur est habilité (si le descripteur définit `spec.access`, sinon ouvert à tout titulaire de compte, ADR 0017). Avec un compte actif la tuile est cliquable (nouvel onglet) et porte un bouton « Déconnecter » (force la fin de la session applicative, `POST /apps/<id>/disconnect`) ; sans compte, tuile grisée plutôt que masquée ; `disabled` reste masqué (ADR 0022). N'accède jamais au coffre.
- Affiche un lien « Administration » (`SESAME_ADMIN_URL`) aux membres du groupe d'administrateurs (`SESAME_ADMIN_GROUP`, même défaut `sesame-admins` que l'admin).

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

- Déploiement : Docker Compose pour le dev / la démo. Chaîne d'intégration : GitLab CI (le dépôt public étant sur GitHub, la CI doit rester portable : logique dans des scripts / `Makefile`, fichiers CI minces). Publication des images : GitHub Releases + GHCR, sur tag Git (`.github/workflows/release.yml`, ADR 0025), même principe de fichier CI mince.
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
| Coffre de secrets | **PostgreSQL par défaut**, sans Vault obligatoire (`SESAME_SECRET_STORE=postgres`, table `app_secrets`, AES-256-GCM, ADR 0021) ; OpenBao / Vault reste une implémentation interchangeable (`openbao`/`vault`), démontrée en dev via `docker-compose.openbao.yml` (remplace en partie l'ADR 0007) | Tranché |
| Routage | **Une appli par nom d'hôte**, cookie portail sur le domaine parent (retiré par le proxy avant relais) | Tranché |
| Parcours utilisateur | **Page « Mes applications »** dans le portail ; rejeu à l'arrivée sur l'appli, dans le proxy | Tranché |
| Registre des comptes | **Table PostgreSQL** sans secret (`AccountRegistry`), source : UI d'admin | Tranché |
| Habilitation | **Le compte suffit** : `spec.access` facultatif (absent/vide ⇒ tout utilisateur avec un compte actif) ; présent ⇒ restreint en plus par groupes/`users` (ADR 0017) | Tranché |
| UI d'admin | **FastAPI + Jinja2** (rendu serveur) ; AppRole admin en écriture sans lecture | Tranché |
| Emplacement des descripteurs | **Fichiers Git** (lecture seule) **et base** (créés / modifiés dans l'admin, historisés, rechargés à chaud) ; fichiers prioritaires en cas de conflit d'`id` ou d'hôte (ADR 0014) | Tranché |
| Déconnexion fournisseur | **RP-Initiated Logout** optionnel (`SESAME_OIDC_LOGOUT`) : `client_id` + `post_logout_redirect_uri`, **sans `id_token_hint`** (l'ID token n'est pas conservé) | Tranché |
| Embarquement | **CLI `sesame-onboard`** : `verify` (rejeu sans JavaScript, règles du proxy), `fingerprint`, `health` (empreinte du HTML brut, sans identifiants), `record` (recorder Playwright, soumission factice interceptée, sonde d'échec facultative ; ADR 0015) ; **compte de test facultatif** (connexion réelle observée : requête JS ou formulaire, source des jetons, succès, cookie de session ; identifiants jamais conservés ; ADR 0019) | Tranché |
| Diagnostic des rejeux | **`SESAME_REPLAY_DEBUG`** (proxy, désactivé par défaut, activé en dev) : dernière réponse de l'appli en cas d'échec (statut, en-têtes, corps 64 Ko), valeurs du coffre et des cookies masquées, visible dans l'admin ; rien vers le navigateur (ADR 0018) | Tranché |
| Mode « remise » (handoff) | **Facultatif, par appli, désactivé par défaut** (`spec.session.mode: proxy \| handoff`) : rejeu côté serveur puis remise au navigateur du seul élément de session (cookie ou valeur de stockage local), transparent sans chemin dédié (marqueur + relais) ; mot de passe jamais remis ; exception assumée aux principes 1 (jetons) et 3 (ADR 0020) | Tranché |
| Recorder dans l'admin | **Service HTTP interne** `sesame-recorder` appelé par l'admin (jeton partagé), bouton « Analyser une page de login » pré-remplissant l'éditeur ; **aucune allowlist anti-SSRF** (choix de l'exploitant, garde-fous interne+jeton+admins+audit ; ADR 0016) | Tranché |
| Page « Mes applications » | **Nouvel onglet** par tuile ; **bouton « Déconnecter »** par appli (force la fin de la session applicative, sans toucher au portail) ; **tuile grisée** (pas masquée) pour une appli habilitée sans compte, `disabled` restant masqué (ADR 0022, remplace en partie l'ADR 0009) | Tranché |
| TLS vers les applis amont | `spec.upstream.tls.verify` à **`false` par défaut** (choix de l'exploitant : PKI internes sans CA connue de Sesame) ; `true` + `ca_file` facultatif pour vérifier réellement une appli donnée (ADR 0023) | Tranché |
| Fournisseur d'identité SAML | **Support SAML 2.0 en plus d'OIDC** (décision de l'exploitant) : `SESAME_IDP_PROTOCOL=oidc\|saml`, un seul actif par déploiement, même choix portail/admin ; `samael`+`xmlsec` (Rust), `python3-saml` (Python) ; vérification de signature jamais désactivable ; métadonnées SP sur `/saml/metadata` ; pas de Single Logout SAML (ADR 0024) | Tranché |
| Publication des images | **GitHub Releases + GHCR** (décision de l'exploitant) : 4 images séparées (portail, proxy, admin, recorder, pas d'image combinée), déclenchée par un tag Git manuel (`vX.Y.Z`), logique dans `make release-images`, fichier CI mince (`.github/workflows/release.yml`, ADR 0025) | Tranché |

Les décisions ont été prises le 2026-09-27. Consigner leur justification dans `docs/decisions/` (ADR). Toute nouvelle décision structurante est posée en question avant d'être codée, puis ajoutée à ce tableau.

## Première étape attendue (initialisation)

Étapes 1 à 5 faites (MVP validé de bout en bout par `make e2e`) ; étape 6 en place (`.gitlab-ci.yml`, non exécutée faute de GitLab). UI d'administration v1 faite (comptes par appli et par utilisateur, désactivation en masse, révocation des sessions ouvertes à la désactivation). Embarquement fait (`verify`, `fingerprint`, `health`) ; recorder fait (`record`, ADR 0015) : analyse de la page de login dans Chromium headless **sans identifiant** (décision de l'utilisateur : mot de passe écarté pour l'instant), soumission factice interceptée, sonde d'échec facultative, descripteur proposé avec points à confirmer (cookie de session, succès). Déconnexion chez le fournisseur d'identité faite (`SESAME_OIDC_LOGOUT`, désactivée par défaut, activée en dev). Applis en base faites (décision de l'utilisateur, ADR 0014, remplace en partie l'ADR 0011) : migrations `0002_app_descriptors.sql` (descripteurs + historique) et `0003_app_descriptor_host.sql` (hôte public unique), `DescriptorStore` Rust (mémoire + PostgreSQL) et Python (concurrence optimiste par révision attendue), `sources.rs` (fusion fichiers Git en lecture seule + base, reproduite dans `admin/…/descriptors.py`), rechargement à chaud dans le portail et le proxy (`SESAME_DESCRIPTORS_RELOAD`, 10 s) ; dans l'admin : formulaire guidé → éditeur YAML (vérifier / enregistrer), historique des révisions, suppression refusée tant qu'il reste des comptes, audit `descriptor_created` / `descriptor_updated` / `descriptor_deleted` ; e2e (appli créée dans l'UI puis servie sans redémarrage). Limites connues : `sesame-onboard health` ne couvre que les fichiers. Recorder appelé depuis l'admin fait (ADR 0016) : service HTTP interne `sesame-recorder` (`onboarding/…/server.py`, image `recorder.Dockerfile`, jeton partagé `SESAME_RECORDER_TOKEN`, jamais exposé via Nginx), bouton « Analyser une page de login » sur `/apps/new` qui pré-remplit l'éditeur, audit `descriptor_recorded` (hôte seul). **Aucune allowlist anti-SSRF** (choix explicite de l'exploitant : applis internes ; garde-fous = service interne + jeton + admins + audit). `admin/…/recorder.py` = client HTTP. `make record` reste le mode CLI (entrypoint remplacé). Recorder avec compte de test fait (ADR 0019 ; admin, service et CLI `--test-account`). Diagnostic des rejeux fait (ADR 0018). Mode « remise » (handoff) fait (ADR 0020 ; `spec.session.mode: handoff`, **transparent sans chemin dédié** : remise du cookie ou du stockage local au navigateur à la première arrivée, marqueur `__sesame_handoff`, puis relais laissant le navigateur porter la session, cookies de Sesame retirés ; nouvelle remise si une navigation correspond à `spec.expiry`). Sous-ressource non authentifiée : `401`, jamais de redirection cross-origin. Nettoyage fait : handler du proxy scindé par mode, recorder scindé observation (`record.py`) / rédaction (`proposal.py`), docs, schémas et ADR à jour. Deux niveaux de tests faits : `make test` (rapide, sans navigateur, marqueur `browser`) et `make test-full` (complet). Coffre PostgreSQL par défaut fait (ADR 0021, décision de l'utilisateur : se passer de Vault) : `PgSecretStore` (`crates/sesame-store-postgres/src/secrets.rs`, migration `0005_app_secrets.sql`, AES-256-GCM, clé `SESAME_SECRETS_ENCRYPTION_KEY`) côté proxy, `PostgresSecretWriter` (`admin/…/store_postgres.py`, chiffrement dans `admin/…/crypto.py`) côté admin, écriture sans lecture par construction (aucune méthode de lecture) ; `SESAME_SECRET_STORE` par défaut `postgres` (`openbao`/`vault` restent disponibles) ; dev : service `secrets-seed` (`dev/postgres/seed_secret.py`) remplace le seed OpenBao par défaut, démo Vault déplacée dans `docker-compose.openbao.yml`. Prochaines pistes ensuite : OpenTelemetry ; blocage optionnel des seules métadonnées cloud dans le recorder ; `health` sur les applis en base ; rôles PostgreSQL séparés proxy/admin documentés dans un script de dev (recommandation ADR 0021 non outillée). Bug corrigé : SESAME_SECRETS_ENCRYPTION_KEY de dev décodait 31 octets, pas 32 (502 sur l'admin au démarrage) ; `make check-dev-keys` (`scripts/check_dev_keys.py`, dans `make lint`) vérifie désormais la longueur des clés base64 des fichiers docker-compose*.yml. Appli factice rendue facultative (décision de l'utilisateur) : profil Compose `demo` (`fake-app`, `db-seed`, `secrets-seed`), `make up` ne la démarre plus, `make up-demo` l'ajoute ; `make health`/`make e2e` en dépendent, documenté dans `docs/dev.md`. SESAME_RECORDER_INSECURE (décision de l'utilisateur) : activé par défaut désormais, la navigation Chromium du recorder ignorant SESAME_CA_FILE (son propre magasin de confiance). Bug corrigé (retour d'usage sur une appli réelle) : le compte de test n'était tenté que si la soumission factice avait observé une requête ; or une validation côté client (identifiant sans forme d'e-mail attendue, par ex.) bloque souvent cette soumission factice avant tout appel réseau (`submission_not_observed`) sans empêcher une connexion réelle. Le compte de test est maintenant tenté dans ce cas aussi ; les blocages structurels (captcha, plusieurs étapes, champ introuvable…) restent définitifs. « Mes applications » (décision de l'utilisateur, ADR 0022, remplace en partie l'ADR 0009) : tuile ouverte en nouvel onglet (`target=_blank`), bouton « Déconnecter » par appli (`POST /apps/<id>/disconnect`, portail, `SessionStore::delete_app_session`, audit `app_logout`/`manual_from_portal`, sans toucher au portail ni à l'appli elle-même), tuile grisée (`TileState::NoAccount`) pour une appli habilitée sans compte plutôt que masquée (`disabled` reste masqué). Diagnostic amélioré (retour d'usage) : le log « appli injoignable » du proxy ne donnait que "error sending request" (message générique de reqwest), inexploitable pour distinguer DNS/TLS/connexion refusée ; `describe_upstream_error` (`replay.rs`) journalise maintenant toute la chaîne de causes, l'URL restant toujours absente du log. `spec.upstream.tls.verify` à `false` par défaut (décision de l'utilisateur, ADR 0023) : beaucoup d'applis internes ont un certificat signé par une PKI privée sans CA connue de Sesame ; le rejeu échouait systématiquement (`invalid peer certificate: UnknownIssuer`) avant que le diagnostic ci-dessus n'existe. `true` + `ca_file` facultatif reste possible par appli pour vérifier réellement. Bug corrigé (retour d'usage sur une appli réelle, ADR 0019) : pour une connexion par appel JSON dont le script décide la redirection après un court délai une fois la réponse reçue (ex. transition d'interface), `logged_in` (compte de test) était constaté à tort à `False` — `wait_for_load_state("load"/"networkidle")` se résolvait avant que le script n'ait déclenché cette redirection, faisant repasser `proposal.to_descriptor` sur le repli générique `status: [302, 303]` au lieu du statut réel observé (200 dans ce cas), d'où l'échec au rejeu (`login_unexpected_response`). `observe_login` (`record.py`) attend désormais explicitement la disparition du champ mot de passe (sondage borné, même budget que l'attente de la requête) avant de conclure. Support SAML fait (décision de l'utilisateur, ADR 0024) : `SESAME_IDP_PROTOCOL=oidc` (défaut) `|saml`, un seul protocole actif par déploiement, le même pour le portail et l'admin. Portail : abstraction `idp.rs` (`PendingLogin` unifié, `Callback::{Oidc,Saml}`), `saml.rs` (`samael`, feature `xmlsec` — vérification de signature XML déléguée, jamais réimplémentée), métadonnées IdP construites en XML à partir de la configuration (pas de récupération dynamique), ACS sur `POST /auth/callback` (même chemin que le retour OIDC, distingué par la méthode), `GET /saml/metadata` (SP, 404 hors SAML), anti-rejeu par l'identifiant de l'`AuthnRequest` porté dans le même cookie chiffré que l'état OIDC. Admin : `SamlAuthenticator` (`python3-saml`), `wantAssertionsSigned` forcé à `true` dans le code (faux par défaut dans la bibliothèque, jamais exposé en configuration), anti-rejeu porté par la session admin existante (pas de nouvel état). Attributs configurables (`SESAME_SAML_USER_KEY_ATTRIBUTE`/`_EMAIL_ATTRIBUTE`/`_GROUPS_ATTRIBUTE`), même rôle que les claims OIDC. Image du portail passée de `distroless/cc` à `debian:bookworm-slim` (étage `runtime-portal`, `samael` lie dynamiquement libxmlsec1/libxml2/libssl) ; le proxy garde `distroless/cc` (`runtime-proxy`, aucune dépendance SAML) ; admin inchangé (roues `xmlsec`/`lxml` liées statiquement). Testé des deux côtés : signature valide acceptée, rejet d'une clé non fiable / audience différente / rejeu / assertion altérée / clé utilisateur dangereuse. Pas d'e2e SAML en dev/CI (décision de l'utilisateur) : `make e2e` reste sur Keycloak (OIDC). Publication des images faite (décision de l'utilisateur, ADR 0025) : `make release-images VERSION=vX.Y.Z [REGISTRY=…]` construit et publie les 4 images (portail, proxy, admin, recorder — pas d'image combinée, pour garder la frontière de sécurité portail/proxy et l'isolation du recorder) sur GitHub Container Registry ; `.github/workflows/release.yml` (fichier CI mince, comme `.gitlab-ci.yml`) l'appelle sur un tag Git (`vX.Y.Z`) poussé manuellement, puis crée la Release GitHub (`gh release create --generate-notes`). Aucun secret nouveau : `GITHUB_TOKEN` fourni par GitHub Actions. Coexiste avec `.gitlab-ci.yml`, qui continue à seulement vérifier que les images buildent, sans les publier. Non testé en environnement sans démon Docker (ici comme dans `.gitlab-ci.yml`) : validé par relecture et `make -n release-images`. Préparation open source faite (version 0.1.0) : audit sans donnée propre à une organisation ; noms d'applications réelles retirés des fichiers (test du recorder : identifiant générique `monAppli`) et de tout l'historique Git (réécrit avec `git filter-repo` puis force-push par l'utilisateur, contenus et messages de commit ; les identifiants de commit antérieurs ont changé). Ne jamais citer de nom d'appli réelle dans un fichier ni un message de commit, en-têtes SPDX ajoutés aux gabarits HTML (commentaire Jinja) et fichiers de configuration, README réécrit (problème, fonctionnement avec diagramme, fonctionnalités, garanties, démarrage, déploiement, limites), fichiers communautaires (`CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, modèles d'issues et de PR), `CHANGELOG.md` et notes de version `docs/releases/v0.1.0.md` utilisées par le workflow de release. Toute nouvelle version : mettre à jour `CHANGELOG.md` et créer `docs/releases/vX.Y.Z.md` avant le tag.

1. Proposer la structure du dépôt (un dossier par bloc, dossier `descriptors/`, `deploy/`, `docs/`).
2. Rédiger `docs/architecture.md` et un schéma Mermaid des flux.
3. Définir le schéma du descripteur d'appli.
4. Mettre en place un `docker-compose.yml` de dev : Nginx, portail, proxy, OpenBao (mode dev), PostgreSQL, un fournisseur OIDC local (Keycloak ou Dex), et une appli factice avec un formulaire de login + CSRF pour les tests.
5. Implémenter un MVP bout en bout sur l'appli factice : login OIDC (fournisseur local en dev), page « Mes applications », registre des comptes, rejeu, injection de session.
6. Pipeline GitLab CI minimal : lint, tests, build des images.

## À faire

(rien en attente : voir « Prochaines pistes » ci-dessus.)

## Structure du dépôt

| Dossier | Contenu |
|---|---|
| `crates/sesame-core` | Cœur Rust sans dépendance fournisseur : modèle des descripteurs (`descriptor.rs`), interfaces `SecretStore` / `SessionStore` / `AccountRegistry` / `AuditSink` (`ports.rs`), types secrets (`secret.rs`), chiffrement / jetons (`crypto.rs`), cookies propres à Sesame (`cookies.rs`), fusion fichiers + base (`sources.rs`), implémentations en mémoire (`memory.rs`), tests de contrat (`contract.rs`, feature `contract`), identité, audit, config |
| `crates/sesame-portal` | Portail : fournisseur d'identité OIDC (`oidc.rs`) ou SAML (`saml.rs`), abstraction commune (`idp.rs`, ADR 0024), page « Mes applications » (`catalog.rs`, trois états de tuile), session portail, déconnexion par appli, `return_to` sûr |
| `crates/sesame-proxy` | Moteur de proxy : rejeu (`replay.rs`), formulaire / CSRF (`form.rs`), jar serveur (`jar.rs`), conditions (`matcher.rs`), réécriture (`rewrite.rs`), mode remise (`handoff.rs`), diagnostic masqué des rejeux (`diagnostic.rs`), relais et aiguillage proxy / handoff (`lib.rs`) |
| `crates/sesame-store-postgres` | `SessionStore` + `AccountRegistry` + `SecretStore` (`secrets.rs`, ADR 0021) sur PostgreSQL, migrations dans `migrations/` |
| `crates/sesame-secrets-openbao` | `SecretStore` OpenBao / Vault (AppRole, KV v2), API HTTP sans SDK |
| `admin/` | UI d'administration (FastAPI) : `service.py` (opérations auditées), `web.py` (routes, CSRF, groupe admin), `auth.py` (`OidcAuthenticator` Authlib ou `SamlAuthenticator` python3-saml, ADR 0024), `ports.py` (`SecretWriter`, `AccountStore`, `DescriptorStore`), `descriptors.py` (validation miroir de `AppDescriptor::validate`, fusion, formulaire guidé), `recorder.py` (client HTTP du service recorder), `crypto.py` (chiffrement des secrets PostgreSQL, ADR 0021), `openbao.py`, `store_postgres.py` (asyncpg, dont `PostgresSecretWriter`), `memory.py`, `templates/` |
| `onboarding/` | Embarquement (`sesame-onboard`) : `verify.py` (rejeu sans JavaScript, miroir de `replay.rs`), `fingerprint.py` (formulaire en HTML brut + empreinte), `health.py`, `record.py` (observation Playwright, extra `capture`), `proposal.py` (rédaction du descripteur proposé), `server.py` (service HTTP interne `sesame-recorder`, image `recorder.Dockerfile`), `matcher.py` (miroir de `matcher.rs`), `http.py`, `cli.py` |
| `schemas/app-descriptor.schema.json` | Schéma du descripteur : **fait foi**, contrat entre Rust et Python |
| `descriptors/` | Descripteurs YAML (`fake-app.yaml` = exemple de référence, utilisé par les tests Rust ; `TEMPLATE.yaml.example` = gabarit commenté, ignoré au chargement) |
| `dev/` | Appli factice (Flask), realm Keycloak, seed OpenBao, seed du registre des comptes |
| `ressources/` | Logo et bannière d'origine ; déclinaisons web générées par `scripts/build_web_assets.py` dans `crates/sesame-core/assets/` (embarquées, servies par le portail sous `/static/`, y compris pour les pages du proxy) et `admin/src/sesame_admin/static/` |
| `tests/e2e/` | Parcours bout en bout Playwright sur le compose de dev |
| `deploy/` | `nginx/nginx.conf`, `docker/rust.Dockerfile` (`--build-arg BIN=…`, étages `runtime-portal`/`runtime-proxy`) |
| `.github/` | `workflows/release.yml` : publication des 4 images sur GHCR + Release GitHub, sur tag Git (ADR 0025), notes tirées de `docs/releases/<tag>.md` si présent ; `ISSUE_TEMPLATE/` (formulaires bug, fonctionnalité, appli non prise en charge ; issues vierges désactivées, vulnérabilités renvoyées vers le signalement privé) ; `pull_request_template.md` (liste de vérification reprenant les conventions ci-dessous) |
| Racine (communauté) | `README.md`, `CONTRIBUTING.md` (règles issues / PR, conventions, publication d'une release), `SECURITY.md` (signalement privé GitHub), `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `CHANGELOG.md` ; notes détaillées par version dans `docs/releases/` |
| `docs/` | `architecture.md`, `descriptor.md`, `configuration.md` (variables d'environnement), `dev.md`, `decisions/` (ADR) |

Toute modification du schéma du descripteur se reporte dans `descriptor.rs`, `docs/descriptor.md`, `descriptors/fake-app.yaml` et `descriptors/TEMPLATE.yaml.example`. Toute évolution de la sémantique du rejeu ou des conditions se reporte des deux côtés : `crates/sesame-proxy` (Rust) et `onboarding/` (Python). Toute évolution de `AppDescriptor::validate` ou de la fusion (`sources.rs`) se reporte dans `admin/src/sesame_admin/descriptors.py`. Si le formulaire de l'appli factice change, mettre à jour son `form_fingerprint`.
Toute nouvelle variable d'environnement se documente dans `docs/configuration.md`.
Charte : couleurs reprises du logo (bleu nuit `#0a1f5c`, bleu `#1464c0`, cyan `#13b5cf`), définies dans `sesame_core::html::STYLE` et `admin/…/templates/base.html` : les garder alignées. Après modification d'une image de `ressources/`, relancer `uv run scripts/build_web_assets.py`. Les pages du proxy ne servent aucune ressource sur l'hôte d'une appli : elles pointent vers le portail.
UI d'admin : pas de `from __future__ import annotations` dans `web.py` (FastAPI doit résoudre l'alias local `Admin`) ; le schéma de base appartient aux migrations Rust ; le format d'audit Python doit rester identique à celui des services Rust (JSON compact, `"log_type":"audit"`).
Tests du proxy : banc commun dans `crates/sesame-proxy/tests/common/` (appli simulée + implémentations en mémoire) ; les tests de non-fuite des logs vivent dans un binaire de test séparé (`no_leak.rs`).

## Commandes

```sh
make test                  # tests RAPIDES (défaut, ~10 s) : cargo test + pytest sans navigateur (marqueur `browser` exclu)
make test-full             # tests COMPLETS : test + tests Playwright du recorder + test-postgres (si Docker)
make test-postgres         # tests de contrat PostgreSQL (Rust + Python) sur une base jetable (Docker)
make e2e                   # parcours bout en bout Playwright (après make up-demo)
make health                # test de santé des formulaires de login (après make up-demo)
make record URL=…        # recorder : analyse une page de login, propose un descripteur (après make up)
make lint                  # cargo fmt --check, clippy -D warnings, ruff, validation des descripteurs
make validate-descriptors  # uv run scripts/validate_descriptors.py
make check-dev-keys        # uv run scripts/check_dev_keys.py (clés de dev, docker-compose*.yml)
make deny                  # licences des dépendances Rust (cargo-deny) et Python (scripts/check_python_licenses.py)
make up / make down        # environnement Docker Compose de dev (make dev-certs en préalable automatique)
make up-demo               # comme make up, avec en plus l'appli factice de démo (profil Compose demo, facultative)
make release-images VERSION=vX.Y.Z [REGISTRY=…]  # construit et publie les 4 images (portail, proxy, admin, recorder) sur GHCR ; déclenché en CI par un tag Git (ADR 0025)
```

Environnement de dev : voir `docs/dev.md` (URLs `*.sesame.localhost:8443`, comptes `alice` / `bob` / `carol` / `admin`).

## Conventions de travail

- Documentation et commentaires de conception en français ; identifiants de code en anglais.
- Commits petits et ciblés, messages descriptifs.
- Tests : après chaque modification, lancer **`make test`** (rapide). `make test-full` seulement quand la modification touche le recorder (`record.py`, `proposal.py`, `server.py`), en fin de lot avant un push, ou sur demande. Un test qui lance un navigateur porte le marqueur `browser` (`pytestmark = pytest.mark.browser`).
- Licence Apache-2.0 : chaque fichier source commence par l'en-tête SPDX `SPDX-License-Identifier: Apache-2.0`.
- Dépendances : uniquement des licences compatibles Apache-2.0 (MIT, BSD, Apache-2.0, ISC, MPL-2.0…) ; pas de GPL/AGPL. Vérification en CI (`cargo deny` côté Rust, outil équivalent côté Python).
- Mettre à jour ce fichier quand l'architecture, les commandes de build/test ou les décisions évoluent.
