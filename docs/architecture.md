# Architecture de Sesame

Sesame est un portail SSO placé devant des applications web qui n'offrent qu'un formulaire login / mot de passe. L'utilisateur s'authentifie une seule fois auprès du fournisseur d'identité de l'organisation (OIDC). Sesame rejoue ensuite côté serveur la connexion à chaque application, avec des identifiants que l'utilisateur ne voit jamais.

Ce document décrit l'architecture cible. Les principes non négociables et les décisions sont dans [`CLAUDE.md`](../CLAUDE.md) et [`docs/decisions/`](decisions/).

## Vue d'ensemble

```mermaid
flowchart LR
    B[Navigateur]
    subgraph Frontal
        N[Nginx<br/>TLS]
    end
    subgraph Sesame
        P[Portail<br/>Rust]
        X[Moteur de proxy<br/>Rust]
        A[UI d'admin<br/>Python]
        O[Embarquement<br/>Python + Playwright]
    end
    subgraph "Briques externes (interchangeables)"
        IDP[(Fournisseur d'identité<br/>OIDC)]
        S[(Coffre de secrets<br/>OpenBao / Vault…)]
        DB[(Magasin de sessions<br/>PostgreSQL)]
        AU[(Journal d'audit)]
        OT[(Observabilité<br/>OpenTelemetry)]
    end
    APP1[Appli cible 1]
    APP2[Appli cible 2]

    B -- "HTTPS (cookie portail uniquement)" --> N
    N -- "sesame.example" --> P
    N -- "*.sesame.example" --> X
    P -- OIDC --> IDP
    P -- sessions portail --> DB
    X -- sessions portail + applicatives --> DB
    X -- "lecture credential (seul lecteur)" --> S
    X -- "rejeu + relais (cookie applicatif injecté)" --> APP1
    X --> APP2
    P & X & A --> AU
    P & X & A & O -.-> OT
    A -- descripteurs, habilitations --> DB
    O -- "capture du formulaire" --> APP1
```

| Composant | Rôle | Accès aux secrets applicatifs |
|---|---|---|
| Nginx | Terminaison TLS, routage par nom d'hôte | Aucun |
| Portail | OIDC, session portail, page « Mes applications », déconnexion | Aucun |
| Moteur de proxy | Relais, rejeu du login, injection de session, détection d'expiration | **Seul lecteur du coffre** |
| Magasin de sessions | Session portail → sessions applicatives (cookies chiffrés) | Cookies applicatifs (chiffrés) |
| UI d'administration | Applis, descripteurs, habilitations, registre des comptes | Écriture seule, sans relecture (voir plus bas) |
| Module d'embarquement | Capture du formulaire, génération de descripteur, test de santé | Compte de test fourni ponctuellement |

## Parcours utilisateur

```mermaid
sequenceDiagram
    autonumber
    actor U as Utilisateur
    participant P as Portail
    participant I as Fournisseur d'identité
    participant X as Moteur de proxy
    participant A as Appli (via Sesame)

    U->>P: https://sesame.example
    P->>I: SSO (si pas de session portail)
    I-->>P: identité + groupes
    P-->>U: page « Mes applications » (tuiles)
    U->>X: clic sur une tuile : https://compta.sesame.example/
    Note over X: pas de session applicative : rejeu du login (1 à 2 s)
    X->>A: rejeu puis requête relayée
    A-->>U: appli affichée, utilisateur déjà connecté
```

1. L'utilisateur se connecte au portail en SSO.
2. Le portail affiche la page **« Mes applications »** : une tuile par appli pour laquelle l'utilisateur est **habilité** (groupes / utilisateurs du descripteur) **et** possède un **compte actif** dans le registre des comptes. Les applis sans compte sont masquées.
3. Un clic sur une tuile ouvre l'adresse de l'appli **exposée par Sesame** (`compta.sesame.example`), jamais son adresse réelle : tout le trafic passe par le proxy, et les cookies applicatifs restent côté serveur.
4. Le proxy constate l'absence de session applicative et rejoue le login à ce moment-là. C'est le même mécanisme que pour une session expirée, donc un seul chemin de code.
5. L'utilisateur arrive dans l'appli, déjà connecté.

Compléments :

- **Accès direct** : un favori ou un lien profond (`https://compta.sesame.example/factures/42`) fonctionne aussi. SSO si nécessaire, rejeu, puis la page demandée.
- **Échec du rejeu** : le proxy affiche une page d'erreur neutre (identifiant de corrélation, lien de retour au portail) et passe le compte à l'état `failed` dans le registre. La tuile le signale jusqu'à ce qu'un administrateur corrige le compte.
- **Retour au portail** : par son adresse, ou via le lien des pages d'erreur. Sesame n'injecte pas de bandeau dans les pages des applis, ce serait fragile et risqué.
- **Déconnexion** : se déconnecter du portail détruit la session portail et toutes les sessions applicatives. Avec `SESAME_OIDC_LOGOUT=true` (désactivé par défaut), le portail ferme aussi la session chez le fournisseur d'identité (OIDC RP-Initiated Logout : `end_session_endpoint` avec `client_id` et `post_logout_redirect_uri`), puis l'utilisateur revient sur `/auth/logged-out`. Voir [ADR 0013](decisions/0013-deconnexion-fournisseur.md).

## Registre des comptes

Le portail doit savoir quelles applis afficher sans accéder au coffre : seul le proxy le lit. Un **registre des comptes**, dans PostgreSQL, indique pour chaque couple (appli, utilisateur) qu'un compte applicatif existe, avec son état. Il ne contient **aucun secret**.

| État | Sens | Tuile | Rejeu |
|---|---|---|---|
| `active` | Compte provisionné | Affichée | Autorisé |
| `failed` | Dernier rejeu en échec (identifiants refusés, formulaire changé…) | Affichée, signalée | Bloqué jusqu'à correction |
| `disabled` | Désactivé par un administrateur | Masquée | Bloqué |

- **Source** : l'UI d'admin. Elle écrit le secret dans le coffre (sans pouvoir le relire) et crée ou met à jour l'entrée du registre dans la même opération.
- **Proxy** : avant de lire le coffre, il vérifie l'habilitation et l'état `active` du compte. Sinon, il refuse sans lire le coffre et émet `access_denied`. Après un rejeu, il met à jour `last_login_at` ou passe le compte à `failed`.
- Le registre et le coffre peuvent diverger (secret supprimé à la main, par exemple). La lecture du coffre en échec passe alors le compte à `failed`.

## Routage : une appli par nom d'hôte

Chaque appli protégée est exposée sous son propre nom d'hôte (`spec.public.host`), par exemple `compta.sesame.example`. Le proxy choisit l'appli d'après l'en-tête `Host`.

Ce choix évite de réécrire les chemins (`/app1/...`). Les applis anciennes cassent souvent sous un préfixe (liens absolus, cookies `Path=/`, JavaScript). La réécriture se limite aux URLs absolues internes (`http://app-interne:8000/...`) dans `Location` et, si le descripteur le demande, dans le corps HTML.

Le portail vit sur le domaine parent (`sesame.example`). Son cookie est posé pour ce domaine et reçu par tous les sous-domaines. Le proxy le retire avant de relayer une requête et capture tous les `Set-Cookie` des applis (voir [ADR 0008](decisions/0008-routage-par-nom-d-hote.md)).

## Flux nominal

```mermaid
sequenceDiagram
    autonumber
    actor U as Navigateur
    participant X as Moteur de proxy
    participant P as Portail
    participant I as Fournisseur d'identité
    participant DB as Magasin de sessions
    participant S as Coffre
    participant A as Appli cible
    participant AU as Audit

    U->>X: GET https://compta.sesame.example/factures
    X->>DB: session portail ?
    DB-->>X: absente
    X-->>U: 302 vers le portail (return_to)
    U->>P: GET /auth/login?return_to=…
    P-->>U: 302 vers le fournisseur (code + PKCE + state + nonce)
    U->>I: authentification
    I-->>U: 302 /auth/callback?code=…
    U->>P: GET /auth/callback
    P->>I: échange du code (back-channel)
    I-->>P: id_token (sub, groups…)
    P->>DB: crée la session portail
    P->>AU: portal_login / success
    P-->>U: 302 return_to + Set-Cookie sesame_session (HttpOnly, Secure, SameSite=Lax)

    U->>X: GET /factures (cookie portail)
    X->>DB: session portail valide ? session applicative ?
    DB-->>X: absente
    X->>X: habilitation (groupes / utilisateurs du descripteur)
    X->>S: get_credential(compta, user_key)
    X->>AU: secret_read / success
    X->>A: GET /login
    A-->>X: formulaire + champs cachés + CSRF + cookie de pré-session
    X->>A: POST /login (champs du descripteur + CSRF + identifiants)
    Note over X: identifiants effacés de la mémoire
    A-->>X: 302 + Set-Cookie session applicative
    X->>AU: login_replay / success
    X->>DB: stocke les cookies applicatifs (chiffrés)
    X->>A: GET /factures (cookie applicatif injecté)
    A-->>X: 200
    X-->>U: 200 (sans Set-Cookie applicatif, URLs réécrites)
```

## Expiration de la session applicative

Le proxy examine chaque réponse relayée avec les règles `spec.expiry` du descripteur : redirection vers la page de login, code 401, marqueur dans le corps…

```mermaid
sequenceDiagram
    autonumber
    actor U as Navigateur
    participant X as Moteur de proxy
    participant A as Appli cible
    participant S as Coffre
    participant DB as Magasin de sessions

    U->>X: GET /factures
    X->>A: GET /factures (cookie applicatif)
    A-->>X: 302 /login  (règle expiry)
    X->>DB: supprime la session applicative
    X->>S: get_credential (audité)
    X->>A: rejeu du login
    A-->>X: nouvelle session
    X->>DB: stocke
    X->>A: GET /factures (répétée : méthode idempotente)
    A-->>X: 200
    X-->>U: 200
```

Règles :

- Seules les requêtes idempotentes (`GET`, `HEAD`, `OPTIONS`) sont répétées automatiquement. Pour un `POST` expiré, Sesame rejoue le login puis redirige l'utilisateur (`303`) vers la page d'origine (`Referer` s'il désigne la même appli, sinon la racine de l'appli). La soumission est perdue, ce qui évite toute double soumission. Un message l'explique à l'utilisateur.
- **Un seul rejeu à la fois** par couple (session portail, appli). Les requêtes concurrentes attendent le résultat.
- **Protection contre le verrouillage de compte** : au plus `login.max_attempts` rejeux consécutifs. Après un échec (règle `login.failure` ou absence de `login.success`), le couple (appli, utilisateur) passe en attente avec un délai croissant et une page d'erreur neutre s'affiche. Cette page ne contient jamais le contenu de la réponse de l'appli.

## Magasin de sessions (PostgreSQL)

Schéma : [`crates/sesame-store-postgres/migrations/`](../crates/sesame-store-postgres/migrations/). Les migrations sont appliquées au démarrage du portail et du proxy (verrou consultatif, sûr en parallèle).

| Table | Contenu |
|---|---|
| `portal_sessions` | Empreinte SHA-256 du jeton du cookie (jamais le jeton), identité, groupes, échéance |
| `app_sessions` | Jar de cookies applicatifs **chiffré** (AES-256-GCM, lié par AAD au couple session / appli), dates, échéance ; `ON DELETE CASCADE` depuis la session portail |
| `app_accounts` | Registre des comptes (voir plus haut), sans secret |

- **Jeton portail** : 256 bits aléatoires dans le cookie. La base n'en stocke que le hash, si bien qu'une fuite de la base ne permet pas de voler des sessions.
- **Cookies applicatifs chiffrés au repos**, avec une clé fournie par configuration. Un fournisseur de clé (KMS, coffre) sera branché derrière une interface.
- **Déconnexion du portail** : suppression de la session portail, puis `ON DELETE CASCADE` sur les sessions applicatives.
- **Purge** : le proxy supprime toutes les 5 minutes les sessions dont `expires_at` est passé. PostgreSQL n'a pas de TTL natif.
- **Durées de vie** : la session applicative expire au plus tôt des trois échéances `session.max_ttl`, `session.idle_ttl` et fin de la session portail.

## Coffre de secrets

- Interface `SecretStore::get_credential(app_id, user_key)`. Implémentation de référence : OpenBao / Vault (KV v2).
- Chemin : `<mount>/sesame/apps/<app_id>/users/<user_key>`. Les clés (`username`, `password`…) sont celles listées dans `spec.credentials.keys`.
- Le moteur de proxy s'authentifie par AppRole et sa policy se limite à la lecture de `sesame/apps/*`. L'UI d'admin a une policy d'écriture sans lecture (`create`, `update`, `delete`) : un administrateur peut définir un mot de passe sans pouvoir le relire.
- `user_key` provient d'un claim configurable. On privilégie un identifiant immuable (`sub`, ou `oid` pour Entra ID) plutôt que l'e-mail ou le nom d'utilisateur, qui peuvent être réattribués.
- En mémoire, les identifiants sont portés par des types qui ne s'affichent jamais et sont effacés à la destruction (`secrecy` / `zeroize`). Ils vivent le temps du rejeu uniquement.

## Hygiène des en-têtes dans le proxy

| Sens | Traitement |
|---|---|
| Navigateur → appli | Retirer le cookie du portail et tout cookie non géré, puis injecter les cookies applicatifs. Retirer `Authorization` venant du navigateur. Réécrire `Host` si `upstream.host_header` est défini. |
| Appli → navigateur | Capturer **tous** les `Set-Cookie` dans le jar côté serveur ; aucun n'atteint le navigateur. Réécrire `Location`. Réécrire les URLs absolues internes du corps si demandé. |
| Erreurs | Pages d'erreur génériques de Sesame, avec un identifiant de corrélation. Jamais de contenu de l'appli lors d'un échec de rejeu. |

## Audit

Chaque lecture de secret et chaque rejeu produit un événement, succès ou échec. L'écriture d'audit fait partie de l'opération : si l'audit échoue, l'opération échoue.

| Action | Émis par | Quand |
|---|---|---|
| `portal_login` / `portal_logout` | Portail | Session portail créée / détruite |
| `access_denied` | Proxy | Utilisateur non habilité, ou compte absent / inactif dans le registre |
| `account_status_changed` | Proxy, UI d'admin | Changement d'état d'un compte du registre (`active`, `failed`, `disabled`) |
| `admin_login` | UI d'admin | Connexion d'un administrateur |
| `credential_written` / `credential_deleted` | UI d'admin | Écriture ou suppression d'identifiants dans le coffre |
| `descriptor_created` / `descriptor_updated` / `descriptor_deleted` | UI d'admin | Création, modification ou suppression d'un descripteur en base (`reason` : `revision:<n>` en succès, cause en échec) |
| `secret_read` | Proxy | Lecture du coffre (succès ou échec) |
| `login_replay` | Proxy | Rejeu du login (succès, échec, abandon) |
| `app_session_expired` | Proxy | Expiration détectée |
| `app_logout` | Proxy | Chemin de déconnexion de l'appli appelé |

Champs : horodatage UTC, action, résultat, acteur (`issuer` + `subject`), appli, compte visé (`target_user`, pour les actions d'administration), identifiant de corrélation, raison courte. Jamais de secret, de cookie ni de contenu de réponse.

## Fournisseur d'identité

- OIDC générique : discovery (`/.well-known/openid-configuration`), flux *authorization code* avec PKCE, vérification de `state`, `nonce`, `iss`, `aud` et de la signature.
- L'état de la connexion en cours (`state`, `nonce`, vérificateur PKCE, `return_to`) voyage dans un cookie chiffré (AES-256-GCM, 10 minutes, `Path=/auth`) : le portail reste sans état et peut être répliqué.
- `return_to` n'accepte que le portail et les hôtes publics déclarés dans les descripteurs, avec le même schéma : pas de redirection ouverte.
- Mapping de claims configurable : `user_key` (défaut `sub`), `groups` (défaut `groups`), libellé (`email`, `name`). Un claim `groups` absent vaut « aucun groupe ».
- Particularités d'Entra ID gérées par configuration : `oid` comme clé, identifiants de groupes (GUID) dans le claim `groups`, *groups overage* au-delà de 200 groupes. Ce dernier cas relève d'un module optionnel, hors du cœur.
- En dev : Keycloak (realm `sesame`, voir `dev/keycloak/`).

## UI d'administration

Application Python (FastAPI, pages rendues côté serveur) sur son propre nom d'hôte (`admin.sesame.example`). Voir [ADR 0011](decisions/0011-administration.md).

| Écran / action | Effet |
|---|---|
| Applications | Liste des applis (fichiers Git et base) avec le nombre de comptes par état, et les descripteurs en base écartés du catalogue (à corriger) |
| Appli → comptes | Registre des comptes de l'appli : état, raison d'un échec, dernière connexion |
| Enregistrer un compte | Identifiants écrits dans le coffre, **puis** compte `active` dans le registre. Réenregistrer remplace les identifiants et réactive un compte `failed` |
| Désactiver / réactiver | Change l'état dans le registre (`failed` reste réservé au proxy). La désactivation **révoque les sessions applicatives ouvertes** de l'utilisateur sur l'appli : l'accès est coupé immédiatement |
| Supprimer | Supprime les identifiants du coffre (toutes versions) puis l'entrée du registre, et révoque les sessions ouvertes |
| Utilisateurs | Recherche d'un utilisateur et liste de tous ses comptes, toutes applis confondues, avec les mêmes actions |
| Tout désactiver | Départ ou suspension : désactive tous les comptes de l'utilisateur, y compris ceux d'applis dont le descripteur a été retiré, et révoque leurs sessions |
| Nouvelle application | Formulaire guidé qui produit un premier jet, puis éditeur YAML : « Vérifier » (schéma et contrôles du proxy, sans enregistrer) et « Créer ». L'appli est en base ; portail et proxy la chargent sans redémarrage |
| Modifier le descripteur | Éditeur YAML, applis en base uniquement. Refusé si la révision a changé depuis l'ouverture (deux administrateurs ne s'écrasent pas). L'`id` ne change pas |
| Historique des révisions | Chaque création, modification ou suppression : date, auteur, document |
| Supprimer l'application | Applis en base uniquement, et seulement sans compte restant : les identifiants resteraient sinon dans le coffre sans apparaître nulle part |
| Applis décrites par un fichier | Lecture seule : modification par merge request, rechargées au redémarrage |

- **Accès** : OIDC auprès du même fournisseur d'identité, avec un client dédié. Membres du groupe d'administrateurs uniquement (`SESAME_ADMIN_GROUP`) ; les autres reçoivent `access_denied`.
- **Coffre** : AppRole de l'admin avec une policy d'écriture sans lecture. Un identifiant saisi ne peut jamais être relu, ni dans l'UI ni par l'API du coffre.
- **Protections web** : jeton CSRF sur chaque action, cookie de session signé (`HttpOnly`, `Secure`, `SameSite=Lax`, 1 h) régénéré à la connexion, redirection après connexion limitée aux chemins locaux.
- **Audit** : `admin_login`, `credential_written`, `credential_deleted`, `account_status_changed`, `access_denied`, `descriptor_created`, `descriptor_updated`, `descriptor_deleted`, avec l'administrateur comme acteur et le compte visé dans `target_user`.

### Catalogue des applis : fichiers et base

Voir [ADR 0014](decisions/0014-applis-en-base.md).

```mermaid
flowchart LR
    G[descriptors/*.yaml<br/>Git, lecture seule] -- au démarrage --> C
    A[UI d'admin] -- "création, modification, suppression<br/>(révision attendue)" --> T[(app_descriptors<br/>+ app_descriptor_history)]
    T -- "version = dernier id de l'historique<br/>vérifiée toutes les SESAME_DESCRIPTORS_RELOAD" --> C[Catalogue<br/>portail et proxy]
```

- **Fusion** : fichiers d'abord, puis base dans l'ordre des identifiants. Un descripteur en base invalide, ou dont l'`id` ou l'hôte public est déjà pris, est écarté et journalisé ; le service continue. L'administration applique les mêmes règles et affiche les descripteurs écartés.
- **Rechargement à chaud** : le portail et le proxy relisent le catalogue seulement quand la version (dernier identifiant de l'historique) change, et l'échangent sans interrompre les requêtes en cours.
- **Concurrence** : chaque écriture indique la révision qu'elle remplace ; une révision périmée est refusée. Un index unique empêche deux descripteurs en base de partager un hôte public.
- **Aucun secret** : un descripteur ne référence les identifiants que par nom de clé (`credentials.keys`).

## Module d'embarquement

Outil en ligne de commande `sesame-onboard` (Python). Voir [ADR 0012](decisions/0012-embarquement.md) et [ADR 0015](decisions/0015-recorder.md) (recorder).

Le moteur de proxy rejoue le login **sans exécuter de JavaScript** : il lit le formulaire dans le HTML brut. L'embarquement repose sur ce même principe.

1. `sesame-onboard record <URL de login>` propose un descripteur (voir « Recorder » ci-dessous), ou un administrateur le rédige à partir de [`descriptors/TEMPLATE.yaml.example`](../descriptors/TEMPLATE.yaml.example) ou du formulaire guidé de l'administration.
2. `sesame-onboard verify <descripteur>` rejoue le login avec un compte de test, avec les mêmes règles que le proxy (champs cachés, CSRF, conditions, cookie de session). Le résultat indique la cause d'un échec, par exemple `login_form_not_found_in_raw_html` pour un formulaire construit en JavaScript, ou `csrf_token_not_found`, `login_rejected`, `session_cookie_missing`.
3. `sesame-onboard fingerprint <descripteur>` calcule l'empreinte de la structure du formulaire (action, méthode, champs, sans les valeurs), à reporter dans `spec.health.form_fingerprint`.
4. Un humain relit le descripteur, qui est fusionné par merge request, ou l'enregistre dans l'éditeur de l'administration.
5. `sesame-onboard health <dossier>` tourne en tâche périodique (cron, CI, service `health` du compose). Il recalcule l'empreinte **sans identifiants** et sort en erreur si le formulaire a changé (`changed`), a disparu (`form_missing`) ou si l'appli est injoignable (`unreachable`).

Les identifiants du compte de test sont lus dans l'environnement (`SESAME_ONBOARD_<CLÉ>`) ou saisis en masqué. Ils ne sont jamais écrits dans un fichier, dans la sortie ni dans les logs.

### Recorder

`sesame-onboard record` analyse le comportement de la page de login dans un Chromium headless (Playwright), **sans aucun identifiant réel**.

```mermaid
sequenceDiagram
    autonumber
    participant R as Recorder
    participant B as Chromium headless
    participant A as Appli cible
    R->>B: ouvrir la page de login (contexte jetable)
    B->>A: GET /login (JavaScript exécuté)
    R->>B: repérer formulaire, champs, jetons CSRF, captcha
    R->>B: remplir des valeurs factices, soumettre
    B--xR: soumission interceptée et annulée (méthode, cible, encodage, noms des champs, en-têtes)
    opt --probe-failure
        B->>A: soumission factice relayée (une seule)
        A-->>B: réponse d'échec (statut, message)
    end
    R->>A: GET /login sans JavaScript (vue du proxy, empreinte)
    R->>A: GET page protégée sans session (règle d'expiration)
    R-->>R: descripteur YAML + points à confirmer
```

- Sont conservés : noms de champs, de cookies et d'en-têtes, codes de statut, chemins, message d'erreur visible. Jamais : valeurs des champs cachés, jetons CSRF, cookies, valeurs factices.
- Pendant l'analyse, aucune requête d'écriture ne sort de l'origine de l'appli ; une seule soumission au plus.
- Blocages signalés (code de sortie 1) : formulaire absent du HTML brut, page de login hors de l'appli (SSO), captcha, login en plusieurs étapes, soumission non observée. Avertissements : login soumis par JavaScript, champs ajoutés à la soumission, encodage non pris en charge.
- Non observable sans identifiants : le cookie de session et la réponse de succès. Ils sont marqués « à confirmer » ; `sesame-onboard verify` avec un compte de test les valide.

Hors périmètre initial : login en plusieurs étapes, captcha, MFA applicatif, enregistrement d'une connexion réelle.

## Observabilité

- Logs JSON sur stdout (Rust : `tracing`). Aucun secret, aucun cookie, pas de query string dans les logs d'accès.
- Métriques et traces via OpenTelemetry (OTLP), exploitables par Datadog, Prometheus, etc.
- Métriques clés : rejeux (succès / échec, par appli), latence du rejeu, expirations détectées, erreurs du coffre, sessions actives.

## Modèle de menace (résumé)

| Menace | Mesure |
|---|---|
| Vol du cookie portail | `HttpOnly`, `Secure`, `SameSite=Lax`, durée limitée, liaison optionnelle à l'empreinte TLS / IP à étudier |
| Fuite de la base de sessions | Jetons portail hachés, cookies applicatifs chiffrés |
| Fuite de secret via logs / erreurs | Types secrets non affichables, tests de non-fuite, pages d'erreur génériques |
| Appli compromise qui pose des cookies sur le domaine parent | Tous les `Set-Cookie` sont capturés par le proxy et n'atteignent jamais le navigateur |
| Verrouillage de compte par rejeux en boucle | `max_attempts`, attente à délai croissant, alerte |
| Élévation via l'UI d'admin | Groupe d'administrateurs dédié, audit de chaque action (y compris les descripteurs : un administrateur peut changer l'hôte ou l'URL amont d'une appli), écriture sans relecture des secrets, historique des révisions |
| Accès direct aux applis sans passer par Sesame | Hors de Sesame : filtrage réseau recommandé (seul le proxy joint les applis) |

## Environnement de dev

Voir [`docs/dev.md`](dev.md).
