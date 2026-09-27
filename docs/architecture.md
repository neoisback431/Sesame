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
| Portail | OIDC, session portail, habilitations, déconnexion | Aucun |
| Moteur de proxy | Relais, rejeu du login, injection de session, détection d'expiration | **Seul lecteur du coffre** |
| Magasin de sessions | Session portail → sessions applicatives (cookies chiffrés) | Cookies applicatifs (chiffrés) |
| UI d'administration | Applis, descripteurs, habilitations, comptes associés | Écriture seule, sans relecture (voir plus bas) |
| Module d'embarquement | Capture du formulaire, génération de descripteur, test de santé | Compte de test fourni ponctuellement |

## Routage : une appli par nom d'hôte

Chaque appli protégée est exposée sous son propre nom d'hôte (`spec.public.host`), par exemple `compta.sesame.example`. Le proxy choisit l'appli d'après l'en-tête `Host`.

Ce choix évite de réécrire les chemins (`/app1/...`). Les applis anciennes cassent souvent sous un préfixe (liens absolus, cookies `Path=/`, JavaScript). La réécriture se limite aux URLs absolues internes (`http://app-interne:8000/...`) dans `Location` et, si le descripteur le demande, dans le corps HTML.

Le portail vit sur le domaine parent (`sesame.example`). Son cookie est posé pour ce domaine et reçu par tous les sous-domaines.

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

- Seules les requêtes idempotentes (`GET`, `HEAD`, `OPTIONS`) sont répétées automatiquement. Pour un `POST` expiré, Sesame rejoue le login puis redirige l'utilisateur (`303`) vers la page d'origine. La soumission est perdue : c'est un point d'UX à affiner.
- **Un seul rejeu à la fois** par couple (session portail, appli). Les requêtes concurrentes attendent le résultat.
- **Protection contre le verrouillage de compte** : au plus `login.max_attempts` rejeux consécutifs. Après un échec (règle `login.failure` ou absence de `login.success`), le couple (appli, utilisateur) passe en attente avec un délai croissant et une page d'erreur neutre s'affiche. Cette page ne contient jamais le contenu de la réponse de l'appli.

## Magasin de sessions (PostgreSQL)

Schéma indicatif, finalisé avec le MVP :

```sql
CREATE TABLE portal_sessions (
    id_hash      bytea PRIMARY KEY,      -- SHA-256 du jeton du cookie, jamais le jeton lui-même
    issuer       text        NOT NULL,
    subject      text        NOT NULL,
    user_key     text        NOT NULL,
    display_name text,
    groups       text[]      NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL
);

CREATE TABLE app_sessions (
    portal_session bytea NOT NULL REFERENCES portal_sessions(id_hash) ON DELETE CASCADE,
    app_id         text  NOT NULL,
    cookies        bytea NOT NULL,       -- jar de cookies chiffré (AES-256-GCM)
    created_at     timestamptz NOT NULL,
    last_used_at   timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    PRIMARY KEY (portal_session, app_id)
);

CREATE INDEX ON portal_sessions (expires_at);
CREATE INDEX ON app_sessions (expires_at);
```

- **Jeton portail** : 256 bits aléatoires dans le cookie. La base n'en stocke que le hash, si bien qu'une fuite de la base ne permet pas de voler des sessions.
- **Cookies applicatifs chiffrés au repos**, avec une clé fournie par configuration. Un fournisseur de clé (KMS, coffre) sera branché derrière une interface.
- **Déconnexion du portail** : suppression de la session portail, puis `ON DELETE CASCADE` sur les sessions applicatives.
- **Purge** : tâche périodique `DELETE … WHERE expires_at < now()`. PostgreSQL n'a pas de TTL natif.
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
| `access_denied` | Proxy | Utilisateur non habilité pour l'appli |
| `secret_read` | Proxy | Lecture du coffre (succès ou échec) |
| `login_replay` | Proxy | Rejeu du login (succès, échec, abandon) |
| `app_session_expired` | Proxy | Expiration détectée |
| `app_logout` | Proxy | Chemin de déconnexion de l'appli appelé |

Champs : horodatage UTC, action, résultat, acteur (`issuer` + `subject`), appli, identifiant de corrélation, raison courte. Jamais de secret, de cookie ni de contenu de réponse.

## Fournisseur d'identité

- OIDC générique : discovery (`/.well-known/openid-configuration`), flux *authorization code* avec PKCE, vérification de `state`, `nonce`, `iss`, `aud` et de la signature.
- Mapping de claims configurable : `user_key` (défaut `sub`), `groups` (défaut `groups`), libellé (`email`, `name`). Un claim `groups` absent vaut « aucun groupe ».
- Particularités d'Entra ID gérées par configuration : `oid` comme clé, identifiants de groupes (GUID) dans le claim `groups`, *groups overage* au-delà de 200 groupes. Ce dernier cas relève d'un module optionnel, hors du cœur.
- En dev : Keycloak (realm `sesame`, voir `dev/keycloak/`).

## Module d'embarquement

1. Un administrateur fournit l'URL de login et un compte de test.
2. Playwright effectue une connexion réelle et observe les formulaires, les champs cachés, les jetons CSRF (input, meta, cookie), la requête de login, la redirection et les cookies posés.
3. Le module génère un descripteur conforme au schéma et une empreinte de la structure du formulaire (`health.form_fingerprint`).
4. Un humain relit le descripteur, puis le valide dans l'UI d'admin ou par merge request.
5. En tâche périodique, le module recalcule l'empreinte et alerte en cas d'écart.

Hors périmètre initial : login en plusieurs étapes, captcha, MFA applicatif.

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
| Élévation via l'UI d'admin | Groupe d'administrateurs dédié, audit de chaque action, écriture sans relecture des secrets |
| Accès direct aux applis sans passer par Sesame | Hors de Sesame : filtrage réseau recommandé (seul le proxy joint les applis) |

## Environnement de dev

Voir [`docs/dev.md`](dev.md).
