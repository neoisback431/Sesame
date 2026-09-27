# Sesame : portail SSO à injection de credentials côté serveur

## Contexte

Plusieurs applications web internes ne supportent aucun mécanisme d'authentification fédérée (ni SAML, ni OIDC, ni en-têtes d'identité). Elles n'offrent qu'un formulaire login / mot de passe.

L'objectif est de placer devant elles un portail SSO unique :

- l'utilisateur s'authentifie uniquement via Microsoft Entra ID (OIDC) ;
- il ne connaît jamais les identifiants applicatifs ;
- le portail rejoue la connexion aux applications côté serveur, de façon totalement transparente.

**Contexte réglementaire** : environnement de paiement soumis à PCI-DSS. Chaque accès à un secret doit être tracé.

## Principes non négociables

1. Aucun mot de passe applicatif ne transite vers le navigateur, ni dans une réponse, ni dans un log, ni dans un message d'erreur.
2. Les secrets ne sortent du coffre qu'en mémoire du moteur de proxy, le temps du rejeu, puis sont effacés.
3. Les cookies de session applicatifs restent côté serveur (magasin de sessions). Le navigateur ne détient que le cookie de session du portail.
4. Toute lecture de secret et toute connexion rejouée produit un événement d'audit (qui, quelle appli, quand, résultat).
5. Aucune extension navigateur requise côté poste client.

### Conséquences pour le code (à respecter systématiquement)

- Ne jamais logger, sérialiser, ni inclure dans une erreur un credential, un cookie applicatif ou un jeton : utiliser des types dédiés dont la représentation texte est masquée (`***`).
- Supprimer des réponses relayées au navigateur tout `Set-Cookie` émis par une appli cible.
- Tout chemin de code qui lit Vault ou déclenche un rejeu émet un événement d'audit, y compris en cas d'échec.
- Aucun secret réel dans le dépôt : uniquement des valeurs de dev explicites (appli factice, Vault en mode dev).
- Chaque nouvelle fonctionnalité touchant aux secrets s'accompagne d'un test vérifiant l'absence de fuite (réponse, logs, erreurs).

## Architecture cible

### 1. Portail d'authentification

- Authentification OIDC auprès d'Entra ID.
- Émet et valide la session portail (cookie sécurisé, `HttpOnly`, `Secure`, `SameSite`).
- Résout les habilitations : quel utilisateur / groupe Entra accède à quelle appli.

### 2. Moteur de proxy (plan de données)

- Reverse proxy devant les applications cibles.
- À chaque requête : vérifie la session portail, cherche une session applicative active, sinon déclenche le rejeu.
- Rejeu : GET de la page de login, extraction des champs cachés / jetons CSRF, POST forgé selon le descripteur de l'appli, capture du cookie de session.
- Détecte l'expiration (redirection vers la page de login, codes de statut, marqueurs définis dans le descripteur) et rejoue automatiquement.
- Réécrit si nécessaire les redirections et URLs absolues des applis.

### 3. Coffre de secrets

- HashiCorp Vault.
- Identifiants par couple (appli, utilisateur) (voir Décisions).
- Seul le moteur de proxy dispose d'une policy de lecture. Authentification du proxy auprès de Vault par AppRole (ou équivalent).

### 4. Magasin de sessions

- Table de correspondance : session portail → sessions applicatives (cookies par appli).
- TTL, invalidation à la déconnexion du portail, purge des sessions expirées.
- Implémentation : PostgreSQL (voir Décisions).

### 5. Module d'embarquement

- Assistant qui, à partir d'une URL de login et d'un compte de test, pilote une connexion réelle via navigateur headless (Playwright).
- Capture : champs du formulaire, action, méthode, champs cachés, jetons CSRF, redirection post-login, nom du cookie de session, marqueurs d'expiration.
- Génère un descripteur d'appli (YAML/JSON versionné) soumis à validation humaine.
- Réutilisé en tâche périodique comme test de santé : alerte si le formulaire de login d'une appli a changé.
- Hors périmètre initial : login multi-étapes, captcha, MFA applicatif (à traiter au cas par cas).

### Fonctions transverses

- **Administration** : gestion des applis, descripteurs, habilitations, comptes associés.
- **Observabilité** : logs structurés JSON, métriques et traces exploitables par Datadog, journal d'audit dédié.

## Flux nominal

1. L'utilisateur accède à une appli protégée via le portail.
2. Pas de session portail → redirection OIDC vers Entra → retour avec session portail.
3. Le moteur de proxy cherche une session applicative dans le magasin.
4. Absente ou expirée → lecture du credential dans Vault → rejeu du login selon le descripteur → stockage du cookie applicatif.
5. La requête est relayée à l'appli avec le cookie applicatif injecté ; la réponse revient au navigateur sans aucun secret.

## Environnement et outillage

- Déploiement : Docker Compose pour le dev / la démo, GitLab CI pour la chaîne d'intégration.
- Frontal TLS : Nginx.
- Cibles de déploiement possibles : on-premises (VMware) et AWS.

## Décisions

| Sujet | Décision | État |
|---|---|---|
| Langage | **Rust** pour le back (portail d'authentification + moteur de proxy) ; **Python** pour le reste (module d'embarquement Playwright, UI d'administration) | Tranché |
| Magasin de sessions | **PostgreSQL** (purge des sessions expirées à implémenter : tâche périodique ou `DELETE` sur `expires_at`) | Tranché |
| Modèle des credentials | **Par utilisateur** : un compte par couple (appli, utilisateur) dans Vault | Tranché |
| Interface d'administration | **UI web dès le départ** (Python) ; authentifiée via Entra, réservée à un groupe d'administrateurs, actions tracées dans l'audit | Tranché |

Les décisions ont été prises le 2026-09-27. Consigner leur justification dans `docs/decisions/` (ADR). Toute nouvelle décision structurante est posée en question avant d'être codée, puis ajoutée à ce tableau.

## Première étape attendue (initialisation)

1. Proposer la structure du dépôt (un dossier par bloc, dossier `descriptors/`, `deploy/`, `docs/`).
2. Rédiger `docs/architecture.md` et un schéma Mermaid des flux.
3. Définir le schéma du descripteur d'appli.
4. Mettre en place un `docker-compose.yml` de dev : Nginx, portail, proxy, Vault (mode dev), PostgreSQL, et une appli factice avec un formulaire de login + CSRF pour les tests.
5. Implémenter un MVP bout en bout sur l'appli factice : login Entra (ou mock OIDC en dev), rejeu, injection de session.
6. Pipeline GitLab CI minimal : lint, tests, build des images.

## Conventions de travail

- Documentation et commentaires de conception en français ; identifiants de code en anglais.
- Commits petits et ciblés, messages descriptifs.
- Mettre à jour ce fichier quand l'architecture, les commandes de build/test ou les décisions évoluent.
