# 0024. Support SAML 2.0, en plus d'OIDC

**Statut** : acceptée (2026-09-28), implémentée.

## Contexte

`CLAUDE.md` documentait dès le départ l'interface `IdentityProvider` comme « OIDC générique »,
mais aucune abstraction n'existait réellement dans le code : `crates/sesame-portal/src/oidc.rs`
était appelé directement, sans intermédiaire. L'exploitant a demandé de pouvoir configurer Sesame
avec un fournisseur d'identité qui n'expose que SAML 2.0 (cas fréquent en entreprise, y compris
avec Entra ID configuré en SAML plutôt qu'en OIDC).

## Décision

- **Un seul protocole actif par déploiement** (`SESAME_IDP_PROTOCOL=oidc` [défaut] `|saml`), le
  même pour le portail et l'administration (pas de bascule à chaud, pas de double bouton de
  connexion). Cohérent avec le modèle actuel « un fournisseur configurable ».
- **Bibliothèques** : `samael` (Rust, MIT, feature `xmlsec`) côté portail ;
  `python3-saml` (Python, MIT, OneLogin) côté administration — même choix des deux côtés (mature,
  largement utilisées, vérification de signature XML déléguée à `xmlsec1`/OpenSSL plutôt que
  réimplémentée). Une bibliothèque SAML pure Rust/Python sans dépendance C existe mais est trop
  récente et peu éprouvée pour la vérification de signature XML, point le plus sensible en
  sécurité d'une implémentation SAML (risque historique de vulnérabilités de type XML Signature
  Wrapping) : la maturité l'emporte sur la simplicité d'installation.
- **Vérification de signature jamais désactivable** : sans certificat IdP valide, le portail
  refuse de démarrer (`SESAME_SAML_IDP_CERT_FILE` requis) ; côté admin, `wantAssertionsSigned` est
  forcé à `true` dans le code (faux par défaut dans `python3-saml`, jamais exposé en
  configuration).
- **Pas de récupération dynamique d'un document de métadonnées IdP** : URL de SSO, émetteur et
  certificat viennent de variables d'environnement (`SESAME_SAML_IDP_*`), cohérent avec le reste
  du projet (aucune brique externe supplémentaire, pas d'appel réseau à l'IdP hors du flux de
  connexion lui-même).
- **Anti-rejeu** : l'identifiant de l'`AuthnRequest` émise est conservé le temps de l'aller-retour
  (cookie chiffré côté portail comme pour l'état OIDC ; session signée existante côté admin) et
  comparé à `InResponseTo` de la réponse, en plus des vérifications faites par la bibliothèque
  (signature, émetteur, audience, fenêtre de validité `NotBefore`/`NotOnOrAfter`).
- **Attributs configurables** : `SESAME_SAML_USER_KEY_ATTRIBUTE` (absent : `NameID`),
  `SESAME_SAML_EMAIL_ATTRIBUTE`, `SESAME_SAML_GROUPS_ATTRIBUTE` — même rôle que
  `SESAME_OIDC_USER_KEY_CLAIM`/`SESAME_OIDC_GROUPS_CLAIM`, sans dépendre d'un fournisseur précis.
- **Métadonnées SP publiées** sur `/saml/metadata` (portail et admin), générées à partir de la
  configuration : simplifie l'inscription de Sesame chez l'IdP. `404` hors protocole SAML.
- **Assertion Consumer Service** : même chemin que le retour OIDC (`/auth/callback`), distingué
  par la méthode HTTP (`GET` OIDC, `POST` SAML liaison HTTP-POST). Pas de nouvelle route à
  déclarer côté Nginx/reverse proxy.
- **Hors périmètre initial** : Single Logout SAML (la déconnexion reste locale au portail, comme
  pour OIDC sans `SESAME_OIDC_LOGOUT`) ; signature de l'`AuthnRequest` par le SP (beaucoup d'IdP,
  dont Entra ID par défaut, ne l'exigent pas) ; IdP-initiated SSO.

## Conséquences

- **Nouvelle dépendance système** : `samael` (feature `xmlsec`) lie dynamiquement
  `libxmlsec1`/`libxml2`/`libssl`/`libxslt`, absents de l'image distroless du portail. Le portail
  utilise désormais une base `debian:bookworm-slim` minimale (`deploy/docker/rust.Dockerfile`,
  étage `runtime-portal`) ; le proxy (aucune dépendance SAML) garde `distroless/cc`
  (`runtime-proxy`). Côté admin, `xmlsec`/`lxml` (dépendances de `python3-saml`) fournissent des
  roues manylinux avec ces bibliothèques liées statiquement : aucun changement de
  `admin/Dockerfile`.
- Testé (Rust, `crates/sesame-portal/src/saml.rs`) : signature valide acceptée et attributs
  mappés ; rejet d'une signature d'une clé non fiable, d'une audience différente, d'un rejeu avec
  un autre identifiant de requête, d'une assertion altérée, d'une clé utilisateur dangereuse.
  Même couverture côté admin (Python, `admin/tests/test_saml_auth.py`), assertions signées
  construites et signées avec les outils de `python3-saml` lui-même (pas de service SAML réel).
- Pas d'e2e SAML en dev/CI (décision de l'exploitant) : aucun service Docker Compose de type IdP
  SAML n'est ajouté ; `make e2e` reste sur le fournisseur OIDC local (Keycloak).
- `spec.access` (habilitations, ADR 0017) fonctionne à l'identique : les groupes viennent de
  `SESAME_SAML_GROUPS_ATTRIBUTE` au lieu du claim OIDC, sans changement du modèle d'habilitation
  ni du registre des comptes.
