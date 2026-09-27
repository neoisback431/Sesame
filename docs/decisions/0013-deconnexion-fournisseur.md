# 0013. Déconnexion chez le fournisseur d'identité, sans conserver l'ID token

**Statut** : acceptée (2026-09-27)

## Contexte

La déconnexion du portail détruit la session portail et toutes les sessions applicatives, mais la session SSO chez le fournisseur d'identité reste ouverte : un nouveau clic sur le portail reconnecte l'utilisateur sans mot de passe. `CLAUDE.md` prévoit une déconnexion chez le fournisseur, en option et désactivée par défaut.

La spécification OIDC RP-Initiated Logout recommande d'envoyer l'ID token (`id_token_hint`). Il faudrait alors le conserver pendant toute la session.

## Décision

- Option `SESAME_OIDC_LOGOUT`, désactivée par défaut.
- Après la destruction locale, redirection `303` vers l'`end_session_endpoint` de la discovery avec `client_id` et `post_logout_redirect_uri` (`/auth/logged-out`).
- **Pas d'`id_token_hint`** : Sesame ne conserve aucun jeton du fournisseur au-delà de la connexion.
- Si la discovery n'expose pas d'`end_session_endpoint`, ou l'expose avec un autre schéma que l'émetteur, Sesame se replie sur la déconnexion locale et avertit au démarrage.

## Conséquences

- Aucun jeton du fournisseur à protéger dans le magasin de sessions.
- Certains fournisseurs demandent une confirmation sans `id_token_hint`. C'est le cas de Keycloak (« Do you want to log out? »). Entra ID accepte `post_logout_redirect_uri` et peut proposer de choisir le compte.
- L'URL `<SESAME_PUBLIC_URL>/auth/logged-out` doit être déclarée chez le fournisseur comme URL de retour après déconnexion.
- Activée dans l'environnement de dev et couverte par les tests bout en bout.
