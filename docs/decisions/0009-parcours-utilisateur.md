# 0009. Parcours utilisateur : page « Mes applications » et rejeu à l'arrivée

**Statut** : acceptée (2026-09-27). Remplacée en partie par [0017](0017-habilitation-par-compte.md) : sans `spec.access`, le compte actif suffit.

## Contexte

L'utilisateur se connecte à Sesame en SSO, puis doit accéder aux applis pour lesquelles il a un compte. Deux questions se posent : comment il choisit l'appli, et à quel moment le login est rejoué.

## Décision

- Le portail affiche une page **« Mes applications »** : une tuile par appli pour laquelle l'utilisateur est habilité **et** possède un compte actif (voir [0010](0010-registre-des-comptes.md)).
- Une tuile pointe vers l'adresse de l'appli **exposée par Sesame**, jamais vers son adresse réelle.
- Le rejeu a lieu **à l'arrivée sur l'appli**, dans le proxy, avec le même mécanisme que pour une session expirée. Il n'y a pas de rejeu anticipé dans le portail.
- L'accès direct (favori, lien profond) reste possible.
- En cas d'échec du rejeu, une page d'erreur neutre renvoie vers le portail, et le compte passe à l'état `failed`.
- Un `POST` sur une session expirée donne lieu à un rejeu, puis à une redirection `303` vers la page d'origine. La soumission est perdue, ce qui évite toute double soumission.
- La déconnexion du portail détruit toutes les sessions applicatives. Fermer aussi la session chez le fournisseur d'identité est une option, désactivée par défaut.
- Aucun bandeau n'est injecté dans les pages des applis.

## Conséquences

- Un seul chemin de code pour le rejeu : première visite ou expiration.
- Le portail n'a besoin ni du coffre ni des applis : il lit les descripteurs et le registre des comptes.
- Une première visite coûte une à deux secondes de plus (le rejeu), sans étape visible pour l'utilisateur.
