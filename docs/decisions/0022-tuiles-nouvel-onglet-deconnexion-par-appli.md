# 0022. « Mes applications » : nouvel onglet, déconnexion par appli, tuile grisée sans compte

**Statut** : acceptée (2026-09-28), implémentée. Remplace en partie [ADR 0009](0009-parcours-utilisateur.md) : une appli sans compte n'est plus masquée, mais affichée grisée.

## Contexte

L'exploitant a demandé trois évolutions de la page « Mes applications » :

1. Ouvrir une appli dans un nouvel onglet plutôt que de remplacer le portail, pour
   garder « Mes applications » à portée de main pendant qu'on travaille dans l'appli.
2. Un bouton par tuile pour forcer la déconnexion de cette seule appli, sans attendre
   l'expiration ni se déconnecter du portail entier.
3. Afficher, grisées, les applis pour lesquelles l'utilisateur est habilité mais n'a pas
   de compte, plutôt que de les masquer entièrement.

## Décision

- **Nouvel onglet** : chaque tuile active porte `target="_blank" rel="noopener noreferrer"`.
  N'affecte pas le lien « Administration » ni le formulaire de déconnexion du portail.
- **Déconnexion par appli** : nouvelle route du portail, `POST /apps/<id>/disconnect`.
  Supprime uniquement la session applicative stockée
  (`SessionStore::delete_app_session`), sans appeler l'appli elle-même (contrairement au
  chemin de déconnexion applicatif détecté par le proxy, `spec.logout.paths`, qui reste
  inchangé). Le prochain accès à l'appli redéclenche un rejeu, comme pour une session
  expirée — c'est le même mécanisme, pas un chemin de code séparé. Audité
  (`app_logout`, `reason: manual_from_portal`), la session **portail** n'est pas touchée.
- **Tuile grisée sans compte** (`TileState::NoAccount` dans `catalog.rs`) : un descripteur
  pour lequel `spec.access` habilite l'utilisateur (ou est absent, donc ouvert à tous),
  mais sans compte dans le registre, est maintenant affiché — non cliquable, sans bouton
  de déconnexion, avec le message « Vous n'avez pas de compte sur cette application. ».
  Un compte `disabled` reste masqué (action explicite d'un administrateur, inchangé).

## Conséquences

- **Le principe « le portail n'accède jamais au coffre » tient toujours** : la tuile
  grisée est déduite du seul descripteur et du registre des comptes, comme avant.
- **Nouvelle divulgation d'information** : un utilisateur habilité voit désormais
  l'existence d'applis auxquelles il n'a pas encore de compte (nom, description).
  Accepté : c'est déjà le périmètre de `spec.access` (groupes / utilisateurs autorisés à
  *demander* un compte), pas un mécanisme de confidentialité de l'existence des applis.
  Sans `spec.access` défini (accès ouvert à tout titulaire de compte, ADR 0017), toute
  personne connectée au portail verra la tuile grisée : cohérent avec le choix de
  l'exploitant de ne pas restreindre par groupe dans ce cas.
- La déconnexion par appli ne touche ni le mot de passe (jamais remis), ni les cookies
  du navigateur en mode proxy (ils ne les détient pas) ; en mode handoff, un cookie ou
  une valeur de stockage local déjà remis au navigateur n'est pas révoqué à distance,
  seule la relation applicative connue du portail est supprimée — limite déjà actée pour
  le mode handoff (ADR 0020).
- Tests : `catalog::tests` (rendu des trois états, nouvel onglet, formulaire de
  déconnexion) ; e2e (`test_disconnect_button_removes_only_that_apps_session`,
  ouverture en nouvel onglet via `open_tile`, tuile grisée pour un compte absent).
