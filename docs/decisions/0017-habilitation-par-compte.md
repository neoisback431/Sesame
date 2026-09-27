# 0017. Le compte suffit : `spec.access` facultatif

**Statut** : acceptée (2026-09-28). Remplace en partie [0009](0009-parcours-utilisateur.md) (habilitation exigée en plus du compte).

## Contexte

Le portail n'affichait une appli, et le proxy n'autorisait l'accès, que si l'utilisateur
était à la fois **habilité** (`spec.access` : un groupe issu du claim OIDC `groups`, ou sa
clé dans `users`) **et** titulaire d'un **compte actif**. Le formulaire de création mettait
par défaut `spec.access.groups: ["<id>-users"]`.

Beaucoup de déploiements n'ont pas de gestion de groupes et leur fournisseur d'identité
n'émet pas de claim `groups`. Dans ce cas, provisionner un compte ne suffisait pas :
l'appli restait invisible, sans indication claire. L'exploitant attend le modèle simple
« je crée un compte pour l'utilisateur → il voit l'appli ».

## Décision

`spec.access` devient **facultatif**.

- **Absent ou vide** : tout utilisateur disposant d'un **compte actif** est autorisé. Le
  provisionnement d'un compte (réservé à l'admin, tracé) vaut autorisation.
- **Présent** : restriction **supplémentaire** — l'utilisateur doit en plus figurer dans
  `users` ou appartenir à l'un des `groups`.

Le compte actif reste dans tous les cas nécessaire (le portail et le proxy le vérifient).
Le formulaire guidé n'impose plus de groupe : laissé vide, il omet `access`.

## Conséquences

- Modèle par défaut aligné sur l'attente : compte = accès, sans groupes.
- Rétrocompatible : les descripteurs existants avec `access` gardent leur restriction.
- La défense en profondeur côté proxy demeure : `access.allows` (vrai si `access` vide),
  **puis** vérification du compte `active` avant toute lecture du coffre.
- Un compte erroné (mauvaise clé) donne accès à cet utilisateur-là uniquement ; le point
  de contrôle reste le provisionnement, réservé aux administrateurs et audité.
- Les applis créées avant ce changement gardent le groupe par défaut (`<id>-users`) : la
  page de l'appli dans l'admin signale toute restriction (« un compte ne suffit pas ») et
  propose « Ouvrir à tous les titulaires d'un compte », qui retire `spec.access` (nouvelle
  révision, audit `descriptor_updated`). Le message de provisionnement le rappelle aussi.
- Portée : schéma (`access` retiré des champs requis, plus d'`anyOf`), Rust
  (`Spec.access` défaut, `Access::allows` vrai si vide, contrôle retiré de `validate`),
  Python (`descriptors.py` : `access_open`, `app_from_doc`, formulaire guidé), portail et proxy
  inchangés dans leur logique (ils appellent `allows`).
