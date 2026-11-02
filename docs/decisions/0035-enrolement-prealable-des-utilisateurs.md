# 0035. Enrôlement préalable des utilisateurs par leur clé SSO

**Statut** : acceptée (2026-11-02), implémentée.

## Contexte

Pour provisionner un compte, l'administrateur devait connaître la clé d'identité exacte de
l'utilisateur, et la page Utilisateurs n'affichait que les titulaires d'un compte : aucun point
d'entrée pour « préparer » quelqu'un. Il fallait en pratique lui demander de se connecter une
première fois pour que le portail le mémorise.

## Décision

- **Page Utilisateurs → « Enrôler un utilisateur »** (`POST /users`) : clé d'identité SSO
  (exactement la valeur du claim configuré), nom et e-mail facultatifs. Écrit une ligne dans la
  table `users` (ADR 0031, aucune migration) via `AccountStore.register_user` ; un nom ou un
  e-mail absent n'efface jamais une valeur connue.
- **Aucun droit n'est accordé** : l'enrôlement rend seulement l'utilisateur connu (liste,
  suggestions de provisionnement, nom affiché). Les comptes applicatifs se créent ensuite appli
  par appli (boutons « Ajouter un compte » de la page de l'utilisateur, formulaire de
  provisionnement existant, identifiants dans le coffre) : à sa première connexion, l'utilisateur
  retrouve ses applications sans autre démarche.
- La liste des utilisateurs et la recherche réunissent désormais titulaires d'un compte et
  utilisateurs connus (connectés ou enrôlés) sans compte.
- Le nom / l'e-mail saisis sont remplacés par ceux du fournisseur d'identité à la première
  connexion (ADR 0031).
- **Audit** : `user_enrolled` (acteur, `target_user`), y compris en cas d'échec.

## Conséquence

Une clé saisie de travers crée un profil orphelin et, si des comptes lui sont attachés, des
comptes rattachés à personne : la page indique de reprendre la valeur exacte du claim.
