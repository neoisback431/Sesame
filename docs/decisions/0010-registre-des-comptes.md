# 0010. Registre des comptes dans PostgreSQL

**Statut** : acceptée (2026-09-27)

## Contexte

Pour afficher « Mes applications », le portail doit savoir pour quels couples (appli, utilisateur) un compte applicatif existe. Il ne doit pas lire le coffre : seul le proxy y a accès, et chaque lecture est un événement d'audit.

## Décision

Une table `app_accounts` (appli, utilisateur, état `active` / `failed` / `disabled`, raison, dates) derrière l'interface `AccountRegistry`. Elle ne contient **aucun secret**.

- L'UI d'admin l'alimente, dans la même opération que l'écriture du secret dans le coffre.
- Le proxy la consulte avant toute lecture du coffre. Si le compte n'est pas `active`, il refuse sans lire le coffre. Après un rejeu, il la met à jour : `last_login_at` en cas de succès, état `failed` en cas d'échec.

## Conséquences

- Le portail reste sans accès au coffre.
- On évite les lectures de coffre et les rejeux inutiles, donc les risques de verrouillage de compte.
- Le registre et le coffre peuvent diverger. Un secret introuvable fait passer le compte à `failed`, ce qui le rend visible aux administrateurs.
- Chaque changement d'état est tracé (`account_status_changed`).
