# 0004. UI web d'administration dès le départ

**Statut** : acceptée (2026-09-27)

## Décision

Une interface web (Python) pour gérer les applis, les descripteurs, les habilitations et les comptes associés.

## Conséquences

- Authentification par le même fournisseur d'identité, accès réservé à un groupe d'administrateurs.
- Chaque action d'administration est tracée dans l'audit.
- Policy d'**écriture sans lecture** sur le coffre : on peut définir un mot de passe sans pouvoir le relire.
- Les descripteurs restent exportables en YAML versionné, pour la revue et la reproductibilité.
