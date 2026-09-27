# 0003. Credentials par utilisateur

**Statut** : acceptée (2026-09-27)

## Contexte

Les identifiants applicatifs pourraient être partagés par appli ou propres à chaque utilisateur. L'environnement est soumis à PCI-DSS.

## Décision

Un compte applicatif par couple (appli, utilisateur) : `credentials.mode: per_user`.

## Conséquences

- Traçabilité de bout en bout : les journaux de l'appli désignent la bonne personne.
- Chemin dans le coffre : `sesame/apps/<app_id>/users/<user_key>`.
- `user_key` doit être stable : `sub`, ou `oid` pour Entra ID.
- Provisionnement de comptes plus lourd, à outiller dans l'UI d'admin.
- Le schéma garde un `enum` pour `mode` : un mode partagé pourra être ajouté si un cas le justifie.
