# 0005. Découplage des briques externes

**Statut** : acceptée (2026-09-27)

## Contexte

Le projet est destiné à être publié en open source et doit convenir à d'autres organisations que celle du déploiement de référence (Entra ID, Vault).

## Décision

Chaque brique externe passe derrière une interface, avec des implémentations choisies par configuration : fournisseur d'identité (OIDC générique), coffre (`SecretStore`), magasin de sessions (`SessionStore`), audit (`AuditSink`), observabilité (OpenTelemetry).

## Conséquences

- Aucun SDK ni type propre à un fournisseur hors de son module d'implémentation.
- Habilitations fondées sur des claims génériques, pas d'API propriétaire (Microsoft Graph…) dans le cœur.
- Une même suite de tests de contrat pour toutes les implémentations d'une interface.
- Aucune donnée propre à une organisation dans le dépôt.
