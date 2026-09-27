# 0007. OpenBao en dev

**Statut** : acceptée (2026-09-27)

## Contexte

HashiCorp Vault est distribué sous BSL depuis 2023. OpenBao en est le fork open source (MPL-2.0), avec une API compatible.

## Décision

OpenBao dans l'environnement de dev. Le client Rust vise l'API commune (KV v2, AppRole) et reste compatible avec Vault.

## Conséquences

- Aucune dépendance de dev à un logiciel non open source.
- Les tests d'intégration ciblent OpenBao. Toute divergence d'API avec Vault est traitée dans le module d'implémentation.
