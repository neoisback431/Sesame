# 0001. Rust pour le back, Python pour le reste

**Statut** : acceptée (2026-09-27)

## Contexte

Le moteur de proxy est sur le chemin de chaque requête et manipule des secrets en mémoire. Le module d'embarquement pilote un navigateur headless.

## Décision

- **Rust** pour le portail d'authentification et le moteur de proxy.
- **Python** pour le module d'embarquement (Playwright), l'UI d'administration et l'outillage.

## Conséquences

- Rust apporte la sûreté mémoire, des performances prévisibles, un binaire unique et des types secrets effacés à la destruction (`secrecy`, `zeroize`).
- Playwright est de premier niveau en Python.
- Deux chaînes d'outillage à maintenir. Le contrat commun est le schéma JSON du descripteur, `schemas/app-descriptor.schema.json`.
