# 0006. Licence Apache-2.0

**Statut** : acceptée (2026-09-27)

## Décision

Apache-2.0, préférée à MIT.

## Conséquences

- Licence explicite sur les brevets des contributeurs, avec clause de rétorsion, un point souvent exigé en entreprise.
- En-tête `SPDX-License-Identifier: Apache-2.0` dans chaque fichier source, et fichier `NOTICE`.
- Dépendances limitées aux licences compatibles (MIT, BSD, Apache-2.0, ISC, MPL-2.0…), vérifiées par `cargo deny`.
