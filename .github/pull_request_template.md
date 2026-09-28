## Objet

<!-- Ce que fait cette PR et pourquoi, en quelques phrases. -->

Issue liée : #

## Type de changement

- [ ] 🐛 Correction de bug
- [ ] ✨ Nouvelle fonctionnalité
- [ ] 🔒 Sécurité
- [ ] ♻️ Refactorisation (sans changement de comportement)
- [ ] 📚 Documentation
- [ ] 🧰 Outillage / CI / images

## Comment j'ai testé

<!-- Tests ajoutés, commandes lancées, parcours vérifié à la main (make up-demo…). -->

## Vérifications

- [ ] `make lint`, `make test` et `make deny` passent (`make test-full` si le recorder est touché)
- [ ] Aucun secret réel ni donnée propre à une organisation (hôtes, URLs, tenant, groupes, utilisateurs)
- [ ] Secrets, cookies et jetons jamais journalisés, sérialisés ni inclus dans une erreur ; test de non-fuite ajouté si la PR touche aux secrets
- [ ] Tout accès au coffre ou rejeu ajouté émet un événement d'audit, y compris en échec
- [ ] Documentation à jour (`docs/configuration.md` pour une nouvelle variable, schéma + `docs/descriptor.md` pour le descripteur, ADR pour une décision structurante)
- [ ] Évolution du rejeu reportée côté Rust (`crates/sesame-proxy`) **et** Python (`onboarding/`), le cas échéant
- [ ] En-tête `SPDX-License-Identifier: Apache-2.0` sur les nouveaux fichiers ; nouvelles dépendances sous licence compatible Apache-2.0
- [ ] J'accepte que ma contribution soit publiée sous licence Apache-2.0
