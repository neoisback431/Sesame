# 0014. Applis en base, créées dans l'administration

**Statut** : acceptée (2026-09-27). Remplace en partie [0011](0011-administration.md) (emplacement des descripteurs).

## Contexte

L'[ADR 0011](0011-administration.md) gardait les descripteurs en fichiers Git, en lecture seule dans l'UI : ajouter une appli demandait une merge request puis le redémarrage du portail, du proxy et de l'administration. Pour les équipes qui exploitent Sesame sans accès au dépôt, ce circuit est trop lourd. L'utilisateur a décidé que les applis pourraient aussi être créées dans l'administration.

## Décision

- **Deux sources** : les fichiers Git restent possibles (lecture seule, chargés au démarrage, un fichier invalide empêche le démarrage). Les descripteurs créés dans l'administration vivent en base (`app_descriptors`, document JSON conforme au schéma), avec un historique en ajout seul (`app_descriptor_history`).
- **Fusion** (`sesame_core::sources`, reproduite côté Python) : fichiers d'abord, puis base dans l'ordre des identifiants. Un descripteur en base invalide, ou dont l'`id` ou l'hôte public est déjà pris, est écarté et journalisé sans arrêter le service.
- **Rechargement à chaud** : portail et proxy vérifient toutes les `SESAME_DESCRIPTORS_RELOAD` (10 s) la version du catalogue (dernier identifiant de l'historique) et ne rechargent que si elle a changé. L'administration relit la base à chaque page.
- **Édition** : formulaire guidé qui produit un premier jet, puis éditeur YAML. Le document est validé contre le schéma et les contrôles de `AppDescriptor::validate`, reproduits en Python, avant tout enregistrement. Les regex sont limitées à la syntaxe commune aux deux moteurs (pas de références arrière ni d'assertions de voisinage).
- **Concurrence** : chaque écriture indique la révision qu'elle remplace ; une révision périmée est refusée. `metadata.revision` est tenue par Sesame. Un index unique (migration 0003) interdit deux descripteurs en base sur le même hôte public.
- **Suppression** : refusée tant que l'appli a des comptes, pour ne pas laisser d'identifiants orphelins dans le coffre.
- **Audit** : `descriptor_created`, `descriptor_updated`, `descriptor_deleted`, en succès comme en échec.

## Conséquences

- Une appli se crée, se modifie et se retire sans redémarrage ni merge request. La relecture humaine de Git est remplacée, pour ces applis, par la validation de l'éditeur, l'historique des révisions et l'audit.
- Un administrateur peut désormais changer l'hôte public ou l'URL amont d'une appli. Le groupe d'administrateurs reste donc un groupe à privilèges élevés (voir le modèle de menace).
- La validation existe en Rust et en Python : toute évolution de `AppDescriptor::validate` se reporte dans `admin/src/sesame_admin/descriptors.py`.
- `sesame-onboard verify` et `fingerprint` s'utilisent sur une copie du YAML de l'éditeur ; `sesame-onboard health` ne couvre encore que les fichiers.
- Le schéma de la base appartient toujours aux migrations Rust.
