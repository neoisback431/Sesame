# 0025. Publication des images Docker sur GitHub (Releases + GHCR)

**Statut** : acceptée (2026-09-28), implémentée.

## Contexte

`.gitlab-ci.yml` vérifie déjà que les 4 images (portail, proxy, admin, recorder) buildent
(`build:images`), mais n'en publie aucune. Le dépôt public étant sur GitHub, l'exploitant a
demandé comment publier une release avec les images Docker associées.

## Décision

- **4 images publiées séparément**, pas d'image combinée : `sesame-portal`, `sesame-proxy`,
  `sesame-admin`, `sesame-recorder`. Reflète des frontières de sécurité et de déploiement déjà
  actées ailleurs, pas un choix nouveau :
  - portail et proxy sont deux processus avec des droits différents (seul le proxy lit le
    coffre de secrets) ; les regrouper romprait cette séparation ;
  - le recorder tourne sans allowlist anti-SSRF (ADR 0016), isolé dans son propre conteneur,
    jamais exposé via Nginx ;
  - poids et cycles de vie très différents (Rust compilé minimal vs Python + Chromium pour le
    recorder).
  Portail et proxy partagent le même `Dockerfile` (étages `runtime-portal` / `runtime-proxy`,
  ADR 0024) mais restent deux images et deux conteneurs distincts.
- **Registre** : GitHub Container Registry (`ghcr.io`), lié au dépôt, authentification par le
  `GITHUB_TOKEN` fourni automatiquement (aucun secret à gérer).
- **Déclencheur** : tag Git manuel (`git tag vX.Y.Z && git push origin vX.Y.Z`), pas de
  publication automatique à chaque merge. Contrôle explicite de ce qui devient une release,
  cohérent avec l'absence de publication automatique ailleurs dans le projet.
- **Logique dans le Makefile** (`make release-images VERSION=vX.Y.Z [REGISTRY=…]`), fichier CI
  mince (`.github/workflows/release.yml`), même principe que `.gitlab-ci.yml`. `REGISTRY` est
  calculé dans le workflow à partir du propriétaire du dépôt (minuscules, exigé par `ghcr.io`) :
  une organisation qui forke le projet publie ses propres images sans modifier le Makefile.
- Le workflow construit les 4 images, les pousse (tag de version + `latest`), puis crée la
  Release GitHub correspondante (`gh release create --generate-notes`).

## Conséquences

- Coexiste avec `.gitlab-ci.yml` sans conflit : celui-ci continue à seulement vérifier que les
  images buildent (`build:images`), sans les publier.
- Pas de test possible en environnement sans démon Docker (ni ici, ni dans `.gitlab-ci.yml`
  d'ailleurs, qui utilise `docker:27-dind`) : validé par relecture et `make -n release-images`
  (affichage des commandes sans les exécuter).
- Aucun secret nouveau à gérer : `GITHUB_TOKEN` est fourni par GitHub Actions à chaque run, avec
  les permissions `contents: write` (Release) et `packages: write` (GHCR) déclarées dans le
  workflow.
