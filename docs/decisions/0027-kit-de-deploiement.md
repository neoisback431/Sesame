# 0027. Kit de déploiement release (`deploy/release/`)

**Statut** : acceptée (2026-09-28), implémentée.

## Contexte

Les images étaient publiées sur GHCR (ADR 0025), mais rien ne permettait de les lancer
simplement : le seul compose construisait les images depuis les sources avec la
configuration de dev (`sesame.localhost`, clés publiques), et les images de l'admin et du
recorder n'étaient pas autonomes (schéma des descripteurs monté depuis le dépôt).
L'exploitant veut un déploiement simple, sans « usine à gaz ».

## Décision

- **Kit autonome `deploy/release/`**, copiable tel quel : `docker-compose.yml` sur les
  images publiées (Sesame + PostgreSQL + Nginx, comme le défaut de l'ADR 0026, sans
  Keycloak), `.env.example`, `generate-keys.sh`, gabarit Nginx, dossier `certs/`.
- **Configuration réduite au minimum** : un domaine (`SESAME_DOMAIN`), dont découlent
  toutes les adresses (portail sur le domaine, administration sur `admin.<domaine>`, applis
  sur `<appli>.<domaine>`, domaine du cookie), l'IdP (émetteur + deux clients) et le groupe
  des administrateurs. Les clés et mots de passe sont générés par `generate-keys.sh`
  (relançable, ne remplace jamais une valeur existante). Les variables obligatoires sont
  vérifiées par Compose (`${VAR:?message}`).
- **Nginx configuré par gabarit** : mécanisme natif de l'image officielle
  (`/etc/nginx/templates`, `NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx`), limité aux variables
  `SESAME_*` pour ne pas toucher aux variables Nginx.
- **Images autonomes** : le schéma des descripteurs est intégré aux images de l'admin et du
  recorder (contexte de build à la racine du dépôt, `.dockerignore` associé).
- **Archive jointe à chaque Release GitHub** (`make release-kit`, version et registre figés),
  pour installer sans cloner le dépôt.
- Périmètre : OIDC. SAML reste possible en ajoutant ses variables (docs/configuration.md),
  sans être prévu dans le kit minimal.

## Conséquences

- Le README décrit l'installation en cinq étapes à partir de ce kit ; le compose racine reste
  celui du dev.
- Le kit exige des images publiées **après** cette décision (schéma intégré) : il ne
  fonctionne pas avec les images de la 0.1.0.
- Non testé ici faute de démon Docker (comme les autres fichiers Compose) : validé par lecture
  des fichiers, test du script de génération des clés et de l'archive.
