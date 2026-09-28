# 0026. Docker Compose : Sesame seul par défaut, Keycloak facultatif

**Statut** : acceptée (2026-09-28), implémentée.

## Contexte

`docker compose up` (et `pull`) lançait tout l'environnement de démo, y compris un
Keycloak de dev qui ne fait pas partie de Sesame. Pour un exploitant qui a déjà son
fournisseur d'identité, ce service est inutile et trompeur. L'exploitant a demandé que le
lancement par défaut se limite à Sesame, la version autonome restant disponible mais
facultative.

## Décision

- **Par défaut** : les services Sesame (portail, proxy, admin, recorder) **plus PostgreSQL
  et Nginx** (Sesame ne démarre pas sans base ; le frontal TLS sert l'exemple de routage par
  nom d'hôte).
- **Keycloak en commentaire** dans `docker-compose.yml` (choix de l'exploitant, plutôt
  qu'un profil Compose ou un fichier séparé) : service et ligne `keycloak:` du `depends_on`
  du portail, à décommenter pour la version autonome.
- **Fournisseur d'identité par `.env`** : les variables OIDC du portail et de l'admin sont
  interpolées (`${SESAME_OIDC_ISSUER:-…}`), avec pour défaut les valeurs du Keycloak de dev ;
  `.env.example` documente les valeurs à fournir. Brancher son IdP ne demande aucune
  modification du compose.
- L'appli factice reste dans le profil `demo` ; `make up-demo` (et donc `make e2e`) exige le
  Keycloak de dev et s'arrête avec un message explicite s'il est encore commenté.

## Conséquences

- Nginx démarre sans Keycloak (cibles résolues à la volée) : `idp.sesame.localhost` répond
  502 tant qu'il est commenté.
- Sans `.env` ni Keycloak décommenté, le portail redémarre en boucle (discovery OIDC
  impossible) : comportement attendu, documenté dans `docs/dev.md`.
- Décommenter à la main est plus fragile qu'un profil (bloc à maintenir, oubli possible de
  la ligne `depends_on`) : contrepartie acceptée pour la lisibilité du fichier.
- Les images Sesame restent construites depuis les sources par ce compose ; `docker compose
  pull` ne tire que PostgreSQL et Nginx.
