# 0002. PostgreSQL comme magasin de sessions

**Statut** : acceptée (2026-09-27)

## Contexte

Il faut associer chaque session portail à ses sessions applicatives, avec expiration, invalidation à la déconnexion et purge. Redis avait été envisagé.

## Décision

PostgreSQL, derrière l'interface `SessionStore`.

## Conséquences

- Pas de TTL natif : colonnes `expires_at`, purge périodique, contrôle de l'expiration à chaque lecture.
- `ON DELETE CASCADE` rend l'invalidation à la déconnexion simple et atomique.
- Une seule base pour les sessions et, à terme, pour les données d'admin et l'audit.
- Jetons portail stockés hachés, cookies applicatifs chiffrés au repos.
- Une implémentation en mémoire sert aux tests. D'autres (Redis…) restent possibles grâce à l'interface.
