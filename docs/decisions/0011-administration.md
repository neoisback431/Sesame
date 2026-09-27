# 0011. UI d'administration : descripteurs en Git, FastAPI

**Statut** : acceptée (2026-09-27)

## Contexte

L'UI d'administration ([0004](0004-ui-web-administration.md)) doit gérer le registre des comptes et les identifiants applicatifs. Deux questions restaient ouvertes : où vivent les descripteurs, et avec quel framework Python construire l'UI.

## Décision

- **Descripteurs** : ils restent des fichiers YAML versionnés dans Git, modifiés par merge request et relus par un humain. L'UI les affiche en lecture seule. Le portail et le proxy continuent de les lire au démarrage.
- **Framework** : FastAPI avec des pages Jinja2 rendues côté serveur. Pas de SPA.
- **Périmètre de la v1** : lister les applis et leurs comptes. Pour chaque compte : l'enregistrer (identifiants écrits dans le coffre, puis entrée active dans le registre), le désactiver, le réactiver ou le supprimer.
- **Coffre** : AppRole dédié avec une policy d'**écriture sans lecture** (`create`/`update` sur `data/`, `delete` sur `metadata/`).
- **Sécurité** : OIDC (code + PKCE), groupe d'administrateurs obligatoire, jeton CSRF sur chaque action, session d'une heure régénérée à la connexion. Chaque action est tracée dans l'audit, au même format que les services Rust.

## Conséquences

- Les modifications de descripteurs gardent l'historique et la relecture de Git. Pas de rechargement à chaud à outiller.
- Pour ajouter une appli, il faut une merge request puis redémarrer le portail et le proxy.
- Le schéma de la base appartient aux migrations Rust. L'UI d'admin l'utilise sans le migrer.
- Python ne permet pas d'effacer une chaîne de la mémoire de façon fiable. Les identifiants saisis ne sont jamais journalisés, audités ni réaffichés, mais ils restent en mémoire jusqu'au passage du ramasse-miettes.
