# 0012. Embarquement : outil en ligne de commande, vérification sans JavaScript

**Statut** : acceptée (2026-09-27)

## Contexte

Le module d'embarquement doit aider à écrire le descripteur d'une appli, le valider, puis détecter un changement du formulaire de login. Le moteur de proxy rejoue le login à partir du HTML brut, sans exécuter de JavaScript.

## Décision

- Un outil en ligne de commande, `sesame-onboard`, cohérent avec les descripteurs en fichiers Git ([0011](0011-administration.md)) : il lit et contrôle des fichiers, et un humain les fusionne par merge request.
- `verify` rejoue le login d'après le descripteur avec un compte de test, avec les règles du proxy : HTML brut, champs cachés, CSRF, conditions de succès et d'échec, cookie de session.
- L'empreinte porte sur la **structure** du formulaire dans le HTML brut (action, méthode, balise, type et nom des champs), jamais sur les valeurs.
- `health` compare l'empreinte sans identifiants. Il peut donc tourner partout (cron, CI) sans accès au coffre, et produit une ligne JSON par appli (`"log_type":"health"`) ainsi qu'un code de sortie.
- Playwright reste une dépendance optionnelle, réservée à une future capture automatique ; `verify` et `health` n'en ont pas besoin.

## Conséquences

- Un formulaire construit en JavaScript est détecté dès `verify` (`login_form_not_found_in_raw_html`) : le proxy ne saurait pas le rejouer.
- Les règles de rejeu existent en deux exemplaires, Rust (proxy) et Python (`verify`). Toute évolution de la sémantique des descripteurs doit être reportée des deux côtés.
- Après un changement légitime du formulaire, relancer `verify` puis mettre à jour l'empreinte (`fingerprint`) et `metadata.revision`.
- Le descripteur s'écrit encore à la main à partir du gabarit. La capture automatique d'un login réel n'est pas implémentée.
