# 0016 — Recorder appelé depuis l'administration

Date : 2026-09-27
Statut : accepté

## Contexte

Le recorder (ADR 0015) analyse une page de login et propose un descripteur. Il
n'existait qu'en ligne de commande (`sesame-onboard record`, `make record`).
L'administrateur devait donc quitter la console, lancer une commande, puis coller
le résultat dans l'éditeur. On veut le déclencher directement depuis l'admin, avec
un bouton « Analyser une page de login » qui pré-remplit l'éditeur.

## Décision

- Le recorder devient un **service HTTP interne** (`sesame-recorder`, `POST /record`),
  jamais exposé via Nginx. L'entrée en ligne de commande (`make record`) est conservée
  en remplaçant l'entrypoint de la même image.
- L'admin l'appelle avec un **jeton partagé** (`SESAME_RECORDER_TOKEN`, en-tête
  `Authorization: Bearer`). Le service refuse toute requête sans jeton valide, ce qui
  empêche un autre service du réseau interne de l'utiliser.
- La fonctionnalité est **activée uniquement si `SESAME_RECORDER_URL` et
  `SESAME_RECORDER_TOKEN` sont tous deux fournis** à l'admin ; sinon le bouton
  n'apparaît pas et `POST /apps/analyze` répond 404.
- Chaque analyse est **auditée** (`descriptor_recorded`, succès ou échec), avec le
  seul **hôte** de l'URL cible, jamais l'URL complète.
- Le service et l'admin n'échangent **aucun identifiant applicatif** : le recorder
  n'envoie qu'une valeur factice pour observer la soumission (ADR 0015), et ne renvoie
  que le descripteur proposé et des notes à relire.

## Pas d'allowlist anti-SSRF (choix de l'exploitant)

Le recorder ouvre l'URL fournie dans un navigateur : c'est un vecteur SSRF. Nous
n'imposons **aucune allowlist**, à la demande de l'exploitant, parce que les applis à
embarquer sont sur des hôtes internes qu'une règle « pas d'IP privée » bloquerait.

Garde-fous retenus à la place :

- service interne, jamais exposé via Nginx ;
- jeton partagé obligatoire ;
- déclencheur réservé aux membres du groupe d'administrateurs (l'admin est déjà
  derrière OIDC + ce groupe) ;
- audit de chaque analyse.

Risque résiduel assumé : un administrateur (ou une session admin compromise) peut
faire pointer le recorder vers une URL interne, y compris les métadonnées cloud
(`169.254.169.254`). Amélioration possible et non retenue pour l'instant : bloquer les
seules adresses de métadonnées cloud, sans gêner l'analyse d'applis internes.

## Conséquences

- Nouveau service `recorder` dans le compose (image Playwright), variables
  `SESAME_RECORDER_*` documentées dans `docs/configuration.md`.
- L'image du recorder embarque un navigateur : elle est plus lourde et n'est pas
  requise si l'on n'utilise pas l'analyse (l'admin fonctionne sans).
- Le recorder est mono-thread (un navigateur réutilisé) : les analyses sont traitées
  en série, ce qui convient à un usage ponctuel.
