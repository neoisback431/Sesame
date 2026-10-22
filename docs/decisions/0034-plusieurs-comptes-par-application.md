# 0034. Plusieurs comptes par utilisateur et par application

**Statut** : acceptée (2026-10-22), implémentée. Remplace en partie l'[ADR 0010](0010-registre-des-comptes.md) (un compte par couple appli / utilisateur) et précise l'[ADR 0029](0029-demandes-d-acces.md) (demandes d'accès).

## Contexte

Le modèle des credentials prévoyait **un compte par couple (appli, utilisateur)**. Or certains
utilisateurs, notamment les administrateurs, ont plusieurs comptes sur une même appli : un compte
« normal » et un compte d'administration, ou un compte de support. Jusqu'ici, ils ne pouvaient en
utiliser qu'un par Sesame ; pour l'autre, il leur restait la connexion manuelle (ADR 0033), ce qui
suppose de connaître le mot de passe applicatif et contredit l'objectif du portail.

Pistes envisagées :

1. **Sélecteur sur la tuile** : un compte actif par appli, changé depuis « Mes applications ».
2. **Un sous-domaine par compte** (`admin--appli.domaine`) : plusieurs comptes ouverts en même
   temps, mais DNS et certificat wildcard de deuxième niveau, règle Nginx, réécriture d'URL et
   `X-Forwarded-Host` propres à chaque compte.
3. **Dupliquer le descripteur** : rien à coder, mais deux descripteurs à maintenir et deux tuiles
   sans lien.

## Décision

Piste 1 (décision de l'exploitant), avec le modèle de données prêt pour la piste 2 plus tard.

- **Identité d'un compte** : `(app_id, user_key, account_id)`. `account_id` est un identifiant
  court (`[a-z0-9-]`, 32 caractères au plus), dérivé du **libellé libre** saisi par
  l'administrateur (« Admin prod » → `admin-prod`). Sans libellé, il s'agit du compte `default`.
  Les comptes existants deviennent le compte `default` (migration `0010`).
- **Compte par défaut** : un seul par couple (`is_default`, index unique partiel). Le premier
  compte créé l'est ; l'administrateur peut en désigner un autre. Il ne se supprime qu'en dernier.
- **Choix de l'utilisateur** : table `app_account_selections` (appli, utilisateur → compte),
  **par utilisateur**, donc valable dans toutes ses sessions portail et d'une connexion à l'autre
  (choix par défaut retenu ; l'alternative « par session portail » remettait le compte par défaut
  à chaque connexion). Supprimée avec le compte choisi (clé étrangère).
- **Compte effectif** (`effective_account`, `ports.rs`) : le compte choisi, sinon le compte par
  défaut, sinon le premier compte, en écartant d'abord les comptes désactivés. Un compte désactivé
  n'est retenu que s'il n'y a rien d'autre, pour que le refus soit tracé.
- **Portail** : la tuile garde l'état du compte effectif. Avec au moins deux comptes actifs ou en
  échec, elle porte un sélecteur (`POST /apps/<id>/account`) qui vérifie le compte, mémorise le
  choix, détruit les sessions applicatives de l'utilisateur sur l'appli (toutes ses sessions
  portail), lève une éventuelle suspension (ADR 0033) et produit l'audit `account_selected`. Un seul
  compte à la fois par appli, tous onglets confondus.
- **Proxy** : rejeu avec le compte effectif. La session applicative mémorise son compte
  (`app_sessions.account_id`). En **mode handoff**, le marqueur `__sesame_handoff` porte le compte
  remis : à la navigation suivante, s'il diffère du compte effectif, la remise est refaite avec le
  bon compte (un marqueur d'avant, valeur `1`, vaut `default`). Le mode proxy n'ajoute aucune requête
  par appel : c'est le portail qui détruit les sessions au changement de compte.
- **Coffres** :
  - PostgreSQL : `app_secrets.account_id`. Le compte `default` garde la donnée authentifiée d'avant
    (`appli|utilisateur|champ`), sans rechiffrement ; les autres comptes utilisent
    `appli|utilisateur#compte|champ` (`#` et `|` sont interdits dans une clé utilisateur, les deux
    formes ne peuvent pas coïncider). Même règle côté Rust (`secrets.rs`) et Python (`crypto.py`).
  - OpenBao / Vault : `…/users/<user_key>` pour `default` (chemin inchangé),
    `…/users/<user_key>/accounts/<account_id>` pour les autres (les policies `sesame/apps/*` le
    couvrent déjà).
- **Diagnostics, état, révocation** : par compte (`replay_diagnostics` clé `(app, user, compte)`) ;
  désactiver un compte ne révoque que ses sessions ; « Tout désactiver » couvre tous les comptes.
- **Audit** : champ `account_id` dans les événements (Rust et Python, même format JSON) ;
  nouveaux événements `account_selected` (portail) et `account_default_changed` (admin).
- **Demandes d'accès (ADR 0029)** : toujours sur le compte `default` (choix par défaut retenu). Un
  couple qui a déjà un compte, quel qu'il soit, n'en dépose pas ; les comptes supplémentaires sont
  créés par un administrateur.
- **Notifications (ADR 0030)** : inchangées, par (événement, appli, utilisateur) ; le compte en
  échec figure dans l'audit et l'administration.

## Conséquences

- Aucun secret supplémentaire n'atteint le navigateur : le libellé et l'identifiant de compte ne
  sont pas des secrets. Les principes 1 à 4 restent tenus ; le changement de compte est audité.
- Compatibilité : migration `0010` sans perte, comptes et secrets existants inchangés (même AAD,
  même chemin OpenBao), anciens marqueurs handoff reconnus.
- Limite assumée : deux comptes d'une même appli ne peuvent pas être ouverts en même temps par le
  même utilisateur (même hôte, mêmes cookies). La piste 2 (un sous-domaine par compte) pourra
  s'ajouter sans changer ce modèle.
- Contrat des interfaces étendu (`AccountKey`, `select_account`, `selected_account(s)`,
  `effective_account`, `delete_user_app_sessions`), couvert par les tests de contrat (mémoire et
  PostgreSQL, Rust et Python) ; tests du proxy dans `crates/sesame-proxy/tests/accounts.rs`.
