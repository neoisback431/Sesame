# 0032. Import des utilisateurs avant leur première connexion

**Statut** : acceptée (2026-11-02), implémentée.

## Contexte

Pour enregistrer le compte applicatif d'une personne, l'administrateur doit saisir sa clé
Sesame (l'`oid` d'Entra ID). Or Sesame ne la connaissait qu'après une première connexion au
portail (ADR 0031) : il fallait demander à chaque nouvelle personne de se connecter avant de
l'embarquer. L'exploitant veut pouvoir préparer les comptes **sans action de leur part**, à
partir des membres des groupes SSO.

## Décision

- **Import manuel** (choix de l'exploitant) : une page `Utilisateurs → Importer des
  utilisateurs` reçoit une liste collée, une personne par ligne, `clé[,nom[,e-mail]]`
  (virgule, point-virgule ou tabulation : export CSV de l'annuaire). Lignes vides, commentaires
  `#` et en-tête ignorés ; 5000 lignes et 512 Kio au plus.
- **Pas de synchronisation automatique** : OIDC ne permet pas de lister les membres d'un groupe,
  et la règle d'indépendance interdit une API propriétaire (Microsoft Graph) dans le cœur. Un
  module optionnel `DirectoryProvider` (Graph, SCIM, LDAP) reste possible plus tard, derrière
  la même méthode d'écriture (`AccountStore.import_user_profiles`) ; il n'est pas livré.
- **Utilisateurs seulement** : l'import complète la table `users` (clé, nom, e-mail). Il ne crée
  **aucun compte applicatif** ni secret : l'administrateur enregistre ensuite le compte comme
  aujourd'hui, la personne étant désormais proposée dans la liste et trouvable par nom.
- **La clé doit être exactement la valeur du claim `SESAME_OIDC_USER_KEY_CLAIM`** (Entra ID :
  l'*Object Id*, pas l'e-mail). La page l'affiche avec le nom du claim configuré.
- **Un champ absent ne remplace jamais une valeur connue** (même règle que le portail). À la
  première connexion, le nom et l'e-mail de l'annuaire remplacent ceux saisis.
- **`users.last_login_at` devient facultatif** (migration `0009`) : `NULL` = jamais connecté. Le
  portail l'écrit explicitement.
- **La page « Utilisateurs » liste aussi les personnes sans compte** (connectées ou importées),
  avec la mention « aucun compte ».
- **Audit** `users_imported` (acteur, `created=…;updated=…;rejected=…`), y compris en échec
  (liste vide de lignes valides, trop volumineuse, base injoignable). Aucun nom ni e-mail dans
  l'audit.

## Conséquences

- L'administration a besoin de `INSERT` / `UPDATE` sur `users` (même rôle PostgreSQL que
  maintenant ; la séparation des rôles recommandée par l'ADR 0021 devra l'inclure).
- Donnée personnelle saisie par un administrateur (nom, e-mail) : même nature que l'ADR 0031.
- Une clé mal saisie (e-mail au lieu de l'`oid`) crée une entrée orpheline sans effet sur les
  accès : la personne se connecte avec sa vraie clé et n'est pas rattachée. Le texte de la page
  le rappelle.

## Alternatives écartées

- **Microsoft Graph** : lecture directe des groupes, mais module propriétaire, application Entra
  supplémentaire à gérer et permission large (`GroupMember.Read.All`). Écarté par l'exploitant.
- **Création automatique de comptes `pending`** pour les groupes de `spec.access` : plus
  invasif, à valider côté sécurité ; non retenu.
