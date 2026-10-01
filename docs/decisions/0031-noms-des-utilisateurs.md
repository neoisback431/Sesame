# 0031. Noms des utilisateurs dans l'administration

**Statut** : acceptée (2026-10-01), implémentée.

## Contexte

L'administration identifiait chaque utilisateur par sa **clé Sesame** (le claim configuré,
`oid` avec Entra ID), par exemple `CmPymIROfTM_CDtsZjAmW95gHfJ_JOzAKoVY75UQ534` : illisible
pour un administrateur qui doit retrouver « Alice Martin ». Sesame ne conservait jamais le
nom, seulement la clé.

## Décision

- **Mémorisation à la connexion** : le portail enregistre le **nom** et l'**e-mail** déclarés
  par le fournisseur d'identité (table `users`, migration `0008`, une ligne par clé, mise à
  jour à chaque connexion). Trait `UserDirectory` (mémoire, PostgreSQL, test de contrat).
- **Nom tel que fourni** par le fournisseur d'identité : claim `name` (OIDC), à défaut
  `preferred_username` puis l'e-mail ; en SAML, l'attribut e-mail configuré. Pas de
  réorganisation « Nom Prénom » : le prénom et le nom ne sont pas séparés dans `name`.
- **Un champ absent ne remplace jamais une valeur connue** (un jeton sans `email` n'efface
  pas l'adresse déjà enregistrée).
- **Lecture par l'administration seulement** (`AccountStore.user_profiles`) : pages
  Utilisateurs, comptes d'un utilisateur, comptes d'une appli, demandes d'accès et
  notifications affichent le nom en premier et la clé en dessous ; la recherche porte sur le
  nom, l'e-mail et la clé ; les suggestions de provisionnement portent le nom en libellé.
- **Jamais bloquant** : un échec d'écriture (portail) ou de lecture (administration) est
  journalisé ou ignoré, la clé suffit à tout le reste.
- **Aucune autorisation n'en dépend** : habilitations, coffre, registre et audit restent sur
  la clé utilisateur. Le nom et l'e-mail ne sont ni dans les cookies, ni dans les mails de
  notification, ni dans l'audit.

## Conséquences

- Donnée personnelle conservée en base (nom, e-mail) en plus de la clé : même nature que ce
  que le portail affiche déjà à l'utilisateur, mais désormais persistante. À mentionner dans
  l'analyse de conformité de l'exploitant.
- Une personne jamais connectée au portail (compte créé à l'avance par l'administrateur) reste
  affichée par sa clé jusqu'à sa première connexion.
- Les comptes déjà créés se remplissent au fil des connexions : aucune reprise de données.

## Alternatives écartées

- **Libellé saisi à la main** par l'administrateur : saisie répétée, jamais synchronisée avec
  l'annuaire.
- **« NOM Prénom » via `family_name` / `given_name`** : demande d'activer des revendications
  facultatives chez le fournisseur ; écarté faute de besoin, à reprendre si le tri par nom
  devient nécessaire.
- **Interroger l'API de l'annuaire (Microsoft Graph)** : interdit par le principe
  d'indépendance vis-à-vis des fournisseurs.
