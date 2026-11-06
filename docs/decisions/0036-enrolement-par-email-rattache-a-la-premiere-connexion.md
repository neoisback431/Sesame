# 0036. Enrôlement par e-mail, rattaché à l'identité SSO à la première connexion

**Statut** : acceptée (2026-11-06), implémentée.

## Contexte

L'ADR 0035 permet d'enrôler quelqu'un avant sa première connexion, mais en saisissant sa clé
SSO exacte (`oid` avec Entra ID), que l'administrateur n'a presque jamais sous la main. Besoin
(décision de l'exploitant) : un **cas spécifique du provisionnement manuel**, sans changer la
règle générale (clé = claim configuré) : on ajoute la personne à la main, par son e-mail ;
quand elle se connecte réellement pour la première fois, son identité SSO est rattachée au
compte créé à la main.

## Décision

- **Enrôlement par e-mail** (Utilisateurs → « Enrôler un utilisateur », mode « e-mail ») :
  la clé sous laquelle les comptes et secrets sont rangés est l'**e-mail en minuscules**.
  Table `enrolments` (migration `0011`, sans secret) : clé, valeur de correspondance, auteur,
  état de la réclamation. L'enrôlement par clé exacte (ADR 0035) reste disponible.
- **Rattachement à la première connexion** : `UserDirectory::resolve_user_key`, appelé par le
  portail dans `finish_login` (OIDC et SAML) avant de créer la session :
  1. un alias `(issuer, subject)` existe (table `user_aliases`) → clé rattachée ;
  2. sinon, un enrôlement non réclamé dont la valeur égale (casse ignorée) l'attribut de
     correspondance de l'identité est **réclamé une seule fois, de façon atomique** (`UPDATE …
     WHERE claimed_at IS NULL`), et l'alias est écrit dans la même transaction ;
  3. sinon, la clé issue du fournisseur d'identité, inchangée.
- **Alias, pas de ré-écriture** : les comptes et secrets restent sous la clé e-mail. Les
  réécrire vers l'`oid` obligerait à rechiffrer les secrets (l'AAD du chiffrement contient la
  clé), ce que ni le portail ni le proxy ne peuvent ni ne doivent faire. La session portail
  porte la clé rattachée : le proxy, le catalogue, les demandes d'accès fonctionnent sans changement.
- **Attribut de correspondance configurable** : `SESAME_OIDC_ENROLMENT_CLAIM` (défaut
  `email` ; `preferred_username` avec Entra pour l'UPN) ; en SAML, l'attribut e-mail
  (`SESAME_SAML_EMAIL_ATTRIBUTE`). Le claim `email` d'Entra n'est pas vérifié par le
  fournisseur : qui peut obtenir ce claim pour l'adresse d'un enrôlé en attente peut
  réclamer ses comptes. À choisir en connaissance de cause (voir `docs/configuration.md`).
- **Échec fermé** : si la résolution échoue (base indisponible), la connexion est refusée
  (503) ; jamais de repli silencieux sur l'`oid`, qui couperait l'utilisateur de ses comptes.
- **Un enrôlement ne se réclame qu'une fois** : ensuite, une autre identité portant la même
  valeur ne le réclame plus.
- **Garde-fou côté admin** : refus d'enrôler un e-mail déjà enrôlé ou déjà connu (un
  utilisateur qui s'est déjà connecté avec son `oid` ne doit pas être doublé ; on lui ajoute
  directement ses comptes).
- **Audit** : `user_enrolled` (raison `email`) à l'enrôlement, `user_linked` (acteur = identité
  SSO, `target_user` = clé rattachée) au rattachement, dans la même opération que la session.

## Conséquences

- La clé d'un utilisateur rattaché reste son e-mail : si l'adresse change côté IdP, le
  rattachement (par alias sur `issuer`+`subject`) continue de fonctionner ; la clé affichée ne change pas.
- Les habilitations `spec.access.users` visent la clé rattachée (l'e-mail), pas l'`oid`.
- Un enrôlement jamais réclamé reste en attente indéfiniment (visible dans la page de l'utilisateur).
