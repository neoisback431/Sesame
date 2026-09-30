# 0029. Demandes d'accès depuis « Mes applications »

**Statut** : acceptée (2026-09-30), implémentée.

## Contexte

Une tuile grisée (ADR 0022) signale une appli pour laquelle l'utilisateur est habilité
mais n'a pas de compte. Il ne pouvait qu'écrire à un administrateur. L'exploitant veut
qu'il puisse **demander l'accès** depuis la tuile, de deux façons :

1. **Il a déjà un compte applicatif** : il fournit ses identifiants, tout est enregistré,
   l'administrateur n'a plus qu'à valider l'activation.
2. **Il n'a pas de compte** : l'administrateur voit la demande et procède à la
   configuration (création du compte applicatif, puis provisionnement dans Sesame).

## Décision

- **Nouvel état de compte `pending`** (registre des comptes) : identifiants fournis par
  l'utilisateur, en attente de validation. Le rejeu est refusé (`account_pending`) tant
  qu'un administrateur n'a pas activé le compte ; la tuile reste grisée (« demande en
  cours »).
- **Table `access_requests`** (migration `0006`) : une ligne par couple (appli,
  utilisateur), type `credentials` ou `no_account`, état `open` / `approved` / `rejected`
  / `fulfilled`, note facultative de l'utilisateur. Aucun secret. Une nouvelle demande
  remplace la précédente (pas de multiplication de lignes).
- **Écriture directe dans le coffre** (choix de l'exploitant) : les identifiants saisis
  sont écrits dans le coffre à la soumission, compte `pending`, sans étape intermédiaire.
  Le **portail n'écrit ni ne lit jamais le coffre** : il relaie la soumission au moteur de
  proxy par un **service interne** (`SESAME_PROXY_INTERNAL_LISTEN`, jeton partagé
  `SESAME_INTERNAL_TOKEN`, jamais exposé par Nginx), le proxy détenant déjà le coffre et
  le moteur de rejeu. Nouvelle interface `SecretWriter` (implémentée par le coffre
  PostgreSQL ; pas par OpenBao/Vault, où la demande « j'ai un compte » est alors
  indisponible et le portail ne propose que « je n'ai pas de compte »).
- **Vérification par rejeu à la soumission** (choix de l'exploitant) : le proxy tente le
  login avec les identifiants saisis, **une seule tentative** (pas de nouvel essai, pour
  ne pas verrouiller le compte applicatif), sans créer de session ni toucher au registre.
  Échec : rien n'est enregistré, message générique avec identifiant de corrélation.
- **Garde-fous** : la soumission n'est acceptée que si l'utilisateur est habilité
  (`spec.access`, vérifié par le portail puis par le proxy) et n'a pas déjà de compte
  (ou seulement un compte `pending`, qu'il remplace). Un compte `active`, `failed` ou
  `disabled` ne peut donc **jamais** être écrasé par ce chemin. Le compte `pending` est
  créé avant l'écriture du secret ; si l'écriture échoue, la demande est retirée.
- **Administration** : page « Demandes d'accès » (compteur, filtre par type). Type
  `credentials` : **Activer** (compte `active`, demande `approved`) ou **Refuser**
  (identifiants et compte supprimés, demande `rejected`). Type `no_account` : l'admin
  crée le compte par le formulaire habituel (la demande passe alors à `fulfilled`) ou
  refuse. Aucune valeur de secret n'est jamais relue ni affichée.
- **Audit** : `access_requested` (portail/proxy : qui, appli, type, résultat, y compris
  les échecs de vérification), `credential_written`, `login_replay` (vérification),
  `access_request_approved` / `access_request_rejected` / `access_request_fulfilled`
  (admin).

## Conséquences

- **Exception au principe 1 (documentée)** : un mot de passe applicatif transite du
  navigateur vers le portail, puis du portail vers le proxy. C'est le mot de passe que
  l'utilisateur saisit lui-même (jamais un secret lu dans le coffre et renvoyé), en
  HTTPS de bout en bout côté navigateur ; le lien portail → proxy est interne (comme le
  recorder, ADR 0016). Il n'est ni journalisé, ni renvoyé, ni conservé au-delà de la
  requête (types `SecretString`, effacés à la destruction) ; un test vérifie l'absence de
  fuite dans la réponse, les logs et l'audit.
- **Le proxy gagne un droit d'écriture** sur le coffre PostgreSQL. ADR 0021 recommandait
  des rôles PostgreSQL distincts : le rôle du proxy doit maintenant pouvoir écrire
  `app_secrets` (et `app_accounts`, `access_requests`). Le chiffrement reste le même.
- **Nouvel appelant du service interne** : un client capable de joindre le port interne
  avec le jeton peut soumettre des identifiants pour un utilisateur donné. Même modèle
  de confiance que le recorder : réseau interne + jeton partagé.
- Un utilisateur peut spammer de nouvelles demandes, mais une seule ligne par couple
  (appli, utilisateur) existe : pas d'amplification de stockage.
