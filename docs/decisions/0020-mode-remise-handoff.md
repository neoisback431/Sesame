# 0020 — Mode « remise » (handoff) : exception aux principes 1 et 3

Date : 2026-09-28
Statut : accepté (validé le 2026-09-28) ; implémenté (session.mode, proxy handoff, recorder, admin)

## Contexte

Le mode nominal (proxy) garde la session applicative côté serveur : le navigateur ne voit
jamais ni identifiant, ni cookie, ni jeton de l'appli. Certaines applis ne fonctionnent pas
ainsi :

- SPA qui gardent leur session dans le stockage du navigateur (`localStorage`) et
  l'envoient elles-mêmes en en-tête `Authorization` (cas YAST : `refreshToken` stocké,
  aucune vérification côté serveur au chargement) ;
- applis dont le JavaScript lit ses propres cookies, ou qui utilisent des WebSockets.

Pour elles, le proxy ne peut pas rendre la connexion transparente.

## Décision

Mode facultatif, **par appli**, **désactivé par défaut** : `spec.session.mode: proxy |
handoff` (défaut `proxy`).

En `handoff`, Sesame :

1. vérifie la session portail, le compte actif et l'habilitation (inchangé) ;
2. lit le credential dans le coffre et rejoue le login côté serveur (inchangé, audité) ;
3. **remet** au navigateur l'élément de session déclaré dans le descripteur, puis le
   redirige vers `public.start_path` ; l'appli est ensuite jointe **directement**, sans
   proxy.

Élément remis, déclaré dans `spec.session.handoff` :

- `cookie` : cookie de session posé sur le domaine de l'appli (via une URL dédiée sur
  l'hôte de l'appli routée par Nginx vers Sesame, ou un domaine parent commun) ;
- `local_storage` : valeur lue dans la réponse au login (champ JSON pointé) écrite sous
  une clé donnée du stockage local, par une page de remise servie sur l'hôte de l'appli.

Le mot de passe applicatif ne quitte **jamais** le serveur (principe 1 maintenu pour
lui). Seul l'élément de session est remis.

## Conséquences (contreparties assumées)

- **Exception au principe 3** et, pour les jetons, à la règle « jamais de jeton vers le
  navigateur » : l'élément remis est visible et copiable par l'utilisateur.
- Déconnexion portail et désactivation d'un compte **non immédiates** : la session reste
  valable jusqu'à son expiration côté appli, sauf si le descripteur déclare une
  déconnexion que Sesame appelle.
- Plus de reconnexion automatique à l'expiration : l'utilisateur repasse par la tuile.
- Audit limité à la connexion (lecture du coffre, rejeu, remise) : les accès suivants ne
  passent plus par Sesame.
- Réservé aux applis où le proxy est impossible **et** où l'exploitant accepte ce risque ;
  en contexte PCI-DSS, à justifier appli par appli (hors périmètre des données de carte).
- L'admin affiche le mode de chaque appli ; le recorder ne propose `handoff` que comme
  suggestion, jamais par défaut.

## Hors périmètre de cette ADR

Le relais de l'en-tête `Authorization` du navigateur à travers le proxy (mode mixte) : non
retenu, le mode `handoff` joint l'appli directement.
