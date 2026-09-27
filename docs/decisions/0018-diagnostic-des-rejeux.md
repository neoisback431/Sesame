# 0018 — Diagnostic des rejeux en échec dans l'administration

Date : 2026-09-28
Statut : accepté

## Contexte

Un rejeu en échec ne laissait qu'un code court (`login_unexpected_response`…) dans le
registre des comptes. Pour corriger un descripteur, l'exploitant devait deviner ce que
l'appli avait répondu. L'exploitant a demandé à voir la réponse réelle de l'appli dans
l'administration : il provisionne lui-même les comptes et veut pouvoir déboguer
facilement.

Le principe « jamais le contenu de la réponse de l'appli » vise le **navigateur de
l'utilisateur** : il reste inchangé (page d'erreur générique). La réponse d'une appli au
login peut toutefois recopier la saisie (identifiant, voire mot de passe) et contient ses
cookies de session.

## Décision

Option `SESAME_REPLAY_DEBUG` du proxy, **désactivée par défaut**, activée dans le compose
de dev. Active, le proxy enregistre pour chaque compte le diagnostic du **dernier** rejeu
en échec (`DiagnosticStore`, table `replay_diagnostics`, migration `0004`) :

- étape (page de login ou envoi du formulaire), méthode, URL, **noms** des champs envoyés ;
- statut, en-têtes, corps de la réponse (tronqué à 64 Ko).

Avant écriture, le proxy masque (`***`) toutes les valeurs lues dans le coffre sous leurs
formes brute, encodée URL, échappée HTML et échappée JSON, ainsi que les valeurs des
`Set-Cookie` (noms et attributs conservés). L'administration l'affiche, échappé, depuis un
compte en échec (« Voir la réponse de l'appli »), avec une aide selon le code d'échec et
le descripteur courant. Le diagnostic est supprimé avec le compte (`ON DELETE CASCADE`).

## Conséquences

- Correction d'un descripteur sans accès aux logs ni à l'appli.
- Risque résiduel : une valeur du coffre réapparaissant sous un encodage non prévu, ou
  des données de l'appli (autres que les identifiants) visibles des administrateurs. D'où
  la désactivation par défaut ; à activer en production en connaissance de cause.
- Rien ne change pour le navigateur de l'utilisateur ni pour les logs et l'audit.
- Tests : masquage (`diagnostic.rs`), diagnostic sans identifiant ni valeur de cookie
  (`tests/proxy.rs`), contrat `DiagnosticStore` (mémoire, PostgreSQL), affichage échappé
  dans l'admin.
