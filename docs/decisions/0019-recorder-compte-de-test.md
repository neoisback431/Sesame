# 0019 — Recorder avec compte de test

Date : 2026-09-28
Statut : accepté (remplace en partie l'ADR 0015, qui écartait tout identifiant)

## Contexte

Sans identifiant, le recorder n'observe qu'une soumission factice : il ne voit ni la
réponse d'une connexion réussie, ni le cookie de session, et devine mal les connexions
faites en JavaScript (jeton CSRF lu dans un cookie ou un script, champs renommés, JSON).
Sur une appli réelle, le descripteur proposé échouait au rejeu
(`login_unexpected_response`, « jeton de sécurité invalide »). L'exploitant a demandé
que le recorder aille au bout de la procédure avec un couple identifiant / mot de passe
de test.

## Décision

Compte de test **facultatif**, saisi dans l'admin (formulaire « Analyser une page de
login ») ou fourni à `sesame-onboard record --test-account` (variables
`SESAME_ONBOARD_USERNAME` / `SESAME_ONBOARD_PASSWORD`, sinon saisie masquée).

Après l'analyse habituelle, le recorder ouvre un contexte de navigateur neuf, remplit le
formulaire avec le compte de test et laisse partir **la seule requête qui transporte le
mot de passe** (même origine uniquement ; toute autre écriture est bloquée). Il en déduit :

- cible, méthode, encodage, noms réels des champs identifiant / mot de passe, constantes
  simples envoyées, envoi ou non des champs cachés ;
- source de chaque jeton envoyé (en-tête ou champ) : cookie, balise meta, champ caché, ou
  script de la page (expression régulière construite d'après le contexte du jeton dans le
  HTML servi), ou **appel d'API** fait par le JavaScript avant le login : nouvelle source
  `endpoint` du descripteur (`url` appelée en GET, même origine, avec les cookies de la
  page de login ; jeton lu dans un champ JSON pointé ou par `pattern`), refaite par le
  proxy et par `sesame-onboard verify` ;
- réponse : statut, redirection, cookies posés ; cookie(s) de session ; connexion réussie
  si plus aucun champ mot de passe n'est visible.

Le descripteur proposé porte alors `login.success` et `session.cookies` observés.

Garde-fous : identifiants transmis au service recorder interne (jeton partagé), utilisés
en mémoire le temps de la connexion, jamais conservés, journalisés, audités ni renvoyés ;
les messages d'erreur Playwright ne sont pas relayés (seul le type d'exception). L'audit
`descriptor_recorded` indique « (compte de test) », sans l'identifiant.

## Conséquences

- Descripteur rejouable tel quel dans la plupart des cas, y compris pour les connexions
  en JavaScript (vérifié par `sesame-onboard verify`, mêmes règles que le proxy).
- Une vraie connexion est faite sur l'appli avec le compte de test (session ouverte côté
  appli, dernière connexion mise à jour) : utiliser un compte dédié.
- Hors périmètre inchangé : login multi-étapes, captcha, MFA, session hors cookies
  (jeton en stockage JavaScript : signalé bloquant).
