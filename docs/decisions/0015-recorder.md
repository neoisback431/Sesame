# 0015. Recorder : analyse d'une page de login sans identifiant

**Statut** : acceptée (2026-09-27). Complète [0012](0012-embarquement.md).

## Contexte

Le descripteur d'une appli s'écrivait à la main, à partir du gabarit ou du formulaire guidé de l'administration ([0014](0014-applis-en-base.md)). La capture automatique était prévue avec Playwright. L'utilisateur a demandé de mettre en place ce « recorder » en **écartant pour l'instant le mot de passe** : aucun identifiant réel n'est saisi, demandé ni rejoué.

## Décision

- Nouvelle commande `sesame-onboard record <URL de login>`. Elle ouvre la page dans un Chromium headless (Playwright, JavaScript exécuté), dans un contexte jetable (pas de profil, téléchargements et service workers bloqués).
- **Repérage** : formulaire contenant un champ mot de passe, champ identifiant (attribut `autocomplete`, nom, visibilité), champs cachés, balises meta et cookies ressemblant à des jetons CSRF, captcha, login en plusieurs étapes.
- **Soumission interceptée** : le recorder remplit des valeurs factices (`sesame-recorder-…`, mot de passe aléatoire) et déclenche la soumission, puis l'**annule** avant qu'elle ne parte. Il en retient la méthode, la cible, l'encodage (formulaire ou JSON), les noms des champs envoyés et les en-têtes CSRF. La source d'un jeton envoyé en en-tête (meta, cookie, champ caché) se déduit en comparant les valeurs **en mémoire** ; seules les correspondances de noms sont conservées.
- **Vue du proxy** : le formulaire est recherché dans le HTML brut, sans JavaScript. Absent, l'appli n'est pas rejouable (`login_form_not_found_in_raw_html`). Son empreinte est reportée dans `spec.health.form_fingerprint`.
- **Expiration** : une page protégée (`--protected-path`, `/` par défaut) est demandée sans session ; sa réponse (redirection vers le login, 401…) donne `spec.expiry`.
- **Sonde d'échec, facultative** (`--probe-failure`) : la soumission factice est relayée, une seule fois et vers l'origine de l'appli uniquement, pour observer la réponse d'échec (statut, redirection, message d'erreur visible) et proposer `spec.login.failure`. Désactivée par défaut, car l'appli reçoit alors une tentative de connexion (identifiant inexistant, reconnaissable dans ses journaux).
- **Sortie** : un descripteur YAML valide contre le schéma, en tête duquel sont listés les points à confirmer, et un constat lisible sur la sortie d'erreur. Le cookie de session, qui n'apparaît qu'après une connexion réussie, reste à renseigner (`--session-cookie`) ; les conditions de succès sont à confirmer par `verify`.
- **Jamais conservé ni affiché** : valeurs des champs cachés, jetons CSRF, cookies, valeurs factices saisies. Pendant l'analyse, aucune requête d'écriture ne sort de l'origine de l'appli, et une seule soumission au plus est autorisée.

## Conséquences

- Le descripteur proposé est rejouable après ajout du seul cookie de session (vérifié en test sur l'appli factice avec `verify`).
- Playwright et un navigateur sont nécessaires au seul recorder : extra `capture` du paquet, image `recorder` (profil `tools`, image Playwright officielle). L'image de santé reste sans navigateur.
- Un login entièrement piloté par JavaScript est analysé, mais signalé (`login_submitted_by_javascript`) : le proxy rejoue la requête observée, pas le script.
- Étape suivante possible : un enregistrement avec un compte de test (connexion réelle observée pour le cookie de session et le succès), sous les mêmes règles de non-conservation des valeurs. Également : lancer le recorder depuis l'administration, ce qui demanderait un navigateur côté serveur et un contrôle des URL analysables (SSRF).
