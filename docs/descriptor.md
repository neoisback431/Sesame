# Descripteur d'appli

Un descripteur indique à Sesame comment exposer une appli et comment rejouer sa connexion. Il est versionné dans `descriptors/`, au format YAML, et validé par le schéma [`schemas/app-descriptor.schema.json`](../schemas/app-descriptor.schema.json).

**Un descripteur ne contient jamais de secret.** Les identifiants sont désignés par un nom de clé (`from_secret: password`), puis lus dans le coffre au moment du rejeu.

Exemple complet : [`descriptors/fake-app.yaml`](../descriptors/fake-app.yaml).

## Structure

| Section | Rôle |
|---|---|
| `metadata` | `id` stable (clé du coffre, des sessions et de l'audit), nom, `revision` incrémentée à chaque modification validée, responsable |
| `spec.upstream` | URL interne de l'appli, TLS, délai, en-tête `Host` éventuel |
| `spec.public.host` | Nom d'hôte public sous lequel Sesame expose l'appli (une appli par hôte) |
| `spec.access` | Habilitations : `groups` et / ou `users` (valeurs issues des claims OIDC) |
| `spec.credentials` | `mode: per_user` et liste des clés lues dans le coffre (`username`, `password`…) |
| `spec.login` | Rejeu : page de login, formulaire, champs, jetons CSRF, conditions de succès et d'échec, `max_attempts` |
| `spec.session` | Cookies de session à capturer, `max_ttl`, `idle_ttl` |
| `spec.expiry` | Conditions signalant une session applicative expirée sur une réponse relayée |
| `spec.logout` | Chemins de déconnexion de l'appli et comportement associé |
| `spec.rewrite` | Réécriture de `Location` et des URLs absolues internes |
| `spec.health` | Intervalle du test de santé, empreinte du formulaire validé |

## Champs du formulaire

```yaml
fields:
  username: { from_secret: username }   # lu dans le coffre
  password: { from_secret: password }
  remember: { value: "on" }             # constante non sensible
```

Avec `include_hidden_inputs: true` (valeur par défaut), tous les `input type=hidden` du formulaire sont renvoyés tels quels. Les jetons CSRF se déclarent dans `csrf` quand ils viennent d'ailleurs ou doivent être renvoyés autrement :

| `source` | Lecture | Renvoi par défaut |
|---|---|---|
| `hidden_input` | `<input type=hidden name=…>` | Champ du même nom |
| `meta` | `<meta name=… content=…>` | Champ du même nom (ou `send_as.header`) |
| `cookie` | Cookie posé par la page de login | Champ du même nom (ou `send_as.header`) |
| `regex` | Premier groupe de `pattern` dans le HTML | Champ du même nom |

## Conditions (`success`, `failure`, `expiry`)

Une condition vaut si **toutes** ses propriétés sont vraies. Un ensemble `any_of` vaut si **au moins une** de ses conditions vaut.

| Propriété | Sens |
|---|---|
| `status` | Code HTTP parmi la liste |
| `location_matches` / `location_not_matches` | Regex sur l'en-tête `Location` |
| `cookie_set` | La réponse pose ce cookie |
| `body_contains` / `body_not_contains` | Texte présent / absent du corps |

`failure` est évalué avant `success`. Ces conditions portent sur la réponse au POST de login, avant de suivre les redirections.

## Contrôles

- `make validate-descriptors` vérifie les fichiers contre le schéma JSON et l'unicité des `id`.
- Au démarrage, le moteur de proxy refait ces contrôles et en ajoute d'autres : regex compilables, `from_secret` correspondant à une clé de `credentials.keys`, etc. Un descripteur invalide empêche le démarrage.
