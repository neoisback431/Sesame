# Descripteur d'appli

Un descripteur indique à Sesame comment exposer une appli et comment rejouer sa connexion. Il est versionné dans `descriptors/`, au format YAML, et validé par le schéma [`schemas/app-descriptor.schema.json`](../schemas/app-descriptor.schema.json).

**Un descripteur ne contient jamais de secret.** Les identifiants sont désignés par un nom de clé (`from_secret: password`), puis lus dans le coffre au moment du rejeu.

Exemple complet : [`descriptors/fake-app.yaml`](../descriptors/fake-app.yaml). Gabarit commenté pour une nouvelle appli : [`descriptors/TEMPLATE.yaml.example`](../descriptors/TEMPLATE.yaml.example).

## Structure

| Section | Rôle |
|---|---|
| `metadata` | `id` stable (clé du coffre, des sessions et de l'audit), nom, `revision` incrémentée à chaque modification validée (tenue par Sesame pour les descripteurs en base), responsable |
| `spec.upstream` | URL interne de l'appli, TLS, délai, en-tête `Host` éventuel |
| `spec.public.host` | Nom d'hôte public sous lequel Sesame expose l'appli (une appli par hôte) |
| `spec.public.start_path` | Page ouverte par la tuile du portail (défaut `/`). À renseigner quand la racine de l'appli affiche le formulaire de login même une fois connecté ; le recorder avec compte de test la propose d'après la page atteinte après connexion |
| `spec.access` | Habilitation **facultative** : absent ou vide, tout utilisateur avec un compte actif est autorisé ; présent, restreint en plus aux `groups` (claims OIDC) et / ou `users` |
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

**Page de login construite en JavaScript** (React, Vue… : le formulaire n'existe pas dans le HTML servi, champs parfois sans attribut `name`) : `use_form: false`. Le proxy lit quand même la page de login (cookies, jetons `meta` / `cookie` / `regex`, appel `endpoint`), puis envoie directement la requête vers `action` (obligatoire), avec les champs déclarés dans `fields` ; `form_selector` et `include_hidden_inputs` sont ignorés. Le recorder détecte ce cas et lit les noms réellement envoyés dans la requête observée.

```yaml
login:
  form_url: /login
  use_form: false
  action: /api/auth/login
  encoding: json
  fields:
    email: { from_secret: username }
    password: { from_secret: password }
```

Avec `include_hidden_inputs: true` (valeur par défaut), tous les `input type=hidden` du formulaire sont renvoyés tels quels. Les jetons CSRF se déclarent dans `csrf` quand ils viennent d'ailleurs ou doivent être renvoyés autrement :

| `source` | Lecture | Renvoi par défaut |
|---|---|---|
| `hidden_input` | `<input type=hidden name=…>` | Champ du même nom |
| `meta` | `<meta name=… content=…>` | Champ du même nom (ou `send_as.header`) |
| `cookie` | Cookie posé par la page de login | Champ du même nom (ou `send_as.header`) |
| `regex` | Premier groupe de `pattern` dans le HTML | Champ du même nom |
| `endpoint` | Réponse d'un `GET` sur `url` (même origine), fait après la page de login avec ses cookies : champ JSON `name` (chemin pointé, ex. `data.token`), ou premier groupe de `pattern` sur le corps. Les cookies posés par cet appel rejoignent la session du rejeu | Champ `name` (ou `send_as.header`) |

Cas d'une appli dont le JavaScript récupère le jeton par une API avant de se connecter :

```yaml
csrf:
  - source: endpoint
    url: /api/csrf-token        # réponse : {"csrfToken": "…"}
    name: csrfToken
    send_as: { header: x-csrf-token }
```

Le recorder avec compte de test (ADR 0019) détecte ce cas et génère ce bloc.

## Conditions (`success`, `failure`, `expiry`)

Une condition vaut si **toutes** ses propriétés sont vraies. Un ensemble `any_of` vaut si **au moins une** de ses conditions vaut.

| Propriété | Sens |
|---|---|
| `status` | Code HTTP parmi la liste |
| `location_matches` / `location_not_matches` | Regex sur l'en-tête `Location` |
| `cookie_set` | La réponse pose ce cookie |
| `body_contains` / `body_not_contains` | Texte présent / absent du corps |

`failure` est évalué avant `success`. Ces conditions portent sur la réponse au POST de login, avant de suivre les redirections.

## Fichiers Git ou base

Un descripteur vit soit dans un fichier YAML de `descriptors/` (relu par merge request, lecture seule dans l'administration), soit en base, créé et modifié dans l'administration (formulaire guidé puis éditeur YAML, historique des révisions). Voir [ADR 0014](decisions/0014-applis-en-base.md). Le portail et le proxy fusionnent les deux sources : fichiers d'abord, puis base ; un descripteur en base dont l'`id` ou l'hôte public est déjà pris est écarté.

## Contrôles

- `make validate-descriptors` vérifie les fichiers contre le schéma JSON et l'unicité des `id`.
- Au démarrage, le moteur de proxy refait ces contrôles et en ajoute d'autres : regex compilables, `from_secret` correspondant à une clé de `credentials.keys`, etc. Un fichier invalide empêche le démarrage ; un descripteur en base invalide est écarté et journalisé, sans interrompre le service.
- L'éditeur de l'administration applique le schéma et ces mêmes contrôles avant d'enregistrer. Les regex doivent rester dans la syntaxe commune à Python et à la crate `regex` : pas de références arrière ni d'assertions de voisinage.
- Pour un descripteur en base, `sesame-onboard verify` s'utilise sur une copie du YAML de l'éditeur enregistrée dans un fichier. `sesame-onboard health` ne couvre pour l'instant que les fichiers.
- `sesame-onboard record <URL de login>` propose un descripteur en analysant la page dans un navigateur headless, sans identifiant, avec la liste des points à confirmer ; avec `--test-account` (ou le compte de test de l'admin), il se connecte réellement et observe le succès, le cookie de session et l'origine des jetons (ADR 0019).
- `sesame-onboard verify <descripteur>` rejoue le login avec un compte de test, avec les règles du proxy (HTML brut, sans JavaScript), et indique la cause d'un échec.
- `sesame-onboard fingerprint <descripteur>` calcule l'empreinte à reporter dans `spec.health.form_fingerprint` ; `sesame-onboard health` la surveille ensuite.
