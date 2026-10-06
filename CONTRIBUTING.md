# Contribuer à Sesame

Merci de votre intérêt ! Sesame protège des identifiants applicatifs : la sécurité et la
confidentialité passent avant tout, y compris dans les issues et les pull requests.

- [Avant tout : ne publiez jamais de secret](#avant-tout--ne-publiez-jamais-de-secret)
- [Signaler un problème (issues)](#signaler-un-problème-issues)
- [Proposer une modification (pull requests)](#proposer-une-modification-pull-requests)
- [Environnement de développement](#environnement-de-développement)
- [Conventions](#conventions)
- [Publier une release (mainteneurs)](#publier-une-release-mainteneurs)

## Avant tout : ne publiez jamais de secret

Les issues, pull requests, commentaires et captures d'écran sont **publics**. N'y mettez
jamais :

- de mot de passe, de jeton, de cookie de session, de clé de chiffrement, de secret client
  OIDC ou de certificat privé (même « de test » s'il vient d'un vrai environnement) ;
- de donnée propre à votre organisation : noms d'hôtes ou URLs internes, identifiant de
  tenant, noms de groupes réels, noms d'utilisateurs réels, adresses e-mail ;
- de réponse brute d'une application (le diagnostic des rejeux masque les valeurs du coffre et
  des cookies, mais relisez-le quand même).

Remplacez-les par des valeurs génériques (`app-interne.exemple`, `alice`, `***`). Une
contribution qui en contient sera masquée ou refusée.

**Une vulnérabilité ne s'ouvre jamais en issue publique** : voir [SECURITY.md](SECURITY.md).

## Signaler un problème (issues)

Utilisez les modèles proposés à l'ouverture d'une issue :

| Modèle | Pour |
|---|---|
| 🐛 **Bug** | Un comportement incorrect, reproductible |
| ✨ **Fonctionnalité** | Une amélioration ou un nouveau besoin |
| 🧩 **Application non prise en charge** | Une appli dont le login ne se rejoue pas |

Règles :

1. **Cherchez d'abord** parmi les issues existantes (ouvertes et fermées) : commentez plutôt
   que de dupliquer.
2. **Une issue = un sujet.** Deux problèmes distincts, deux issues.
3. **Un bug doit être reproductible** : version de Sesame, protocole (OIDC / SAML), coffre
   utilisé, étapes précises, résultat attendu et obtenu, **identifiant de corrélation** de la
   page d'erreur et extrait des logs correspondants (masqués).
4. **Une application qui ne se rejoue pas** : joignez le descripteur (anonymisé), la sortie de
   `sesame-onboard verify` ou du recorder, et le code d'échec (`login_unexpected_response`,
   `submission_not_observed`…). Précisez si la page de login utilise du JavaScript, un captcha,
   plusieurs étapes ou une MFA (hors périmètre pour l'instant).
5. **Une demande de fonctionnalité** décrit le besoin (le problème à résoudre) avant la
   solution. Les changements structurants (nouvelle brique, changement de modèle de sécurité)
   passent par une discussion puis une [décision d'architecture](docs/decisions/) avant d'être
   codés.
6. Restez courtois et factuel : voir le [code de conduite](CODE_OF_CONDUCT.md).

Libellés utilisés par les mainteneurs : `bug`, `enhancement`, `security`, `documentation`,
`onboarding` (embarquement d'applis), `good first issue`, `needs-info` (en attente d'éléments ;
fermée sans réponse sous 30 jours), `wontfix`, `duplicate`.

## Proposer une modification (pull requests)

1. **Ouvrez d'abord une issue** pour tout changement non trivial, afin de valider l'approche.
   Les corrections de documentation ou de coquilles peuvent venir directement.
2. **Forkez**, créez une branche depuis `main` (`fix/…`, `feat/…`, `docs/…`).
3. **Petits commits ciblés**, messages descriptifs (le quoi dans le titre, le pourquoi dans le
   corps).
4. **Avant de pousser** :
   ```sh
   make lint     # fmt, clippy -D warnings, ruff, validation des descripteurs
   make test     # tests rapides Rust + Python
   make deny     # licences des dépendances
   ```
   Si vous touchez au recorder (`onboarding/…/record.py`, `proposal.py`, `server.py`), lancez
   aussi `make test-full`.
5. **Remplissez le modèle de PR** : objet, issue liée, comment vous avez testé, et la liste de
   vérification.

Une PR est fusionnée quand :

- la CI est verte ;
- au moins un mainteneur l'a approuvée ;
- elle respecte les [conventions](#conventions) ci-dessous ;
- toute fonctionnalité touchant aux secrets est accompagnée d'un **test de non-fuite**
  (réponse, logs, erreurs) ;
- la documentation est à jour (`docs/configuration.md` pour toute nouvelle variable
  d'environnement, `docs/descriptor.md` et le schéma pour tout changement du descripteur, un
  ADR pour toute décision structurante) ;
- elle n'introduit **ni secret réel, ni donnée propre à une organisation**.

Les mainteneurs peuvent demander de scinder une PR trop large. En contribuant, vous acceptez
que votre contribution soit publiée sous licence [Apache-2.0](LICENSE).

## Environnement de développement

Voir [docs/dev.md](docs/dev.md). En résumé :

```sh
make up-demo   # environnement complet avec l'appli factice (Keycloak de dev décommenté dans docker-compose.yml)
make test      # tests rapides
make e2e       # parcours bout en bout dans un navigateur (après make up-demo)
```

Hors conteneurs : Rust stable (≥ 1.85) et [`uv`](https://docs.astral.sh/uv/) (Python ≥ 3.11).
Le portail compile contre `libxmlsec1` (SAML) : `libxmlsec1-dev`, `libxml2-dev`,
`pkg-config` et `clang` sous Debian / Ubuntu.

## Conventions

- **Langue** : documentation et commentaires de conception en français ; identifiants de code
  en anglais.
- **Licence** : chaque fichier source commence par `SPDX-License-Identifier: Apache-2.0`.
- **Dépendances** : licences compatibles Apache-2.0 uniquement (MIT, BSD, Apache-2.0, ISC,
  MPL-2.0…), jamais de GPL / AGPL ; vérifié par `make deny`.
- **Secrets** : jamais journalisés, sérialisés ni inclus dans une erreur ; utilisez les types
  masqués (`***`) existants.
- **Contrat Rust / Python** : le schéma `schemas/app-descriptor.schema.json` fait foi ; toute
  évolution du rejeu se reporte dans `crates/sesame-proxy` **et** `onboarding/`, toute
  évolution de la validation des descripteurs dans `admin/…/descriptors.py`.
- **Indépendance des briques** : aucun SDK ni type propre à un fournisseur hors de son module
  d'implémentation.
- **CI portable** : la logique vit dans le `Makefile` et `scripts/`, les fichiers CI restent
  minces.

## Publier une release (mainteneurs)

1. Mettez à jour la version (`Cargo.toml`, `*/pyproject.toml`), la version fixée des kits
   (`variable "sesame_version"` dans `deploy/aws/variables.tf`, `SESAME_VERSION` dans
   `deploy/release/.env.example` : `make check-kit-versions` vérifie l'accord avec `Cargo.toml`),
   le [CHANGELOG](CHANGELOG.md) et les notes de version `docs/releases/vX.Y.Z.md`.
2. Taguez et poussez :
   ```sh
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```
3. Le workflow `.github/workflows/release.yml` construit et publie les 4 images sur GitHub
   Container Registry (`sesame-portal`, `sesame-proxy`, `sesame-admin`, `sesame-recorder`), puis
   crée la Release GitHub avec `docs/releases/vX.Y.Z.md` comme notes (notes générées depuis les
   commits si le fichier n'existe pas) et l'archive du kit de déploiement
   (`sesame-deploy-vX.Y.Z.tar.gz` et `sesame-aws-vX.Y.Z.tar.gz`, `make release-kit`). Voir l'[ADR 0025](docs/decisions/0025-publication-images-github.md).

En local : `make release-images VERSION=vX.Y.Z [REGISTRY=ghcr.io/<organisation>/sesame]`.
