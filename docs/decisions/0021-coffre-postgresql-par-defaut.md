# 0021. Coffre de secrets PostgreSQL par défaut, sans Vault obligatoire

**Statut** : acceptée (2026-09-28), implémentée. Remplace en partie [0007](0007-openbao-en-dev.md) : OpenBao n'est plus la brique de coffre par défaut ; elle reste une implémentation interchangeable de `SecretStore` ([ADR 0005](0005-decouplage-briques-externes.md)).

## Contexte

Vault / OpenBao est une brique de plus à déployer, sauvegarder, superviser : un coût
disproportionné pour un déploiement qui n'a pas déjà de Vault d'entreprise. Sesame a
déjà PostgreSQL comme magasin de sessions et registre des comptes ([ADR 0002](0002-magasin-de-sessions-postgresql.md),
[0010](0010-registre-des-comptes.md)) ; y ajouter une table de secrets a un coût marginal
bien plus faible. L'exploitant a demandé un mode sans coffre externe, où les identifiants
applicatifs vivent dans la même base, et que ce mode devienne le mode par défaut.

## Décision

- Nouvelle implémentation de `SecretStore` (lecture, utilisée par le proxy) :
  `PgSecretStore` (`crates/sesame-store-postgres/src/secrets.rs`), table `app_secrets`
  (migration `0005_app_secrets.sql`) : une ligne par champ (`username`, `password`…),
  valeur chiffrée **AES-256-GCM**, liée par AAD au triplet (appli, utilisateur, champ).
  Même mécanisme que le chiffrement des cookies applicatifs (`CookieCipher`), avec une
  **clé distincte** (`SESAME_SECRETS_ENCRYPTION_KEY`) : deux domaines d'exposition
  différents.
- Écriture, réservée à l'UI d'admin : `PostgresSecretWriter`
  (`admin/src/sesame_admin/store_postgres.py`), chiffrement identique côté Python
  (`admin/src/sesame_admin/crypto.py`, `cryptography` / `AESGCM`, même format
  `nonce (12 octets) || chiffré`). **Aucune méthode de lecture** : comme pour Vault,
  l'admin ne relit jamais un secret qu'il a écrit.
- Écrire un identifiant **remplace l'ensemble des champs** du couple (appli,
  utilisateur), comme un `PUT` KV v2 de Vault : un champ absent de l'écriture est
  supprimé.
- `SESAME_SECRET_STORE` passe de `openbao` par défaut à **`postgres` par défaut**.
  `openbao` / `vault` restent disponibles en changeant cette seule variable (avec les
  variables `SESAME_OPENBAO_*` déjà existantes, inchangées).
- Environnement de dev : `docker-compose.yml` n'a plus besoin d'OpenBao par défaut
  (service retiré du fichier principal ; le compte de dev `fake-app` / `alice` est
  provisionné par `dev/postgres/seed_secret.py`, qui écrit dans `app_secrets` avec la
  même clé que le proxy et l'admin). OpenBao reste démontrable par
  `docker compose -f docker-compose.yml -f docker-compose.openbao.yml up`, qui bascule
  `SESAME_SECRET_STORE` du proxy et de l'admin sur `openbao`, sans toucher au reste :
  preuve vivante de l'indépendance vis-à-vis des briques externes (ADR 0005).

## Conséquences (contreparties assumées)

- **Séparation lecture / écriture affaiblie par rapport à Vault.** L'AppRole de Vault en
  écriture sans lecture est une garantie du serveur du coffre lui-même, indépendante du
  code qui l'appelle. Avec PostgreSQL, seule l'application garantit qu'aucune méthode ne
  relit un secret déchiffré : un accès SQL direct au rôle utilisé par l'admin, combiné à
  la clé de chiffrement, permettrait de déchiffrer `app_secrets`. Recommandation en
  production, non forcée par le code (comme pour le reste du schéma, déjà partagé entre
  l'admin et les services Rust) : un rôle PostgreSQL dédié à l'admin sans droit `SELECT`
  sur `app_secrets` (seulement `INSERT` / `UPDATE` / `DELETE`), et un rôle dédié au
  proxy en lecture seule. Documenté dans `docs/configuration.md`.
- Une brique externe de moins à opérer pour un petit déploiement.
- `SESAME_SECRETS_ENCRYPTION_KEY` doit être **identique** entre le proxy (déchiffre) et
  l'admin (chiffre), et **distincte** de `SESAME_SESSION_ENCRYPTION_KEY`. Sa perte est
  irréversible pour les secrets déjà écrits (comme la perte d'une clé de descellement
  Vault). Sa rotation n'est pas outillée : elle rendrait illisibles les secrets déjà
  écrits, à réenregistrer (même limite que `SESAME_SESSION_ENCRYPTION_KEY` aujourd'hui).
- Vault / OpenBao reste une implémentation à part entière de `SecretStore`, utile aux
  organisations qui en ont déjà un (rotation automatique, HSM, audit centralisé du
  coffre lui-même).
- Testé comme les autres implémentations PostgreSQL : contrat Rust
  (`crates/sesame-store-postgres/tests/contract.rs::postgres_secret_store`) et Python
  (`admin/tests/test_store_contract.py::test_secret_writer_contract`,
  `admin/tests/test_crypto.py`).
