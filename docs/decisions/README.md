# Décisions d'architecture (ADR)

Une fiche par décision structurante : contexte, décision, conséquences. Une décision n'est jamais modifiée : une nouvelle fiche la remplace, et la fiche remplacée le mentionne.

| # | Décision | Date |
|---|---|---|
| [0001](0001-langages.md) | Rust pour le back, Python pour le reste | 2026-09-27 |
| [0002](0002-magasin-de-sessions-postgresql.md) | PostgreSQL comme magasin de sessions | 2026-09-27 |
| [0003](0003-credentials-par-utilisateur.md) | Credentials par utilisateur | 2026-09-27 |
| [0004](0004-ui-web-administration.md) | UI web d'administration dès le départ | 2026-09-27 |
| [0005](0005-decouplage-briques-externes.md) | Découplage des briques externes | 2026-09-27 |
| [0006](0006-licence-apache-2.md) | Licence Apache-2.0 | 2026-09-27 |
| [0007](0007-openbao-en-dev.md) | OpenBao en dev | 2026-09-27 |
| [0008](0008-routage-par-nom-d-hote.md) | Une appli par nom d'hôte | 2026-09-27 |
| [0009](0009-parcours-utilisateur.md) | Parcours utilisateur : « Mes applications », rejeu à l'arrivée | 2026-09-27 |
| [0010](0010-registre-des-comptes.md) | Registre des comptes dans PostgreSQL | 2026-09-27 |
| [0011](0011-administration.md) | UI d'administration : descripteurs en Git, FastAPI | 2026-09-27 |
| [0012](0012-embarquement.md) | Embarquement : outil en ligne de commande, vérification sans JavaScript | 2026-09-27 |
| [0013](0013-deconnexion-fournisseur.md) | Déconnexion chez le fournisseur d'identité, sans conserver l'ID token | 2026-09-27 |
| [0014](0014-applis-en-base.md) | Applis en base, créées dans l'administration (remplace en partie 0011) | 2026-09-27 |
| [0015](0015-recorder.md) | Recorder : analyse d'une page de login sans identifiant (remplacée en partie par 0019) | 2026-09-27 |
| [0016](0016-recorder-dans-admin.md) | Recorder appelé depuis l'administration | 2026-09-27 |
| [0017](0017-habilitation-par-compte.md) | Le compte suffit : `spec.access` facultatif (remplace en partie 0009) | 2026-09-28 |
| [0018](0018-diagnostic-des-rejeux.md) | Diagnostic des rejeux en échec dans l'administration | 2026-09-28 |
| [0019](0019-recorder-compte-de-test.md) | Recorder avec compte de test (remplace en partie 0015) | 2026-09-28 |
| [0020](0020-mode-remise-handoff.md) | Mode « remise » (handoff), exception aux principes 1 et 3 | 2026-09-28 |
| [0021](0021-coffre-postgresql-par-defaut.md) | Coffre PostgreSQL par défaut, sans Vault obligatoire (remplace en partie 0007) | 2026-09-28 |
| [0022](0022-tuiles-nouvel-onglet-deconnexion-par-appli.md) | Nouvel onglet, déconnexion par appli, tuile grisée sans compte (remplace en partie 0009) | 2026-09-28 |
| [0023](0023-tls-amont-non-verifie-par-defaut.md) | `spec.upstream.tls.verify` à `false` par défaut | 2026-09-28 |
| [0024](0024-support-saml.md) | Support SAML 2.0, en plus d'OIDC | 2026-09-28 |
| [0025](0025-publication-images-github.md) | Publication des images Docker sur GitHub (Releases + GHCR) | 2026-09-28 |
| [0026](0026-compose-sesame-seul-keycloak-facultatif.md) | Docker Compose : Sesame seul par défaut, Keycloak facultatif | 2026-09-28 |
| [0027](0027-kit-de-deploiement.md) | Kit de déploiement release (`deploy/release/`) | 2026-09-28 |
| [0028](0028-kit-aws-terraform.md) | Kit de déploiement AWS (Terraform, ECS Fargate, RDS) | 2026-09-28 |
