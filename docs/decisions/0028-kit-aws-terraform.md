# 0028. Kit de déploiement AWS (Terraform, ECS Fargate, RDS)

**Statut** : acceptée (2026-09-28), implémentée.

## Contexte

Le kit Docker Compose (ADR 0027) couvre un serveur unique. AWS fait partie des cibles de
déploiement visées ; l'exploitant veut les conteneurs sur ECS et la base sur RDS, sans
avoir à écrire lui-même l'infrastructure.

## Décision

- **Terraform** (compatible OpenTofu, `>= 1.6`, providers `aws ~> 5.0` et `random`), dans
  `deploy/aws/`, joint à chaque Release (`sesame-aws-<tag>.tar.gz`, version et registre des
  images figés par `make release-kit`).
- **VPC existant** fourni par l'exploitant (sous-réseaux privés avec NAT) : Sesame doit
  joindre les applications internes, qui vivent déjà dans un réseau de l'organisation.
- **ECS Fargate** : un service par composant (portail, proxy, admin, recorder facultatif),
  mêmes images et mêmes variables que le kit Compose ; le recorder est joint par l'admin via
  ECS Service Connect sous le nom `recorder` (même URL que dans Compose).
- **ALB + ACM** à la place de Nginx : même routage par nom d'hôte (domaine → portail,
  `admin.` → admin, reste → proxy), certificat créé et validé si une zone Route 53 est
  fournie, sinon certificat existant. ALB interne par défaut, limité à `allowed_cidrs`.
- **RDS PostgreSQL 17** privé, chiffré, sauvegardé, protégé contre la suppression ;
  connexion TLS (`sslmode=require`).
- **Secrets** : clés générées par Terraform (`random_bytes` / `random_password`), gardées
  dans un secret Secrets Manager et injectées par ECS ; seules les tâches (rôle
  d'exécution) les lisent, jamais visibles dans les définitions de tâches. Les tâches n'ont
  pas de rôle IAM (Sesame n'appelle aucune API AWS).
- **Journaux** : CloudWatch Logs (logs JSON et audit), rétention 365 jours par défaut
  (exigence de conservation de l'audit en contexte PCI-DSS).

## Conséquences

- Aucune modification du code de Sesame : le kit n'est que de la configuration.
- L'état Terraform contient les clés de chiffrement : backend chiffré à accès restreint
  requis (documenté). Régénérer `secrets_encryption_key` rendrait les identifiants
  applicatifs illisibles.
- SAML n'est pas préconfiguré (variables à ajouter dans `ecs.tf`), pour garder le kit
  minimal.
- Pas de validation en CI (Terraform absent de l'image CI) : validé par `terraform
  validate` et un `plan` à identifiants factices.

## Alternatives écartées

- **CloudFormation / CDK** : moins portable et moins répandu que Terraform chez les
  exploitants visés (on-premises + AWS).
- **VPC créé par le kit** : plus simple à tester, mais Sesame n'y joindrait pas les
  applications internes sans peering ; l'exploitant a un VPC existant.
- **ECS sur EC2** : instances à gérer ; Fargate suffit (aucun besoin d'accès à l'hôte).
