# SPDX-License-Identifier: Apache-2.0

# ── Obligatoires ──────────────────────────────────────────────────────────────────

variable "region" {
  description = "Région AWS, ex. eu-west-3."
  type        = string
}

variable "domain" {
  description = "Domaine de Sesame : portail sur <domain>, administration sur admin.<domain>, applis sur <appli>.<domain>."
  type        = string
}

variable "vpc_id" {
  description = "VPC existant, depuis lequel Sesame joint les applications internes."
  type        = string
}

variable "private_subnet_ids" {
  description = "Sous-réseaux privés (au moins deux zones) pour les tâches ECS et la base. Sortie Internet requise (NAT) : images, fournisseur d'identité."
  type        = list(string)
}

variable "alb_subnet_ids" {
  description = "Sous-réseaux de l'Application Load Balancer (au moins deux zones) : publics si alb_internal = false, privés sinon."
  type        = list(string)
}

variable "oidc_issuer" {
  description = "Émetteur OIDC. Entra ID : https://login.microsoftonline.com/<tenant-id>/v2.0"
  type        = string
}

variable "oidc_portal_client_id" {
  description = "Client OIDC du portail (URL de retour : https://<domain>/auth/callback)."
  type        = string
}

variable "oidc_portal_client_secret" {
  description = "Secret du client OIDC du portail."
  type        = string
  sensitive   = true
}

variable "oidc_admin_client_id" {
  description = "Client OIDC de l'administration (URL de retour : https://admin.<domain>/auth/callback)."
  type        = string
}

variable "oidc_admin_client_secret" {
  description = "Secret du client OIDC de l'administration."
  type        = string
  sensitive   = true
}

# ── Certificat et DNS ─────────────────────────────────────────────────────────────

variable "route53_zone_id" {
  description = "Zone Route 53 du domaine. Si renseignée : certificat ACM créé et validé automatiquement, et enregistrements <domain> / *.<domain> créés vers l'ALB."
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "Certificat ACM existant couvrant <domain> et *.<domain>. Requis si route53_zone_id est vide."
  type        = string
  default     = ""
}

# ── Facultatives ──────────────────────────────────────────────────────────────────

variable "name" {
  description = "Préfixe des ressources créées."
  type        = string
  default     = "sesame"
}

variable "tags" {
  description = "Étiquettes ajoutées à toutes les ressources."
  type        = map(string)
  default     = {}
}

variable "sesame_version" {
  description = "Version des images (tag de release)."
  type        = string
  default     = "latest"
}

variable "image_registry" {
  description = "Registre des images Sesame (ghcr.io/<organisation> ou miroir ECR)."
  type        = string
  default     = "ghcr.io/neoisback431"
}

variable "admin_group" {
  description = "Groupe (claim de groupes) dont les membres accèdent à l'administration. Entra ID : GUID du groupe."
  type        = string
  default     = "sesame-admins"
}

variable "oidc_user_key_claim" {
  description = "Claim servant de clé utilisateur. Entra ID : oid."
  type        = string
  default     = "sub"
}

variable "oidc_groups_claim" {
  description = "Claim portant les groupes."
  type        = string
  default     = "groups"
}

variable "alb_internal" {
  description = "ALB interne (joignable seulement depuis le réseau de l'organisation) ou public."
  type        = bool
  default     = true
}

variable "allowed_cidrs" {
  description = "Plages d'adresses autorisées à joindre l'ALB (HTTPS)."
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "replay_debug" {
  description = "Mise au point d'une appli : réponse de l'appli au dernier rejeu en échec, visible dans l'administration."
  type        = bool
  default     = false
}

variable "recorder_enabled" {
  description = "Déploie le service d'analyse des pages de login (bouton « Analyser une page de login »)."
  type        = bool
  default     = true
}

variable "proxy_desired_count" {
  description = "Nombre de tâches du moteur de proxy."
  type        = number
  default     = 1
}

variable "db_instance_class" {
  description = "Classe de l'instance RDS PostgreSQL."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "Stockage de la base, en Go."
  type        = number
  default     = 20
}

variable "db_multi_az" {
  description = "Base répliquée sur deux zones (recommandé en production)."
  type        = bool
  default     = false
}

variable "db_deletion_protection" {
  description = "Protège la base contre la suppression (terraform destroy compris)."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Rétention des journaux CloudWatch (dont le journal d'audit)."
  type        = number
  default     = 365
}
