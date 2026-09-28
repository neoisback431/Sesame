# SPDX-License-Identifier: Apache-2.0

output "portal_url" {
  description = "Portail « Mes applications »."
  value       = "https://${var.domain}"
}

output "admin_url" {
  description = "Administration."
  value       = "https://admin.${var.domain}"
}

output "oidc_redirect_uris" {
  description = "URL de retour à déclarer chez le fournisseur d'identité."
  value = {
    portal = "https://${var.domain}/auth/callback"
    admin  = "https://admin.${var.domain}/auth/callback"
  }
}

output "alb_dns_name" {
  description = "Nom DNS de l'ALB : cible des enregistrements <domain> et *.<domain> si route53_zone_id est vide."
  value       = aws_lb.this.dns_name
}

output "log_group" {
  description = "Journaux CloudWatch des services (dont le journal d'audit)."
  value       = aws_cloudwatch_log_group.this.name
}

output "config_secret_arn" {
  description = "Secret Secrets Manager contenant les clés de chiffrement et la connexion à la base."
  value       = aws_secretsmanager_secret.config.arn
}
