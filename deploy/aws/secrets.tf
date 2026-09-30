# SPDX-License-Identifier: Apache-2.0
# Clés générées une fois et gardées dans AWS Secrets Manager, injectées dans les tâches.
# Ne jamais régénérer secrets_encryption_key : les identifiants applicatifs déjà
# enregistrés deviendraient illisibles.

resource "random_bytes" "portal_state_key" {
  length = 32
}

resource "random_bytes" "session_encryption_key" {
  length = 32
}

resource "random_bytes" "secrets_encryption_key" {
  length = 32
}

resource "random_password" "admin_session_key" {
  length  = 64
  special = false
}

resource "random_password" "recorder_token" {
  length  = 64
  special = false
}

# Jeton du service interne du proxy (demandes d'accès avec identifiants, ADR 0029).
resource "random_password" "internal_token" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "config" {
  name                    = "${var.name}/config"
  description             = "Sesame : cles de chiffrement, connexion a la base, secrets OIDC"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "config" {
  secret_id = aws_secretsmanager_secret.config.id
  secret_string = jsonencode({
    database_url              = "postgres://sesame:${random_password.db.result}@${aws_db_instance.this.address}:${aws_db_instance.this.port}/sesame?sslmode=require"
    portal_state_key          = random_bytes.portal_state_key.base64
    session_encryption_key    = random_bytes.session_encryption_key.base64
    secrets_encryption_key    = random_bytes.secrets_encryption_key.base64
    admin_session_key         = random_password.admin_session_key.result
    recorder_token            = random_password.recorder_token.result
    internal_token            = random_password.internal_token.result
    oidc_portal_client_secret = var.oidc_portal_client_secret
    oidc_admin_client_secret  = var.oidc_admin_client_secret
  })
}
