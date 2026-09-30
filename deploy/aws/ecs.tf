# SPDX-License-Identifier: Apache-2.0
# Services ECS Fargate : portail, proxy, administration, recorder (facultatif).
# Même configuration que le kit Docker Compose (deploy/release), secrets lus dans
# Secrets Manager au démarrage des tâches (jamais en clair dans la définition).

locals {
  # Services derrière l'ALB (clés reprises par alb.tf).
  web_services = {
    portal = { port = 8080, health_path = "/healthz" }
    proxy  = { port = 8081, health_path = "/.sesame/healthz" }
    admin  = { port = 8000, health_path = "/healthz" }
  }

  image  = { for s in ["portal", "proxy", "admin", "recorder"] : s => "${var.image_registry}/sesame-${s}:${var.sesame_version}" }
  secret = aws_secretsmanager_secret.config.arn

  env = {
    portal = {
      SESAME_PUBLIC_URL          = "https://${var.domain}"
      SESAME_COOKIE_DOMAIN       = var.domain
      SESAME_ADMIN_URL           = "https://admin.${var.domain}"
      SESAME_ADMIN_GROUP         = var.admin_group
      SESAME_OIDC_ISSUER         = var.oidc_issuer
      SESAME_OIDC_CLIENT_ID      = var.oidc_portal_client_id
      SESAME_OIDC_USER_KEY_CLAIM = var.oidc_user_key_claim
      SESAME_OIDC_GROUPS_CLAIM   = var.oidc_groups_claim
      # Service interne du proxy (Service Connect) : demandes d'accès avec identifiants.
      SESAME_PROXY_INTERNAL_URL = "http://proxy-internal:8082"
    }
    proxy = {
      SESAME_PORTAL_URL    = "https://${var.domain}"
      SESAME_COOKIE_DOMAIN = var.domain
      SESAME_REPLAY_DEBUG  = tostring(var.replay_debug)
    }
    admin = merge({
      SESAME_ADMIN_PUBLIC_URL    = "https://admin.${var.domain}"
      SESAME_ADMIN_GROUP         = var.admin_group
      SESAME_OIDC_ISSUER         = var.oidc_issuer
      SESAME_OIDC_CLIENT_ID      = var.oidc_admin_client_id
      SESAME_OIDC_USER_KEY_CLAIM = var.oidc_user_key_claim
      SESAME_OIDC_GROUPS_CLAIM   = var.oidc_groups_claim
    }, var.recorder_enabled ? { SESAME_RECORDER_URL = "http://recorder:8090" } : {})
    recorder = {
      SESAME_APPS_DOMAIN = var.domain
    }
  }

  # Variable d'environnement → clé du secret JSON "<name>/config".
  secrets = {
    portal = {
      SESAME_DATABASE_URL       = "database_url"
      SESAME_PORTAL_STATE_KEY   = "portal_state_key"
      SESAME_OIDC_CLIENT_SECRET = "oidc_portal_client_secret"
      SESAME_INTERNAL_TOKEN     = "internal_token"
    }
    proxy = {
      SESAME_DATABASE_URL           = "database_url"
      SESAME_SESSION_ENCRYPTION_KEY = "session_encryption_key"
      SESAME_SECRETS_ENCRYPTION_KEY = "secrets_encryption_key"
      SESAME_INTERNAL_TOKEN         = "internal_token"
    }
    admin = merge({
      SESAME_DATABASE_URL           = "database_url"
      SESAME_ADMIN_SESSION_KEY      = "admin_session_key"
      SESAME_OIDC_CLIENT_SECRET     = "oidc_admin_client_secret"
      SESAME_SECRETS_ENCRYPTION_KEY = "secrets_encryption_key" # l'admin chiffre, le proxy déchiffre
    }, var.recorder_enabled ? { SESAME_RECORDER_TOKEN = "recorder_token" } : {})
    recorder = {
      SESAME_RECORDER_TOKEN = "recorder_token"
    }
  }

  size = {
    portal   = { cpu = 256, memory = 512 }
    proxy    = { cpu = 512, memory = 1024 }
    admin    = { cpu = 256, memory = 512 }
    recorder = { cpu = 1024, memory = 2048 } # Chromium headless
  }

  ports = merge({ for k, v in local.web_services : k => v.port }, { recorder = 8090 })

  services = var.recorder_enabled ? ["portal", "proxy", "admin", "recorder"] : ["portal", "proxy", "admin"]
}

# ── Cluster, journaux, découverte interne ────────────────────────────────────────

resource "aws_service_discovery_http_namespace" "this" {
  name = var.name
}

resource "aws_ecs_cluster" "this" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  service_connect_defaults {
    namespace = aws_service_discovery_http_namespace.this.arn
  }
}

# Logs JSON des services, dont le journal d'audit ("log_type":"audit").
resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
}

# ── Rôle d'exécution : tirer les images, écrire les logs, lire le secret ─────────
# Les tâches elles-mêmes n'ont aucun rôle IAM : Sesame n'appelle aucune API AWS.

data "aws_iam_policy_document" "assume_ecs_tasks" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs_tasks.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "read_config" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.config.arn]
  }
}

resource "aws_iam_role_policy" "read_config" {
  name   = "read-config"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.read_config.json
}

# ── Définitions de tâches ────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "service" {
  for_each = toset(local.services)

  family                   = "${var.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = local.size[each.key].cpu
  memory                   = local.size[each.key].memory
  execution_role_arn       = aws_iam_role.execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name      = each.key
    image     = local.image[each.key]
    essential = true

    # Le proxy expose en plus son service interne (8082), joint par le portail seulement.
    portMappings = concat([{
      name          = each.key
      containerPort = local.ports[each.key]
      protocol      = "tcp"
      appProtocol   = "http"
      }], each.key == "proxy" ? [{
      name          = "internal"
      containerPort = 8082
      protocol      = "tcp"
      appProtocol   = "http"
    }] : [])

    environment = [for k, v in local.env[each.key] : { name = k, value = v }]
    secrets     = [for k, v in local.secrets[each.key] : { name = k, valueFrom = "${local.secret}:${v}::" }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = var.region
        awslogs-stream-prefix = each.key
      }
    }
  }])
}

# ── Services ─────────────────────────────────────────────────────────────────────

resource "aws_ecs_service" "service" {
  for_each = toset(local.services)

  name            = each.key
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.service[each.key].arn
  launch_type     = "FARGATE"
  desired_count   = each.key == "proxy" ? var.proxy_desired_count : 1

  # Rétablit un service dont la nouvelle version ne démarre pas.
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = contains(keys(local.web_services), each.key) ? [each.key] : []
    content {
      target_group_arn = aws_lb_target_group.service[each.key].arn
      container_name   = each.key
      container_port   = local.ports[each.key]
    }
  }

  # Migrations de la base au premier démarrage.
  health_check_grace_period_seconds = contains(keys(local.web_services), each.key) ? 60 : null

  # Appels internes : le recorder par l'administration (« recorder:8090 »), le service des
  # demandes d'accès du proxy par le portail (« proxy-internal:8082 »).
  service_connect_configuration {
    enabled = true

    dynamic "service" {
      for_each = each.key == "proxy" ? [1] : []
      content {
        port_name = "internal"
        client_alias {
          dns_name = "proxy-internal"
          port     = 8082
        }
      }
    }

    dynamic "service" {
      for_each = each.key == "recorder" ? [1] : []
      content {
        port_name = "recorder"
        client_alias {
          dns_name = "recorder"
          port     = 8090
        }
      }
    }
  }

  depends_on = [aws_lb_listener.https, aws_iam_role_policy.read_config]
}
