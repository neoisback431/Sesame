# SPDX-License-Identifier: Apache-2.0
# Application Load Balancer : TLS (ACM) et routage par nom d'hôte, à la place de Nginx.
#   <domain>        → portail
#   admin.<domain>  → administration
#   *.<domain>      → moteur de proxy (une appli par nom d'hôte)

locals {
  create_certificate = var.certificate_arn == "" && var.route53_zone_id != ""
  certificate_arn    = local.create_certificate ? aws_acm_certificate_validation.this[0].certificate_arn : var.certificate_arn
}

# ── Certificat (si une zone Route 53 est fournie et aucun certificat) ────────────

resource "aws_acm_certificate" "this" {
  count                     = local.create_certificate ? 1 : 0
  domain_name               = var.domain
  subject_alternative_names = ["*.${var.domain}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = local.create_certificate ? {
    for dvo in aws_acm_certificate.this[0].domain_validation_options : dvo.domain_name => dvo
  } : {}

  zone_id = var.route53_zone_id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  records = [each.value.resource_record_value]
  ttl     = 300
  # <domain> et *.<domain> partagent le même enregistrement de validation.
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "this" {
  count                   = local.create_certificate ? 1 : 0
  certificate_arn         = aws_acm_certificate.this[0].arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}

# ── Équilibreur ──────────────────────────────────────────────────────────────────

resource "aws_lb" "this" {
  name                       = var.name
  internal                   = var.alb_internal
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = var.alb_subnet_ids
  drop_invalid_header_fields = true
  # L'analyse d'une page de login (recorder) peut dépasser la minute.
  idle_timeout = 120
}

resource "aws_lb_target_group" "service" {
  for_each = local.web_services

  name        = "${var.name}-${each.key}"
  port        = each.value.port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    path    = each.value.health_path
    matcher = "200"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service["proxy"].arn
  }

  lifecycle {
    precondition {
      condition     = var.certificate_arn != "" || var.route53_zone_id != ""
      error_message = "Renseignez route53_zone_id (certificat créé automatiquement) ou certificate_arn."
    }
  }
}

resource "aws_lb_listener_rule" "portal" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  condition {
    host_header {
      values = [var.domain]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service["portal"].arn
  }
}

resource "aws_lb_listener_rule" "admin" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 20

  condition {
    host_header {
      values = ["admin.${var.domain}"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service["admin"].arn
  }
}

# ── DNS (si une zone Route 53 est fournie) ───────────────────────────────────────

resource "aws_route53_record" "sesame" {
  for_each = var.route53_zone_id != "" ? toset([var.domain, "*.${var.domain}"]) : toset([])

  zone_id = var.route53_zone_id
  name    = each.value
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = false
  }
}
