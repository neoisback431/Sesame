# SPDX-License-Identifier: Apache-2.0
# Groupes de sécurité : ALB ← utilisateurs, tâches ECS ← ALB, base ← tâches ECS seulement.

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "Sesame : equilibreur de charge"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  ingress {
    description = "HTTP (redirection vers HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "tasks" {
  name        = "${var.name}-tasks"
  description = "Sesame : taches ECS"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Portail, proxy, administration depuis l'ALB"
    from_port       = 8000
    to_port         = 8081
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description = "Trafic interne (administration vers recorder, Service Connect)"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  # Sortie libre : applications internes, fournisseur d'identité, registre d'images.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name        = "${var.name}-db"
  description = "Sesame : base PostgreSQL"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL depuis les taches ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.tasks.id]
  }
}
