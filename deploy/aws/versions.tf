# SPDX-License-Identifier: Apache-2.0
# Compatible Terraform et OpenTofu.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # L'état contient les clés générées et le mot de passe de la base : stockez-le dans un
  # backend chiffré à accès restreint, par exemple S3 (voir README.md).
  # backend "s3" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = merge({ Application = "sesame" }, var.tags)
  }
}
