#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Vérifie que les kits de déploiement pointent sur la version courante du projet.

Les kits (Compose et Terraform) fixent la version des images au lieu d'utiliser ``latest`` :
avec ``latest``, la définition de tâche ECS ne change jamais et ``terraform apply`` ne
redéploie rien. Cette version doit donc être relevée à chaque release en même temps que
``Cargo.toml`` ; ce contrôle évite d'oublier un des fichiers.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# fichier -> motif dont le groupe 1 est la version fixée (sans « v » initial géré plus bas)
PINS = {
    "deploy/aws/variables.tf": r'variable "sesame_version" \{.*?default\s*=\s*"([^"]+)"',
    "deploy/release/.env.example": r"^SESAME_VERSION=(\S+)\s*$",
}


def main() -> int:
    cargo = (ROOT / "Cargo.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.M)
    if not m:
        print("Cargo.toml : version introuvable")
        return 1
    expected = f"v{m.group(1)}"
    errors = []
    for rel, pattern in PINS.items():
        found = re.search(pattern, (ROOT / rel).read_text(), re.S | re.M)
        value = found.group(1) if found else None
        if value != expected:
            errors.append(f"{rel} : version « {value} », attendue « {expected} » (Cargo.toml)")
    for error in errors:
        print(error)
    if not errors:
        print(f"Versions des kits : ok ({expected})")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
