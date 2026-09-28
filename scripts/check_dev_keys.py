#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Vérifie que les clés de chiffrement de dev (base64, 32 octets) déclarées dans les
fichiers Compose sont bien valides : une clé trop courte ou trop longue ne casse rien
au chargement (base64 accepte n'importe quelle longueur), seulement au démarrage du
service qui la lit (`CryptoError` / `InvalidKey`), et Nginx renvoie alors un 502.
"""

import base64
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Variables dont la valeur doit être 32 octets aléatoires encodés en base64
# (`CookieCipher::from_base64` côté Rust, `SecretCipher` côté Python).
KEY_VARS = re.compile(r"^\s*(SESAME_\w*(?:ENCRYPTION_KEY|STATE_KEY))\s*:\s*(\S+)\s*$")


def check(path: Path) -> list[str]:
    errors = []
    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        m = KEY_VARS.match(line)
        if not m:
            continue
        name, value = m.groups()
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception:
            errors.append(f"{path}:{lineno}: {name} n'est pas du base64 valide")
            continue
        if len(decoded) != 32:
            errors.append(f"{path}:{lineno}: {name} décode {len(decoded)} octets (32 attendus)")
    return errors


def main() -> int:
    errors = [e for f in ROOT.glob("docker-compose*.yml") for e in check(f)]
    for e in errors:
        print(e, file=sys.stderr)
    if errors:
        print(f"{len(errors)} clé(s) de dev invalide(s).", file=sys.stderr)
        return 1
    print("Clés de chiffrement de dev : ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
