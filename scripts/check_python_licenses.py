#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Vérifie que les dépendances Python d'un projet ont une licence compatible Apache-2.0.

Usage (depuis un projet uv) : uv run --with pip-licenses python ../scripts/check_python_licenses.py
"""

from __future__ import annotations

import json
import subprocess
import sys

ALLOWED = (
    "MIT",
    "BSD",
    "Apache",
    "ISC",
    "MPL",
    "Mozilla Public License",
    "PSF",
    "Python Software Foundation",
    "Unlicense",
    "CC0",
    "Zlib",
)
DENIED = ("GPL", "AGPL", "LGPL", "SSPL", "BUSL", "Commons Clause")


def main() -> int:
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "piplicenses",
            "--format=json",
            "--ignore-packages",
            "pip-licenses",
            "prettytable",
            "wcwidth",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    bad = []
    for pkg in json.loads(out):
        lic = pkg["License"]
        allowed = any(a.lower() in lic.lower() for a in ALLOWED)
        denied = any(d.lower() in lic.lower() for d in DENIED)
        if denied or not allowed:
            bad.append(f"{pkg['Name']} {pkg['Version']} : {lic}")
    for line in bad:
        print(f"licence non autorisée : {line}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
