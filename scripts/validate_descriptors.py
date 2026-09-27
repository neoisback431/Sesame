#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Valide les descripteurs d'appli contre schemas/app-descriptor.schema.json.

Usage : uv run scripts/validate_descriptors.py [fichiers...]
Sans argument, valide descriptors/*.yaml. Code de sortie non nul en cas d'erreur.
"""
# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema>=4.21", "pyyaml>=6"]
# ///

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schemas" / "app-descriptor.schema.json"


def main(argv: list[str]) -> int:
    validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    paths = [Path(a) for a in argv] or sorted((ROOT / "descriptors").glob("*.y*ml"))
    failed, ids = False, {}
    for path in paths:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
        for err in errors:
            location = "/".join(map(str, err.absolute_path)) or "(racine)"
            print(f"{path}: {location}: {err.message}", file=sys.stderr)
        app_id = (doc or {}).get("metadata", {}).get("id")
        if app_id in ids:
            print(f"{path}: metadata.id « {app_id} » déjà utilisé par {ids[app_id]}", file=sys.stderr)
            errors.append(None)
        ids[app_id] = path
        failed |= bool(errors)
        if not errors:
            print(f"{path}: ok")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
