# SPDX-License-Identifier: Apache-2.0
"""Chargement et validation des descripteurs (schéma JSON du dépôt)."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

DEFAULT_SCHEMA = Path(__file__).resolve().parents[3] / "schemas" / "app-descriptor.schema.json"


class DescriptorError(ValueError):
    pass


@cache
def _validator(schema_file: Path) -> Draft202012Validator:
    return Draft202012Validator(json.loads(schema_file.read_text(encoding="utf-8")))


def validate(doc: Any, schema_file: Path = DEFAULT_SCHEMA) -> list[str]:
    errors = sorted(_validator(schema_file).iter_errors(doc), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(map(str, e.absolute_path)) or '(racine)'} : {e.message}" for e in errors]


def load(path: Path, schema_file: Path = DEFAULT_SCHEMA) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    errors = validate(doc, schema_file)
    if errors:
        raise DescriptorError(f"{path.name} : {errors[0]}")
    return doc


def load_dir(directory: Path, schema_file: Path = DEFAULT_SCHEMA) -> list[dict[str, Any]]:
    return [load(p, schema_file) for p in sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")])]
