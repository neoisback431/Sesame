# SPDX-License-Identifier: Apache-2.0
"""Descripteurs d'applis : fichiers YAML versionnés, validés par le schéma JSON (lecture seule)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator


class DescriptorError(ValueError):
    pass


@dataclass(frozen=True)
class App:
    id: str
    name: str
    description: str | None
    public_host: str
    groups: tuple[str, ...]
    users: tuple[str, ...]
    credential_keys: tuple[str, ...]
    revision: int
    source: str  # YAML d'origine, affiché tel quel (ne contient aucun secret)

    def allows(self, user_key: str, groups: tuple[str, ...]) -> bool:
        return user_key in self.users or any(g in self.groups for g in groups)


def load_dir(directory: Path, schema_file: Path) -> dict[str, App]:
    validator = Draft202012Validator(json.loads(schema_file.read_text(encoding="utf-8")))
    apps: dict[str, App] = {}
    hosts: set[str] = set()
    for path in sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")]):
        source = path.read_text(encoding="utf-8")
        doc: Any = yaml.safe_load(source)
        errors = list(validator.iter_errors(doc))
        if errors:
            raise DescriptorError(f"{path.name} : {errors[0].message}")
        meta, spec = doc["metadata"], doc["spec"]
        app = App(
            id=meta["id"],
            name=meta["name"],
            description=meta.get("description"),
            public_host=spec["public"]["host"],
            groups=tuple(spec["access"].get("groups", [])),
            users=tuple(spec["access"].get("users", [])),
            credential_keys=tuple(spec["credentials"]["keys"]),
            revision=meta["revision"],
            source=source,
        )
        if app.id in apps or app.public_host in hosts:
            raise DescriptorError(f"{path.name} : id ou hôte public en double")
        apps[app.id] = app
        hosts.add(app.public_host)
    return apps
