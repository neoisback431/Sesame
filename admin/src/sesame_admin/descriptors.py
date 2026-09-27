# SPDX-License-Identifier: Apache-2.0
"""Descripteurs d'applis : fichiers YAML versionnés (lecture seule) et documents en base.

Le schéma JSON fait foi pour la structure ; ``DescriptorValidator.check`` y ajoute
les contrôles de ``AppDescriptor::validate`` (Rust) pour qu'un descripteur accepté
ici ne soit pas écarté ensuite par le portail ou le proxy. La fusion fichiers + base
suit les mêmes règles que ``sesame_core::sources``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .ports import StoredDescriptor

MAX_DOCUMENT_BYTES = 64 * 1024
# Identifiants réservés par les routes de l'administration (/apps/new).
RESERVED_IDS = frozenset({"new"})

# Constructions acceptées par le module re de Python mais refusées par la crate regex
# (moteur du proxy) : références arrière et assertions de voisinage.
_UNSUPPORTED_REGEX = re.compile(r"\\[1-9]|\\k<|\(\?P=|\(\?<?[=!]")
_DURATION = re.compile(r"^([0-9]+)(s|m|h)$")


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
    source: str  # YAML affiché tel quel (ne contient aucun secret)
    origin: str = "file"  # "file" (Git, lecture seule) ou "db" (créé dans l'administration)
    updated_at: datetime | None = None
    updated_by: str | None = None

    @property
    def editable(self) -> bool:
        return self.origin == "db"

    @property
    def access_open(self) -> bool:
        """Aucune restriction d'habilitation : le compte actif fait foi."""
        return not self.groups and not self.users

    def allows(self, user_key: str, groups: tuple[str, ...]) -> bool:
        return self.access_open or user_key in self.users or any(g in self.groups for g in groups)


@dataclass(frozen=True)
class Rejected:
    """Descripteur en base écarté du catalogue (le portail et le proxy l'ignorent aussi)."""

    stored: StoredDescriptor
    reason: str


@dataclass(frozen=True)
class Catalog:
    apps: dict[str, App]
    rejected: list[Rejected]


def _regex_error(pattern: Any) -> str | None:
    if not isinstance(pattern, str):
        return None  # déjà signalé par le schéma
    if _UNSUPPORTED_REGEX.search(pattern):
        return f"regex « {pattern} » : références arrière et assertions de voisinage non prises en charge"
    try:
        re.compile(pattern)
    except re.error as e:
        return f"regex « {pattern} » : {e}"
    return None


class DescriptorValidator:
    def __init__(self, schema_file: Path) -> None:
        self.schema: dict[str, Any] = json.loads(schema_file.read_text(encoding="utf-8"))
        self._validator = Draft202012Validator(self.schema)

    def check(self, doc: Any) -> list[str]:
        """Erreurs lisibles (vide si le descripteur est valide). Jamais de valeur de secret :
        un descripteur n'en contient pas."""
        errors = sorted(self._validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
        if errors:
            return [f"{'/'.join(map(str, e.absolute_path)) or '(racine)'} : {e.message}" for e in errors]
        return _semantic_errors(doc)

    def ordered(self, doc: Any) -> Any:
        """Document dont les clés suivent l'ordre du schéma (le stockage JSONB ne le conserve pas)."""
        return _ordered(doc, self.schema, self.schema)

    def to_yaml(self, doc: Any) -> str:
        return yaml.safe_dump(
            self.ordered(doc), sort_keys=False, allow_unicode=True, default_flow_style=False, width=100
        )


def _semantic_errors(doc: dict[str, Any]) -> list[str]:
    """Contrôles de ``AppDescriptor::validate`` non exprimables dans le schéma."""
    spec = doc["spec"]
    errors: list[str] = []
    keys = spec["credentials"]["keys"]
    login = spec["login"]
    for name, field in login["fields"].items():
        key = field.get("from_secret")
        if key is not None and key not in keys:
            errors.append(f"spec/login/fields/{name} : référence la clé inconnue « {key} »")
    for token in login.get("csrf", []):
        if token["source"] == "regex":
            if "pattern" not in token:
                errors.append(f"spec/login/csrf : pattern requis pour source=regex ({token['name']})")
            elif err := _regex_error(token["pattern"]):
                errors.append(f"spec/login/csrf : {err}")
    patterns: list[Any] = list(spec.get("logout", {}).get("paths", []))
    for where, matcher_set in (
        ("login/success", login["success"]),
        ("login/failure", login.get("failure")),
        ("expiry", spec["expiry"]),
    ):
        if matcher_set is None:
            continue
        if not matcher_set["any_of"]:
            errors.append(f"spec/{where} : any_of vide")
        for m in matcher_set["any_of"]:
            patterns += [m[k] for k in ("location_matches", "location_not_matches") if k in m]
    errors += [err for p in patterns if (err := _regex_error(p))]
    if not spec["session"]["cookies"]:
        errors.append("spec/session/cookies : vide")
    for where, value in _durations(spec):
        m = _DURATION.fullmatch(value)
        if m and int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)] >= 2**64:
            errors.append(f"spec/{where} : durée invalide")
    if doc["metadata"]["id"] in RESERVED_IDS:
        errors.append(f"metadata/id : « {doc['metadata']['id']} » est réservé")
    return errors


def _durations(spec: dict[str, Any]) -> Iterable[tuple[str, str]]:
    for section, key in (
        ("upstream", "timeout"),
        ("session", "max_ttl"),
        ("session", "idle_ttl"),
        ("health", "interval"),
    ):
        value = spec.get(section, {}).get(key)
        if isinstance(value, str):
            yield f"{section}/{key}", value


def _resolve(node: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in node:
        target: Any = root
        for part in node["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        node = {**target, **{k: v for k, v in node.items() if k != "$ref"}}
    return node


def _ordered(doc: Any, node: Any, root: dict[str, Any]) -> Any:
    if not isinstance(node, dict):
        return doc
    node = _resolve(node, root)
    if isinstance(doc, dict):
        props: dict[str, Any] = node.get("properties", {})
        extra = node.get("additionalProperties")
        out: dict[str, Any] = {}
        for key in [*[k for k in props if k in doc], *[k for k in doc if k not in props]]:
            out[key] = _ordered(doc[key], props.get(key, extra), root)
        return out
    if isinstance(doc, list):
        return [_ordered(item, node.get("items"), root) for item in doc]
    return doc


def parse_yaml(text: str) -> dict[str, Any]:
    """YAML saisi dans l'éditeur → document. Les alias YAML sont refusés (pas d'expansion)."""
    if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise DescriptorError(f"descripteur trop volumineux (maximum {MAX_DOCUMENT_BYTES // 1024} Kio)")
    try:
        events = list(yaml.parse(text, Loader=yaml.SafeLoader))
        if any(isinstance(e, yaml.AliasEvent) for e in events):
            raise DescriptorError("les alias YAML (*nom) ne sont pas acceptés")
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        where = f" (ligne {mark.line + 1}, colonne {mark.column + 1})" if mark else ""
        raise DescriptorError(f"syntaxe YAML invalide{where}") from None
    if not isinstance(doc, dict):
        raise DescriptorError("le descripteur doit être un objet YAML")
    return doc


def app_from_doc(
    doc: dict[str, Any],
    source: str,
    origin: str = "file",
    updated_at: datetime | None = None,
    updated_by: str | None = None,
) -> App:
    meta, spec = doc["metadata"], doc["spec"]
    return App(
        id=meta["id"],
        name=meta["name"],
        description=meta.get("description"),
        public_host=spec["public"]["host"],
        groups=tuple(spec.get("access", {}).get("groups", [])),
        users=tuple(spec.get("access", {}).get("users", [])),
        credential_keys=tuple(spec["credentials"]["keys"]),
        revision=meta["revision"],
        source=source,
        origin=origin,
        updated_at=updated_at,
        updated_by=updated_by,
    )


def load_dir(directory: Path, schema_file: Path) -> dict[str, App]:
    validator = DescriptorValidator(schema_file)
    apps: dict[str, App] = {}
    hosts: set[str] = set()
    for path in sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")]):
        source = path.read_text(encoding="utf-8")
        doc: Any = yaml.safe_load(source)
        errors = validator.check(doc)
        if errors:
            raise DescriptorError(f"{path.name} : {errors[0]}")
        app = app_from_doc(doc, source)
        if app.id in apps or app.public_host in hosts:
            raise DescriptorError(f"{path.name} : id ou hôte public en double")
        apps[app.id] = app
        hosts.add(app.public_host)
    return apps


def merge(files: dict[str, App], stored: list[StoredDescriptor], validator: DescriptorValidator) -> Catalog:
    """Fichiers d'abord, puis base dans l'ordre des identifiants (comme ``sesame_core::sources``)."""
    apps = dict(files)
    hosts = {a.public_host for a in files.values()}
    rejected: list[Rejected] = []
    for s in sorted(stored, key=lambda s: s.app_id):
        errors = validator.check(s.document)
        if errors:
            rejected.append(Rejected(s, errors[0]))
            continue
        app = app_from_doc(s.document, validator.to_yaml(s.document), "db", s.updated_at, s.updated_by)
        if app.id != s.app_id:
            rejected.append(Rejected(s, "metadata.id différent de la clé"))
        elif app.id in apps:
            rejected.append(Rejected(s, "identifiant déjà utilisé"))
        elif app.public_host in hosts:
            rejected.append(Rejected(s, "hôte public déjà utilisé"))
        else:
            apps[app.id] = app
            hosts.add(app.public_host)
    return Catalog(apps, rejected)


def _regex_literal(text: str) -> str:
    """Échappement compris à l'identique par re (Python) et la crate regex (Rust)."""
    return re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", text)


def draft(form: dict[str, str]) -> dict[str, Any]:
    """Premier jet de descripteur à partir du formulaire guidé, à relire dans l'éditeur."""

    def words(name: str) -> list[str]:
        return [w for w in re.split(r"[\s,]+", form.get(name, "")) if w]

    get = lambda name, default="": form.get(name, "").strip() or default  # noqa: E731
    base_url = get("base_url").rstrip("/")
    form_url = get("form_url", "/login")
    cookie = get("session_cookie", "SESSIONID")
    metadata: dict[str, Any] = {"id": get("id"), "name": get("name"), "revision": 1}
    if get("description"):
        metadata["description"] = get("description")
    if get("owner"):
        metadata["owner"] = get("owner")
    access: dict[str, Any] = {}
    if words("groups"):
        access["groups"] = words("groups")
    if words("users"):
        access["users"] = words("users")
    login: dict[str, Any] = {
        "form_url": form_url,
        "form_selector": get("form_selector", "form"),
        "fields": {
            get("username_field", "username"): {"from_secret": "username"},
            get("password_field", "password"): {"from_secret": "password"},
        },
    }
    if get("csrf_field"):
        login["csrf"] = [{"source": "hidden_input", "name": get("csrf_field")}]
    login["success"] = {
        "any_of": [
            {
                "status": [302, 303],
                "location_not_matches": "^" + _regex_literal(form_url),
                "cookie_set": cookie,
            }
        ]
    }
    if get("failure_text"):
        login["failure"] = {"any_of": [{"body_contains": get("failure_text")}]}
    return {
        "apiVersion": "sesame/v1",
        "kind": "AppDescriptor",
        "metadata": metadata,
        "spec": {
            "upstream": {"base_url": base_url},
            "public": {"host": get("public_host").lower()},
            # access omis => tout utilisateur avec un compte actif est autorisé.
            **({"access": access} if access else {}),
            "credentials": {"mode": "per_user", "keys": ["username", "password"]},
            "login": login,
            "session": {"cookies": [cookie]},
            "expiry": {
                "any_of": [
                    {
                        "status": [302, 303],
                        "location_matches": f"^({_regex_literal(base_url)})?{_regex_literal(form_url)}",
                    },
                    {"status": [401]},
                ]
            },
            "logout": {"paths": ["^/logout$"]},
            "health": {"interval": "1h"},
        },
    }
