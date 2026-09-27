# SPDX-License-Identifier: Apache-2.0
"""Configuration de l'UI d'administration (variables d'environnement ``SESAME_*``)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .openbao import OpenBaoConfig


class ConfigError(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"variable {name} requise")
    return value


def _or(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


@dataclass(frozen=True)
class OidcSettings:
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    scopes: str
    user_key_claim: str
    groups_claim: str


@dataclass(frozen=True)
class Settings:
    listen_host: str
    listen_port: int
    public_url: str
    session_key: str = field(repr=False)
    session_ttl_secs: int
    admin_group: str
    descriptors_dir: Path
    schema_file: Path
    database_url: str = field(repr=False)
    ca_file: Path | None
    oidc: OidcSettings
    openbao: OpenBaoConfig

    @classmethod
    def from_env(cls) -> Settings:
        listen = _or("SESAME_ADMIN_LISTEN", "0.0.0.0:8000")
        host, _, port = listen.rpartition(":")
        ca = os.environ.get("SESAME_CA_FILE", "").strip()
        return cls(
            listen_host=host,
            listen_port=int(port),
            public_url=_required("SESAME_ADMIN_PUBLIC_URL").rstrip("/"),
            session_key=_required("SESAME_ADMIN_SESSION_KEY"),
            session_ttl_secs=int(_or("SESAME_ADMIN_SESSION_TTL_SECS", "3600")),
            admin_group=_or("SESAME_ADMIN_GROUP", "sesame-admins"),
            descriptors_dir=Path(_or("SESAME_DESCRIPTORS_DIR", "descriptors")),
            schema_file=Path(_or("SESAME_SCHEMA_FILE", "schemas/app-descriptor.schema.json")),
            database_url=_required("SESAME_DATABASE_URL"),
            ca_file=Path(ca) if ca else None,
            oidc=OidcSettings(
                issuer=_required("SESAME_OIDC_ISSUER").rstrip("/"),
                client_id=_required("SESAME_OIDC_CLIENT_ID"),
                client_secret=_required("SESAME_OIDC_CLIENT_SECRET"),
                scopes=_or("SESAME_OIDC_SCOPES", "openid profile email"),
                user_key_claim=_or("SESAME_OIDC_USER_KEY_CLAIM", "sub"),
                groups_claim=_or("SESAME_OIDC_GROUPS_CLAIM", "groups"),
            ),
            openbao=OpenBaoConfig(
                addr=_required("SESAME_OPENBAO_ADDR"),
                mount=_or("SESAME_OPENBAO_MOUNT", "secret"),
                path_prefix=_or("SESAME_OPENBAO_PATH_PREFIX", "sesame/apps"),
                role_id=_required("SESAME_OPENBAO_ROLE_ID"),
                secret_id=_required("SESAME_OPENBAO_SECRET_ID"),
                namespace=os.environ.get("SESAME_OPENBAO_NAMESPACE") or None,
            ),
        )
