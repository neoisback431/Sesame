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
class SamlSettings:
    """SAML 2.0 générique (SP-initiated). Pas de récupération dynamique d'un document de
    métadonnées IdP : tout vient de variables d'environnement (miroir de
    ``sesame_portal::config::SamlConfig``, ADR 0024)."""

    idp_entity_id: str
    idp_sso_url: str
    idp_cert_pem: str = field(repr=False)
    sp_entity_id: str
    user_key_attribute: str | None
    email_attribute: str | None
    groups_attribute: str | None


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
    # Recorder : service interne d'analyse d'une page de login. Fonctionnalité
    # activée seulement si l'URL et le jeton sont tous deux fournis.
    recorder_url: str | None
    recorder_token: str | None = field(repr=False)
    # Un seul protocole actif par déploiement : "oidc" ou "saml" (SESAME_IDP_PROTOCOL,
    # même défaut et même choix que le portail, ADR 0024). Le champ inactif est `None`.
    idp_protocol: str
    oidc: OidcSettings | None
    saml: SamlSettings | None
    # Coffre de secrets : "postgres" par défaut (ADR 0021, pas de brique externe
    # supplémentaire) ou "openbao" / "vault".
    secret_store: str
    secrets_encryption_key: str | None = field(repr=False)
    openbao: OpenBaoConfig | None

    @classmethod
    def from_env(cls) -> Settings:
        listen = _or("SESAME_ADMIN_LISTEN", "0.0.0.0:8000")
        host, _, port = listen.rpartition(":")
        ca = os.environ.get("SESAME_CA_FILE", "").strip()
        secret_store = _or("SESAME_SECRET_STORE", "postgres")
        if secret_store not in ("postgres", "openbao", "vault"):
            raise ConfigError(f"SESAME_SECRET_STORE inconnu : {secret_store}")
        idp_protocol = _or("SESAME_IDP_PROTOCOL", "oidc")
        oidc_settings: OidcSettings | None = None
        saml_settings: SamlSettings | None = None
        if idp_protocol == "oidc":
            oidc_settings = OidcSettings(
                issuer=_required("SESAME_OIDC_ISSUER").rstrip("/"),
                client_id=_required("SESAME_OIDC_CLIENT_ID"),
                client_secret=_required("SESAME_OIDC_CLIENT_SECRET"),
                scopes=_or("SESAME_OIDC_SCOPES", "openid profile email"),
                user_key_claim=_or("SESAME_OIDC_USER_KEY_CLAIM", "sub"),
                groups_claim=_or("SESAME_OIDC_GROUPS_CLAIM", "groups"),
            )
        elif idp_protocol == "saml":
            cert_file = _required("SESAME_SAML_IDP_CERT_FILE")
            try:
                idp_cert_pem = Path(cert_file).read_text()
            except OSError as e:
                raise ConfigError(f"SESAME_SAML_IDP_CERT_FILE ({cert_file}) : {e}") from e
            saml_settings = SamlSettings(
                idp_entity_id=_required("SESAME_SAML_IDP_ENTITY_ID"),
                idp_sso_url=_required("SESAME_SAML_IDP_SSO_URL"),
                idp_cert_pem=idp_cert_pem,
                sp_entity_id=_required("SESAME_SAML_SP_ENTITY_ID"),
                user_key_attribute=(os.environ.get("SESAME_SAML_USER_KEY_ATTRIBUTE", "").strip() or None),
                email_attribute=(os.environ.get("SESAME_SAML_EMAIL_ATTRIBUTE", "").strip() or None),
                groups_attribute=(os.environ.get("SESAME_SAML_GROUPS_ATTRIBUTE", "").strip() or None),
            )
        else:
            raise ConfigError(f"SESAME_IDP_PROTOCOL : « {idp_protocol} » inconnu (oidc, saml)")
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
            recorder_url=(os.environ.get("SESAME_RECORDER_URL", "").strip() or None),
            recorder_token=(os.environ.get("SESAME_RECORDER_TOKEN", "").strip() or None),
            idp_protocol=idp_protocol,
            oidc=oidc_settings,
            saml=saml_settings,
            secret_store=secret_store,
            secrets_encryption_key=(
                _required("SESAME_SECRETS_ENCRYPTION_KEY")
                if secret_store == "postgres"  # noqa: S105 (nom de la brique, pas un mot de passe)
                else None
            ),
            openbao=(
                OpenBaoConfig(
                    addr=_required("SESAME_OPENBAO_ADDR"),
                    mount=_or("SESAME_OPENBAO_MOUNT", "secret"),
                    path_prefix=_or("SESAME_OPENBAO_PATH_PREFIX", "sesame/apps"),
                    role_id=_required("SESAME_OPENBAO_ROLE_ID"),
                    secret_id=_required("SESAME_OPENBAO_SECRET_ID"),
                    namespace=os.environ.get("SESAME_OPENBAO_NAMESPACE") or None,
                )
                if secret_store in ("openbao", "vault")
                else None
            ),
        )
