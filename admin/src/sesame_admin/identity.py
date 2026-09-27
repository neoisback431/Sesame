# SPDX-License-Identifier: Apache-2.0
"""Identité issue des claims OIDC (mapping configurable) et validation des clés utilisateur."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Mêmes règles que sesame_core::identity::validate_user_key.
_USER_KEY = re.compile(r"^[A-Za-z0-9@._+-]{1,256}$")


def valid_user_key(key: str) -> bool:
    return bool(_USER_KEY.fullmatch(key)) and key not in {".", ".."}


@dataclass(frozen=True)
class AdminUser:
    issuer: str
    subject: str
    user_key: str
    display_name: str | None
    groups: tuple[str, ...]

    @property
    def actor(self) -> str:
        return f"{self.issuer}|{self.subject}"


class ClaimsError(ValueError):
    pass


def identity_from_claims(
    claims: dict[str, Any], issuer: str, user_key_claim: str, groups_claim: str
) -> AdminUser:
    sub = claims.get("sub")
    key = claims.get(user_key_claim)
    if not isinstance(sub, str) or not sub:
        raise ClaimsError("sub absent")
    if not isinstance(key, str) or not valid_user_key(key):
        raise ClaimsError(f"claim {user_key_claim} absent ou invalide")
    raw = claims.get(groups_claim)
    if raw is None:
        groups: tuple[str, ...] = ()
    elif isinstance(raw, str):
        groups = (raw,)
    elif isinstance(raw, list):
        groups = tuple(g for g in raw if isinstance(g, str))
    else:
        raise ClaimsError(f"claim {groups_claim} de type inattendu")
    name = claims.get("name") or claims.get("email") or claims.get("preferred_username")
    return AdminUser(
        issuer=str(claims.get("iss") or issuer),
        subject=sub,
        user_key=key,
        display_name=name if isinstance(name, str) else None,
        groups=groups,
    )
