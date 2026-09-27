# SPDX-License-Identifier: Apache-2.0
"""Authentification OIDC des administrateurs (Authlib : discovery, code + PKCE, nonce)."""

from __future__ import annotations

import ssl
from typing import Any, Protocol

from authlib.integrations.starlette_client import OAuth, OAuthError
from starlette.requests import Request
from starlette.responses import Response

from .config import OidcSettings


class AuthError(RuntimeError):
    pass


class Authenticator(Protocol):
    async def login_redirect(self, request: Request, redirect_uri: str) -> Response: ...

    async def callback(self, request: Request) -> dict[str, Any]:
        """Claims de l'ID token vérifié (signature, iss, aud, exp, nonce)."""
        ...


class OidcAuthenticator:
    def __init__(self, cfg: OidcSettings, ca_file: str | None = None) -> None:
        verify: ssl.SSLContext | bool = True
        if ca_file:
            verify = ssl.create_default_context()
            verify.load_verify_locations(cafile=ca_file)
        self._oauth = OAuth()
        self._oauth.register(
            name="sesame",
            server_metadata_url=f"{cfg.issuer}/.well-known/openid-configuration",
            client_id=cfg.client_id,
            client_secret=cfg.client_secret,
            client_kwargs={"scope": cfg.scopes, "code_challenge_method": "S256", "verify": verify},
        )

    async def login_redirect(self, request: Request, redirect_uri: str) -> Response:
        return await self._oauth.sesame.authorize_redirect(request, redirect_uri)

    async def callback(self, request: Request) -> dict[str, Any]:
        try:
            token = await self._oauth.sesame.authorize_access_token(request)
        except OAuthError as e:
            raise AuthError(e.error or "oidc_error") from None
        claims = token.get("userinfo")
        if not claims:
            raise AuthError("id_token absent")
        return dict(claims)
