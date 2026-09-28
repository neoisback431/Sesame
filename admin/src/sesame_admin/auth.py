# SPDX-License-Identifier: Apache-2.0
"""Authentification des administrateurs : OIDC (Authlib) ou SAML (python3-saml), un seul
protocole actif par déploiement (ADR 0024)."""

from __future__ import annotations

import ssl
from typing import Any, Protocol

from authlib.integrations.starlette_client import OAuth, OAuthError
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from .config import OidcSettings, SamlSettings


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


def _pem_body(pem: str) -> str:
    """Retire l'en-tête/pied PEM : `python3-saml` attend le corps base64 nu."""
    body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    if not body:
        raise AuthError("certificat IdP vide ou illisible")
    return body


def _saml_settings(cfg: SamlSettings, acs_url: str) -> dict[str, Any]:
    return {
        "strict": True,
        "sp": {
            "entityId": cfg.sp_entity_id,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        },
        "idp": {
            "entityId": cfg.idp_entity_id,
            "singleSignOnService": {
                "url": cfg.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": _pem_body(cfg.idp_cert_pem),
        },
        # wantAssertionsSigned est False par défaut dans python3-saml : jamais accepté tel
        # quel ici, la vérification de signature n'est pas facultative.
        "security": {
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "authnRequestsSigned": False,
            "rejectDeprecatedAlgorithm": True,
        },
    }


def _saml_request_data(request: Request, post: dict[str, str] | None = None) -> dict[str, Any]:
    url = request.url
    http_host = url.hostname or ""
    default_port = 443 if url.scheme == "https" else 80
    if url.port and url.port != default_port:
        http_host = f"{http_host}:{url.port}"
    return {
        "https": "on" if url.scheme == "https" else "off",
        "http_host": http_host,
        "script_name": url.path,
        "get_data": dict(request.query_params),
        "post_data": post or {},
    }


class SamlAuthenticator:
    """SAML 2.0 générique (SP-initiated, liaison Redirect/POST). L'anti-rejeu (identifiant de
    l'`AuthnRequest`) est porté par la session admin (cookie signé existant, comme `next` pour
    l'OIDC) : pas besoin d'encoder d'état dans `RelayState`."""

    def __init__(self, cfg: SamlSettings) -> None:
        self._cfg = cfg

    async def login_redirect(self, request: Request, redirect_uri: str) -> Response:
        settings = _saml_settings(self._cfg, redirect_uri)
        auth = OneLogin_Saml2_Auth(_saml_request_data(request), settings)
        url = auth.login()
        request.session["saml_request_id"] = auth.get_last_request_id()
        return RedirectResponse(url, status_code=302)

    async def callback(self, request: Request) -> dict[str, Any]:
        form = await request.form()
        post = {k: v for k, v in form.items() if isinstance(v, str)}
        redirect_uri = str(request.url).split("?", 1)[0]
        settings = _saml_settings(self._cfg, redirect_uri)
        auth = OneLogin_Saml2_Auth(_saml_request_data(request, post), settings)
        request_id = request.session.pop("saml_request_id", None)
        try:
            auth.process_response(request_id=request_id)
        except OneLogin_Saml2_Error as e:
            raise AuthError(f"saml_error:{e.code}") from None
        if auth.get_errors() or not auth.is_authenticated():
            # Détail (get_last_error_reason) jamais relayé : peut citer du contenu de l'assertion.
            raise AuthError("saml_error:" + ",".join(auth.get_errors() or ["not_authenticated"]))

        name_id = auth.get_nameid()
        if not name_id:
            raise AuthError("saml_error:missing_name_id")
        claims: dict[str, Any] = {"sub": name_id}
        for name, values in auth.get_attributes().items():
            if not values:
                continue
            claims[name] = values[0] if len(values) == 1 else list(values)
        if self._cfg.email_attribute:
            values = auth.get_attribute(self._cfg.email_attribute)
            if values:
                claims["email"] = values[0]
        return claims

    def metadata_xml(self, acs_url: str) -> str:
        """Métadonnées SP à déclarer chez l'IdP."""
        settings = OneLogin_Saml2_Settings(_saml_settings(self._cfg, acs_url), sp_validation_only=True)
        return settings.get_sp_metadata()
