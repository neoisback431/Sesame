# SPDX-License-Identifier: Apache-2.0
"""SamlAuthenticator : signature obligatoire (jamais désactivable), extraction de l'identité,
rejet d'une assertion altérée ou signée par une clé non fiable."""

import base64
import datetime
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from sesame_admin.auth import AuthError, SamlAuthenticator, _pem_body, _saml_settings
from sesame_admin.config import SamlSettings
from starlette.requests import Request

ACS_URL = "https://admin.sesame.example/auth/callback"
SP_ENTITY_ID = "https://admin.sesame.example/saml/metadata"
IDP_ENTITY_ID = "https://idp.example/saml"


def make_request(method: str = "GET", body: bytes = b"", query: str = "") -> Request:
    scope = {
        "type": "http",
        "method": method,
        "scheme": "https",
        "server": ("admin.sesame.example", 443),
        "path": "/auth/callback",
        "query_string": query.encode(),
        "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
        "session": {},
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def generate_idp_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sesame-test-idp")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def signed_response(
    key_pem: str,
    cert_pem: str,
    *,
    name_id: str,
    request_id: str,
    audience: str = SP_ENTITY_ID,
    attributes: dict[str, str] | None = None,
) -> str:
    """Assertion signée seule (comme un IdP réel), intégrée dans une réponse non signée :
    `wantAssertionsSigned` vérifie la signature sur l'assertion, pas sur la réponse."""
    now = datetime.datetime.now(datetime.UTC)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    not_before = (now - datetime.timedelta(minutes=1)).strftime(fmt)
    not_on_or_after = (now + datetime.timedelta(minutes=5)).strftime(fmt)
    assertion_id = "_" + OneLogin_Saml2_Utils.generate_unique_id()
    attrs_xml = "".join(
        f'<saml:Attribute Name="{name}"><saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>'
        for name, value in (attributes or {}).items()
    )
    assertion_xml = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{assertion_id}" Version="2.0" IssueInstant="{now.strftime(fmt)}">
  <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified">{name_id}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{ACS_URL}"
        InResponseTo="{request_id}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
    <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{now.strftime(fmt)}">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>{attrs_xml}</saml:AttributeStatement>
</saml:Assertion>"""
    signed_assertion = OneLogin_Saml2_Utils.add_sign(assertion_xml, key_pem, cert_pem)
    if isinstance(signed_assertion, bytes):
        signed_assertion = signed_assertion.decode()
    response_id = "_" + OneLogin_Saml2_Utils.generate_unique_id()
    response_xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0"
    IssueInstant="{now.strftime(fmt)}" Destination="{ACS_URL}" InResponseTo="{request_id}">
  <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  {signed_assertion}
</samlp:Response>"""
    return base64.b64encode(response_xml.encode()).decode()


@pytest.fixture
def idp_keypair():
    return generate_idp_cert()


def settings(cert_pem: str) -> SamlSettings:
    return SamlSettings(
        idp_entity_id=IDP_ENTITY_ID,
        idp_sso_url="https://idp.example/saml/sso",
        idp_cert_pem=cert_pem,
        sp_entity_id=SP_ENTITY_ID,
        user_key_attribute=None,
        email_attribute="email",
        groups_attribute="groups",
    )


async def run_callback(authenticator: SamlAuthenticator, body: str, request_id: str) -> dict:
    encoded = "SAMLResponse=" + body.replace("+", "%2B").replace("=", "%3D").replace("/", "%2F")
    request = make_request(method="POST", body=encoded.encode())
    request.session["saml_request_id"] = request_id
    return await authenticator.callback(request)


def test_saml_settings_always_forces_assertions_signed(idp_keypair):
    _, cert_pem = idp_keypair
    s = _saml_settings(settings(cert_pem), ACS_URL)
    assert s["security"]["wantAssertionsSigned"] is True
    assert s["sp"]["entityId"] == SP_ENTITY_ID
    assert s["idp"]["singleSignOnService"]["url"] == "https://idp.example/saml/sso"


def test_pem_body_strips_headers_and_rejects_empty():
    assert _pem_body("-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n") == "ABC"
    assert _pem_body("ABC") == "ABC"
    with pytest.raises(AuthError):
        _pem_body("")


@pytest.mark.asyncio
async def test_accepts_a_correctly_signed_assertion_and_maps_attributes(idp_keypair):
    key_pem, cert_pem = idp_keypair
    auth = SamlAuthenticator(settings(cert_pem))
    body = signed_response(
        key_pem, cert_pem, name_id="alice", request_id="_req-1", attributes={"email": "alice@example.org"}
    )
    claims = await run_callback(auth, body, "_req-1")
    assert claims["sub"] == "alice"
    assert claims["email"] == "alice@example.org"


@pytest.mark.asyncio
async def test_rejects_a_response_signed_by_an_untrusted_key(idp_keypair):
    _, cert_pem = idp_keypair
    other_key_pem, other_cert_pem = generate_idp_cert()
    auth = SamlAuthenticator(settings(cert_pem))
    body = signed_response(other_key_pem, other_cert_pem, name_id="alice", request_id="_req-1")
    with pytest.raises(AuthError):
        await run_callback(auth, body, "_req-1")


@pytest.mark.asyncio
async def test_rejects_a_replayed_response_with_a_different_pending_request_id(idp_keypair):
    key_pem, cert_pem = idp_keypair
    auth = SamlAuthenticator(settings(cert_pem))
    body = signed_response(key_pem, cert_pem, name_id="alice", request_id="_req-1")
    with pytest.raises(AuthError):
        await run_callback(auth, body, "_req-2")


@pytest.mark.asyncio
async def test_rejects_a_response_for_a_different_audience(idp_keypair):
    key_pem, cert_pem = idp_keypair
    auth = SamlAuthenticator(settings(cert_pem))
    body = signed_response(
        key_pem, cert_pem, name_id="alice", request_id="_req-1", audience="https://other-sp.example"
    )
    with pytest.raises(AuthError):
        await run_callback(auth, body, "_req-1")


@pytest.mark.asyncio
async def test_rejects_a_tampered_assertion(idp_keypair):
    key_pem, cert_pem = idp_keypair
    auth = SamlAuthenticator(settings(cert_pem))
    body = signed_response(key_pem, cert_pem, name_id="alice", request_id="_req-1")
    xml = base64.b64decode(body).decode()
    xml = xml.replace(">alice<", ">mallory<", 1)
    tampered = base64.b64encode(xml.encode()).decode()
    with pytest.raises(AuthError):
        await run_callback(auth, tampered, "_req-1")


@pytest.mark.asyncio
async def test_login_redirect_builds_idp_url_and_stores_request_id(idp_keypair):
    _, cert_pem = idp_keypair
    auth = SamlAuthenticator(settings(cert_pem))
    request = make_request(method="GET")
    resp = await auth.login_redirect(request, ACS_URL)
    location = resp.headers["location"]
    assert location.startswith("https://idp.example/saml/sso")
    query = parse_qs(urlsplit(location).query)
    assert "SAMLRequest" in query
    assert request.session["saml_request_id"]
