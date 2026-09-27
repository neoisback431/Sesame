# SPDX-License-Identifier: Apache-2.0
"""Vérification d'un descripteur : rejeu du login sans JavaScript, comme le moteur de proxy.

Les identifiants du compte de test ne vivent qu'en mémoire le temps de l'appel.
Le résultat ne contient ni valeur saisie ni valeur de cookie.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from .fingerprint import input_value, meta_content, parse_form
from .http import Jar, get_page, same_origin, set_cookies
from .matcher import ResponseView, any_of


@dataclass
class VerifyResult:
    ok: bool
    reason: str
    status: int | None = None
    location: str | None = None
    cookies_set: list[str] = field(default_factory=list)
    fingerprint: str | None = None


def _csrf_value(token: dict[str, Any], html: str, jar: Jar) -> str | None:
    source, name = token["source"], token["name"]
    if source == "hidden_input":
        return input_value(html, name)
    if source == "meta":
        return meta_content(html, name)
    if source == "cookie":
        return jar.cookies.get(name)
    m = re.search(token["pattern"], html)
    return m.group(1) if m and m.groups() else None


def verify(descriptor: dict[str, Any], credentials: dict[str, str], client: httpx.Client) -> VerifyResult:
    spec = descriptor["spec"]
    login = spec["login"]
    base = spec["upstream"]["base_url"].rstrip("/") + "/"
    jar = Jar()
    try:
        resp, page_url = get_page(client, urljoin(base, login["form_url"]), base, jar)
    except ValueError:
        return VerifyResult(False, "login_page_redirects_away")
    except httpx.HTTPError as e:
        return VerifyResult(False, f"unreachable ({type(e).__name__})")
    if resp.status_code != 200:
        return VerifyResult(False, "login_page_status", status=resp.status_code)
    html = resp.text

    form = parse_form(html, login.get("form_selector", "form"))
    if form is None:
        return VerifyResult(False, "login_form_not_found_in_raw_html")
    action = urljoin(page_url, login.get("action") or form.action or page_url)
    if not same_origin(action, base):
        return VerifyResult(False, "login_action_foreign_origin")

    fields: dict[str, str] = {}
    if login.get("include_hidden_inputs", True):
        fields.update(dict(form.hidden))
    for name, spec_field in login["fields"].items():
        if "from_secret" in spec_field:
            if spec_field["from_secret"] not in credentials:
                return VerifyResult(False, "secret_key_missing")
            fields[name] = credentials[spec_field["from_secret"]]
        else:
            fields[name] = spec_field["value"]
    headers = {"referer": page_url, "origin": base.rstrip("/"), **login.get("extra_headers", {})}
    for token in login.get("csrf", []):
        value = _csrf_value(token, html, jar)
        if value is None:
            return VerifyResult(False, "csrf_token_not_found")
        send_as = token.get("send_as", {})
        if "header" in send_as:
            headers[send_as["header"]] = value
        else:
            fields[send_as.get("field", token["name"])] = value
    if jar.header():
        headers["cookie"] = jar.header()

    method = login.get("method", "POST")
    try:
        if method == "GET":
            resp = client.get(action, params=fields, headers=headers)
        elif login.get("encoding", "form") == "json":
            json_headers = {**headers, "content-type": "application/json"}
            resp = client.post(action, content=json.dumps(fields), headers=json_headers)
        else:
            resp = client.post(action, data=fields, headers=headers)
    except httpx.HTTPError as e:
        return VerifyResult(False, f"unreachable ({type(e).__name__})")
    finally:
        fields.clear()

    names = jar.apply(set_cookies(resp))
    view = ResponseView(resp.status_code, resp.headers.get("location"), tuple(names), resp.text)
    result = VerifyResult(
        ok=False,
        reason="",
        status=resp.status_code,
        location=view.location,
        cookies_set=names,
        fingerprint=form.fingerprint(),
    )
    if any_of(login.get("failure"), view):
        result.reason = "login_rejected"
    elif not any_of(login["success"], view):
        result.reason = "login_unexpected_response"
    elif not all(c in jar.cookies for c in spec["session"]["cookies"]):
        result.reason = "session_cookie_missing"
    else:
        result.ok, result.reason = True, "ok"
    return result
