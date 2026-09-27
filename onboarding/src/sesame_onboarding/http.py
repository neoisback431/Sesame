# SPDX-License-Identifier: Apache-2.0
"""Accès HTTP « à la manière du proxy » : pas de JavaScript, jar de cookies par nom,
redirections suivies seulement dans l'origine de l'appli."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

MAX_REDIRECTS = 5


def origin(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return parts.scheme, parts.netloc


def same_origin(a: str, b: str) -> bool:
    return origin(a) == origin(b)


@dataclass
class Jar:
    cookies: dict[str, str] = field(default_factory=dict)

    def apply(self, set_cookies: list[str]) -> list[str]:
        """Applique des ``Set-Cookie`` ; renvoie les noms touchés."""
        names = []
        for raw in set_cookies:
            first, _, attrs = raw.partition(";")
            name, sep, value = first.partition("=")
            name = name.strip()
            if not sep or not name:
                continue
            names.append(name)
            lower = attrs.lower().replace(" ", "")
            if "max-age=0" in lower or "expires=thu,01jan1970" in lower:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value.strip()
        return names

    def header(self) -> str | None:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items()) or None

    def __repr__(self) -> str:  # valeurs de cookies jamais affichées
        return f"Jar(names={sorted(self.cookies)})"


def set_cookies(resp: httpx.Response) -> list[str]:
    return resp.headers.get_list("set-cookie")


def get_page(client: httpx.Client, url: str, base: str, jar: Jar) -> tuple[httpx.Response, str]:
    """GET en suivant les redirections de même origine. Renvoie (réponse, URL finale)."""
    resp = client.get(url, headers=_cookie(jar))
    for _ in range(MAX_REDIRECTS):
        jar.apply(set_cookies(resp))
        if not resp.is_redirect:
            break
        nxt = urljoin(url, resp.headers.get("location", ""))
        if not same_origin(nxt, base):
            raise ValueError("la page de login redirige hors de l'appli")
        url = nxt
        resp = client.get(url, headers=_cookie(jar))
    return resp, url


def _cookie(jar: Jar) -> dict[str, str]:
    h = jar.header()
    return {"cookie": h} if h else {}
