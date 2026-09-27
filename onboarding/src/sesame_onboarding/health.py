# SPDX-License-Identifier: Apache-2.0
"""Test de santé périodique : le formulaire de login a-t-il changé ?

Sans identifiants : récupère la page de login (HTML brut), en calcule l'empreinte
et la compare à ``spec.health.form_fingerprint`` du descripteur validé.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx

from .fingerprint import parse_form
from .http import Jar, get_page


@dataclass(frozen=True)
class HealthResult:
    app_id: str
    status: str  # ok | changed | form_missing | unreachable | no_fingerprint
    expected: str | None = None
    actual: str | None = None
    detail: str | None = None

    @property
    def healthy(self) -> bool:
        return self.status in ("ok", "no_fingerprint")


def check(descriptor: dict[str, Any], client: httpx.Client) -> HealthResult:
    app_id = descriptor["metadata"]["id"]
    spec = descriptor["spec"]
    expected = spec.get("health", {}).get("form_fingerprint")
    base = spec["upstream"]["base_url"].rstrip("/") + "/"
    try:
        resp, _ = get_page(client, urljoin(base, spec["login"]["form_url"]), base, Jar())
    except (httpx.HTTPError, ValueError) as e:
        return HealthResult(app_id, "unreachable", expected, detail=type(e).__name__)
    if resp.status_code != 200:
        return HealthResult(app_id, "unreachable", expected, detail=f"HTTP {resp.status_code}")
    form = parse_form(resp.text, spec["login"].get("form_selector", "form"))
    if form is None:
        return HealthResult(app_id, "form_missing", expected)
    actual = form.fingerprint()
    if expected is None:
        return HealthResult(app_id, "no_fingerprint", None, actual)
    return HealthResult(app_id, "ok" if actual == expected else "changed", expected, actual)
