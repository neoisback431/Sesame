# SPDX-License-Identifier: Apache-2.0
"""Coffre OpenBao / Vault en écriture seule : AppRole + KV v2, API HTTP commune.

Policy attendue : ``create``/``update`` sur ``<mount>/data/<prefix>/*`` et
``delete`` sur ``<mount>/metadata/<prefix>/*``, **sans** ``read``.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

from .identity import valid_user_key
from .ports import Unavailable


@dataclass(frozen=True)
class OpenBaoConfig:
    addr: str
    mount: str
    path_prefix: str
    role_id: str
    secret_id: str
    namespace: str | None = None

    def __repr__(self) -> str:  # le secret AppRole ne doit jamais apparaître
        return f"OpenBaoConfig(addr={self.addr!r}, mount={self.mount!r}, path_prefix={self.path_prefix!r})"


def _segment_ok(s: str) -> bool:
    return bool(s) and s not in {".", ".."} and "/" not in s


class OpenBaoSecretWriter:
    def __init__(self, cfg: OpenBaoConfig, client: httpx.AsyncClient) -> None:
        if not _segment_ok(cfg.mount) or not all(_segment_ok(p) for p in cfg.path_prefix.split("/")):
            raise ValueError("mount ou préfixe de chemin du coffre invalide")
        self._cfg = cfg
        self._client = client
        self._token: str | None = None
        self._renew_after = 0.0
        self._lock = asyncio.Lock()

    def __repr__(self) -> str:
        return f"OpenBaoSecretWriter({self._cfg!r})"

    def _headers(self, token: str | None = None) -> dict[str, str]:
        h = {}
        if self._cfg.namespace:
            h["X-Vault-Namespace"] = self._cfg.namespace
        if token:
            h["X-Vault-Token"] = token
        return h

    def _path(self, kind: str, app_id: str, user_key: str) -> str:
        if not _segment_ok(app_id) or not valid_user_key(user_key):
            raise ValueError("identifiant d'appli ou d'utilisateur invalide")
        c = self._cfg
        return f"{c.addr.rstrip('/')}/v1/{c.mount}/{kind}/{c.path_prefix}/{app_id}/users/{user_key}"

    async def _login(self, force: bool = False) -> str:
        async with self._lock:
            if self._token and not force and time.monotonic() < self._renew_after:
                return self._token
            body = {"role_id": self._cfg.role_id, "secret_id": self._cfg.secret_id}
            try:
                r = await self._client.post(
                    f"{self._cfg.addr.rstrip('/')}/v1/auth/approle/login", json=body, headers=self._headers()
                )
            except httpx.HTTPError as e:
                raise Unavailable(f"coffre injoignable ({type(e).__name__})") from None
            if r.status_code != 200:
                raise Unavailable(f"login AppRole refusé (HTTP {r.status_code})")
            auth = r.json()["auth"]
            self._token = auth["client_token"]
            self._renew_after = time.monotonic() + max(int(auth.get("lease_duration", 0)), 30) * 2 / 3
            return self._token

    async def _call(self, method: str, url: str, json: dict | None = None) -> httpx.Response:
        for force in (False, True):
            token = await self._login(force=force)
            try:
                r = await self._client.request(method, url, json=json, headers=self._headers(token))
            except httpx.HTTPError as e:
                raise Unavailable(f"coffre injoignable ({type(e).__name__})") from None
            if r.status_code != 403:
                return r
        return r

    async def write_credential(self, app_id: str, user_key: str, fields: dict[str, str]) -> None:
        r = await self._call("POST", self._path("data", app_id, user_key), json={"data": fields})
        if r.status_code not in (200, 204):
            raise Unavailable(f"écriture dans le coffre refusée (HTTP {r.status_code})")

    async def delete_credential(self, app_id: str, user_key: str) -> None:
        r = await self._call("DELETE", self._path("metadata", app_id, user_key))
        if r.status_code not in (200, 204, 404):
            raise Unavailable(f"suppression dans le coffre refusée (HTTP {r.status_code})")
