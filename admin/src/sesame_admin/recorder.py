# SPDX-License-Identifier: Apache-2.0
"""Client du service recorder : analyse d'une page de login pour pré-remplir l'éditeur.

Le recorder est un service interne (``SESAME_RECORDER_URL``) authentifié par un jeton
partagé. Il renvoie un descripteur proposé (YAML) et des notes à relire ; il ne reçoit
et ne renvoie **aucun identifiant applicatif**.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx


class RecorderError(RuntimeError):
    """Recorder injoignable ou en erreur. Message affichable, sans secret."""


@dataclass
class RecordingResult:
    yaml: str | None
    summary: list[str]
    todo: list[str]
    warnings: list[str]
    blocking: list[str]
    valid: bool
    errors: list[str]

    @property
    def notes(self) -> list[str]:
        """Tout ce que l'administrateur doit relire, avertissements en premier."""
        return (
            [f"bloquant : {b}" for b in self.blocking]
            + [f"avertissement : {w}" for w in self.warnings]
            + list(self.todo)
            + [f"schéma : {e}" for e in self.errors]
        )


class Recorder(Protocol):
    async def analyze(
        self,
        login_url: str,
        *,
        probe_failure: bool = False,
        credentials: tuple[str, str] | None = None,
    ) -> RecordingResult:
        """``credentials`` : compte de test (connexion réelle), transmis au recorder sans être
        conservé, journalisé ni audité (ADR 0019)."""
        ...


@dataclass
class HttpRecorder:
    base_url: str
    token: str = field(repr=False)
    # Analyse + connexion réelle éventuelle : deux passages dans le navigateur.
    timeout: float = 90.0

    async def analyze(
        self,
        login_url: str,
        *,
        probe_failure: bool = False,
        credentials: tuple[str, str] | None = None,
    ) -> RecordingResult:
        url = self.base_url.rstrip("/") + "/record"
        payload: dict[str, Any] = {"login_url": login_url, "probe_failure": probe_failure}
        if credentials:
            payload["username"], payload["password"] = credentials
        try:
            async with httpx.AsyncClient(timeout=self.timeout, trust_env=False) as client:
                resp = await client.post(
                    url,
                    json=payload,
                    headers={"Authorization": f"Bearer {self.token}"},
                )
        except httpx.HTTPError as e:
            raise RecorderError(f"recorder injoignable ({type(e).__name__})") from None
        if resp.status_code != 200:
            raise RecorderError(f"le recorder a répondu HTTP {resp.status_code}")
        return _result(resp.json())


def _result(body: dict[str, Any]) -> RecordingResult:
    if "error" in body and "yaml" not in body:
        raise RecorderError(str(body["error"]))

    def strings(key: str) -> list[str]:
        value = body.get(key) or []
        return [str(x) for x in value] if isinstance(value, list) else []

    return RecordingResult(
        yaml=body.get("yaml") if isinstance(body.get("yaml"), str) else None,
        summary=strings("summary"),
        todo=strings("todo"),
        warnings=strings("warnings"),
        blocking=strings("blocking"),
        valid=bool(body.get("valid")),
        errors=strings("errors"),
    )
