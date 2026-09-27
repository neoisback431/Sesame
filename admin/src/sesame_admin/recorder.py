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

# Causes de blocage du recorder, expliquées à l'administrateur.
BLOCKING_HELP = {
    "login_page_redirects_away": "la page de login redirige vers un autre domaine (fournisseur SSO, "
    "portail d'entreprise…) : indiquez l'URL finale de la page de login, sur le domaine de l'appli",
    "password_field_outside_form": "le champ mot de passe n'est dans aucun formulaire <form> "
    "(page construite en JavaScript) : non pris en charge par le rejeu actuel",
    "multi_step_login_suspected": "connexion en plusieurs étapes (identifiant puis mot de passe sur un "
    "second écran) : hors périmètre",
    "login_form_not_found": "aucun champ mot de passe sur la page : vérifiez l'URL (page de login, pas "
    "d'accueil) ou que la page s'affiche sans action préalable",
    "captcha_detected": "captcha détecté : hors périmètre",
    "username_field_not_found": "champ identifiant introuvable à côté du mot de passe",
    "login_action_foreign_origin": "le formulaire envoie les identifiants vers un autre domaine : refusé",
    "submission_not_observed": "aucune soumission observée après le clic sur le bouton de connexion",
    "login_page_unreachable_without_javascript": "la page de login n'est pas joignable sans JavaScript",
    "login_form_not_found_in_raw_html": "le formulaire n'existe qu'après exécution du JavaScript et aucune "
    "soumission n'a été observée : cible du rejeu inconnue",
    "session_token_in_response": "l'appli renvoie un jeton (JWT…) dans la réponse au login et son JavaScript "
    "l'envoie en en-tête Authorization : session par jeton, non gérée aujourd'hui (voir « À faire »)",
    "no_session_cookie_after_login": "aucun cookie posé par la connexion : session hors cookies, non gérée",
}


def explain(code: str) -> str:
    base = code.split(" ", 1)[0].split(":", 1)[0]
    return f"{code} — {BLOCKING_HELP[base]}" if base in BLOCKING_HELP else code


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
            [f"bloquant : {explain(b)}" for b in self.blocking]
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
        handoff: bool = False,
    ) -> RecordingResult:
        """``credentials`` : compte de test (connexion réelle), transmis au recorder sans être
        conservé, journalisé ni audité (ADR 0019). ``handoff`` : proposer le mode remise
        (ADR 0020) plutôt que proxy."""
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
        handoff: bool = False,
    ) -> RecordingResult:
        url = self.base_url.rstrip("/") + "/record"
        payload: dict[str, Any] = {"login_url": login_url, "probe_failure": probe_failure, "handoff": handoff}
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
    # Erreur sans constat (URL invalide…) : message seul. Avec constat (formulaire introuvable…) :
    # résultat sans descripteur, pour afficher la cause à l'administrateur.
    if "error" in body and "yaml" not in body and not (body.get("summary") or body.get("blocking")):
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
