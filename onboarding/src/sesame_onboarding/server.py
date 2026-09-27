# SPDX-License-Identifier: Apache-2.0
"""Service HTTP du recorder, appelé par la console d'administration.

Enveloppe fine autour de :mod:`record` : ``POST /record`` renvoie le descripteur
proposé pour une page de login, en JSON. Le service est destiné au **réseau
interne uniquement** (jamais exposé via Nginx) et exige un jeton partagé.

Serveur mono-thread : Playwright (API synchrone) et le navigateur sont démarrés
une fois et réutilisés, les requêtes sont donc traitées en série. Suffisant pour
un usage ponctuel depuis l'admin.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import httpx

from . import descriptors, record

log = logging.getLogger("sesame_recorder")

MAX_BODY = 64 * 1024


class Config:
    def __init__(self) -> None:
        listen = os.environ.get("SESAME_RECORDER_LISTEN", "0.0.0.0:8090")
        host, _, port = listen.rpartition(":")
        self.host = host or "0.0.0.0"  # noqa: S104 (service en conteneur, interne)
        self.port = int(port)
        self.token = os.environ.get("SESAME_RECORDER_TOKEN", "").strip()
        self.schema = Path(os.environ.get("SESAME_RECORDER_SCHEMA", str(descriptors.DEFAULT_SCHEMA)))
        self.insecure = os.environ.get("SESAME_RECORDER_INSECURE", "").lower() in ("1", "true", "yes")
        self.ca_file = os.environ.get("SESAME_CA_FILE") or None
        self.chromium = os.environ.get("SESAME_ONBOARD_CHROMIUM") or None
        self.timeout = float(os.environ.get("SESAME_RECORDER_TIMEOUT", "20"))
        if not self.token:
            raise SystemExit("SESAME_RECORDER_TOKEN requis")


def _verify_context(cfg: Config) -> ssl.SSLContext | bool:
    if cfg.insecure:
        return False
    if cfg.ca_file:
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cafile=cfg.ca_file)
        return ctx
    return True


def analyze(cfg: Config, playwright: Any, browser: Any, body: dict[str, Any]) -> dict[str, Any]:
    """Analyse une page de login et renvoie le descripteur proposé et ses notes."""
    login_url = body.get("login_url")
    if not isinstance(login_url, str) or not login_url:
        return {"error": "login_url requis"}
    username, password = body.pop("username", None), body.pop("password", None)
    credentials = None
    if isinstance(username, str) and isinstance(password, str) and password:
        credentials = (username, password)
    verify = _verify_context(cfg)
    with httpx.Client(follow_redirects=False, timeout=cfg.timeout, verify=verify, trust_env=False) as client:
        rec = record.record(
            login_url,
            client,
            browser,
            base_url=body.get("base_url") or None,
            protected_path=body.get("protected_path") or "/",
            probe_failure=bool(body.get("probe_failure")),
            timeout=cfg.timeout,
            ignore_https_errors=cfg.insecure,
            credentials=credentials,
        )
    credentials = username = password = None  # noqa: F841 (références effacées)
    result: dict[str, Any] = {
        "summary": record.summary(rec),
        "warnings": list(rec.warnings),
        "blocking": list(rec.blocking),
    }
    if rec.password_field is None:
        result["error"] = "formulaire de login introuvable"
        return result
    draft = record.to_descriptor(
        rec,
        app_id=body.get("id") or None,
        name=body.get("name") or None,
        public_host=body.get("public_host") or None,
        groups=body.get("groups") or None,
        users=body.get("users") or None,
        session_cookie=body.get("session_cookie") or None,
    )
    result["todo"] = list(draft.todo)
    result["yaml"] = record.render(draft, rec)
    result["errors"] = descriptors.validate(draft.document, cfg.schema)
    result["valid"] = not result["errors"]
    return result


def _handler(cfg: Config, playwright: Any, browser: Any) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "sesame-recorder"

        def log_message(self, fmt: str, *args: Any) -> None:  # logs JSON via `log`
            log.info("%s", fmt % args)

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            token = header[7:] if header.startswith("Bearer ") else ""
            return bool(token) and hmac.compare_digest(token, cfg.token)

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send(200, {"status": "ok"})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/record":
                self._send(404, {"error": "not found"})
                return
            if not self._authorized():
                self._send(401, {"error": "jeton invalide"})
                return
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0 or length > MAX_BODY:
                self._send(400, {"error": "corps de requête invalide"})
                return
            try:
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError
            except (ValueError, json.JSONDecodeError):
                self._send(400, {"error": "JSON invalide"})
                return
            try:
                self._send(200, analyze(cfg, playwright, browser, body))
            except record.RecordError as e:
                self._send(400, {"error": str(e)})
            except Exception:  # une page hostile ne doit pas tuer le service
                log.exception("analyse impossible")
                self._send(502, {"error": "analyse impossible"})

    return Handler


def main() -> None:
    logging.basicConfig(level=logging.INFO, format='{"level":"%(levelname)s","message":"%(message)s"}')
    cfg = Config()
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=cfg.chromium)
        try:
            httpd = HTTPServer((cfg.host, cfg.port), _handler(cfg, playwright, browser))
            log.info("recorder démarré sur %s:%d", cfg.host, cfg.port)
            httpd.serve_forever()
        finally:
            browser.close()


if __name__ == "__main__":
    main()
