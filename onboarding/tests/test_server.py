# SPDX-License-Identifier: Apache-2.0
"""Couche HTTP du service recorder : authentification, validation d'entrée, routage.

L'analyse réelle (navigateur) est couverte par test_record.py et l'e2e ; ici elle
est remplacée pour tester le serveur sans lancer de navigateur.
"""

import threading
from http.server import HTTPServer

import httpx
import pytest
from sesame_onboarding import server


class Cfg:
    token = "secret-token"


@pytest.fixture
def base(monkeypatch):
    # analyze() renvoie l'entrée reçue, sans navigateur.
    monkeypatch.setattr(server, "analyze", lambda cfg, pw, br, body: {"echo": body})
    httpd = HTTPServer(("127.0.0.1", 0), server._handler(Cfg(), None, None))
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


def test_healthz_needs_no_token(base):
    r = httpx.get(f"{base}/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_record_requires_valid_token(base):
    assert httpx.post(f"{base}/record", json={"login_url": "http://x/"}).status_code == 401
    bad = {"Authorization": "Bearer nope"}
    assert httpx.post(f"{base}/record", json={"login_url": "http://x/"}, headers=bad).status_code == 401


def test_record_runs_with_token(base):
    r = httpx.post(
        f"{base}/record",
        json={"login_url": "http://x/login"},
        headers={"Authorization": "Bearer secret-token"},
    )
    assert r.status_code == 200 and r.json() == {"echo": {"login_url": "http://x/login"}}


def test_bad_json_and_unknown_route(base):
    auth = {"Authorization": "Bearer secret-token"}
    assert httpx.post(f"{base}/record", content=b"not json", headers=auth).status_code == 400
    assert httpx.post(f"{base}/other", json={}, headers=auth).status_code == 404


def test_analyze_requires_login_url():
    assert server.analyze(Cfg(), None, None, {})["error"] == "login_url requis"


def test_analyze_passes_the_test_account_without_echoing_it(monkeypatch):
    import json

    from sesame_onboarding import record

    seen = {}

    def fake_record(url, client, browser, **kw):
        seen.update(kw)
        return record.Recording(login_url=url, base_url="http://x/", form_url="/login")

    monkeypatch.setattr(record, "record", fake_record)
    cfg = type("C", (), {"token": "t", "insecure": False, "ca_file": None, "timeout": 5.0})()
    body = {"login_url": "http://x/login", "username": "testeur", "password": "Pw-secret-42"}
    result = server.analyze(cfg, None, None, body)
    assert seen["credentials"] == ("testeur", "Pw-secret-42")
    assert "Pw-secret-42" not in json.dumps(result) and "password" not in body
    # Sans mot de passe : aucune connexion réelle.
    server.analyze(cfg, None, None, {"login_url": "http://x/login", "username": "testeur"})
    assert seen["credentials"] is None


def test_insecure_defaults_to_true(monkeypatch):
    monkeypatch.setenv("SESAME_RECORDER_TOKEN", "t")
    monkeypatch.delenv("SESAME_RECORDER_INSECURE", raising=False)
    assert server.Config().insecure is True
    for value in ("false", "0", "no", "FALSE"):
        monkeypatch.setenv("SESAME_RECORDER_INSECURE", value)
        assert server.Config().insecure is False
    for value in ("true", "1", "yes", "anything-else"):
        monkeypatch.setenv("SESAME_RECORDER_INSECURE", value)
        assert server.Config().insecure is True
