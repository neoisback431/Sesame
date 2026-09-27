# SPDX-License-Identifier: Apache-2.0
"""Parcours bout en bout sur l'environnement de dev (``make up`` au préalable).

Navigateur réel (Playwright) : SSO Keycloak, page « Mes applications », rejeu
du login de l'appli factice, expiration, habilitations, déconnexion,
administration (enregistrement d'un compte, désactivation, suppression),
absence de fuite de secrets (navigateur et logs des conteneurs).

Variables : ``SESAME_E2E_CHROMIUM`` (chemin d'un Chromium déjà installé).
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
from playwright.sync_api import Browser, Page, expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
PORTAL = "https://sesame.localhost:8443/"
APP = "https://fake-app.sesame.localhost:8443/"
ADMIN = "https://admin.sesame.localhost:8443/"
APP_PASSWORD = "dev-amartin-app-password"  # valeur de dev, voir dev/openbao/seed.sh
CAROL_APP_PASSWORD = "dev-cdupont-app-password"  # compte de carol dans l'appli factice


def compose(*args: str) -> str:
    return subprocess.run(
        ["docker", "compose", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def sql(query: str) -> str:
    return compose("exec", "-T", "postgres", "psql", "-U", "sesame", "-d", "sesame", "-tAc", query).strip()


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch(
            executable_path=os.environ.get("SESAME_E2E_CHROMIUM") or None,
            args=["--host-resolver-rules=MAP *.localhost 127.0.0.1, MAP sesame.localhost 127.0.0.1"],
        )
        yield b
        b.close()


def login(browser: Browser, user: str, start: str = PORTAL) -> Page:
    page = browser.new_context(ignore_https_errors=True).new_page()
    page.goto(start)
    page.fill("#username", user)
    page.fill("#password", user)
    page.click("#kc-login")
    page.wait_for_load_state()
    return page


def browser_cookie_names(page: Page) -> set[str]:
    return {c["name"] for c in page.context.cookies()}


def test_alice_reaches_the_app_through_her_portal(browser: Browser):
    page = login(browser, "alice")
    expect(page.locator("h1")).to_have_text("Mes applications")
    tile = page.get_by_role("link", name=re.compile("Appli factice"))
    expect(tile).to_have_attribute("href", APP)

    tile.click()
    expect(page.locator("h1")).to_have_text("Bonjour amartin")
    # URL interne réécrite vers l'adresse publique.
    account = page.get_by_role("link", name=re.compile("Mon compte"))
    expect(account).to_have_attribute("href", f"{APP}account")
    account.click()
    expect(page.locator("h1")).to_have_text("Compte de amartin")

    # Le navigateur ne détient que le cookie du portail (et ceux de l'IdP).
    names = browser_cookie_names(page)
    assert "sesame_session" in names
    assert not names & {"FAKEAPPSESSID", "FAKEAPPPRE"}, names
    assert APP_PASSWORD not in page.content()
    page.context.close()


def test_expired_app_session_is_replayed_transparently(browser: Browser):
    page = login(browser, "alice", start=APP)
    expect(page.locator("h1")).to_have_text("Bonjour amartin")
    compose("restart", "fake-app")  # l'appli perd toutes ses sessions
    page.wait_for_timeout(3000)
    page.goto(f"{APP}account")
    expect(page.locator("h1")).to_have_text("Compte de amartin")
    page.context.close()


def test_deep_link_goes_through_sso_then_lands_on_the_page(browser: Browser):
    page = login(browser, "alice", start=f"{APP}account")
    assert page.url == f"{APP}account"
    expect(page.locator("h1")).to_have_text("Compte de amartin")
    page.context.close()


def test_bob_has_no_tile_and_is_denied(browser: Browser):
    page = login(browser, "bob")
    expect(page.locator("h1")).to_have_text("Mes applications")
    expect(page.get_by_text("Aucune application")).to_be_visible()
    resp = page.goto(APP)
    assert resp is not None and resp.status == 403
    expect(page.locator("h1")).to_have_text("Accès refusé")
    page.context.close()


def test_portal_logout_destroys_app_sessions_and_idp_session(browser: Browser):
    page = login(browser, "alice", start=APP)
    expect(page.locator("h1")).to_have_text("Bonjour amartin")
    user_sessions = "SELECT count(*) FROM portal_sessions WHERE user_key = 'alice'"
    before = int(sql(user_sessions))
    page.goto(PORTAL)
    page.get_by_role("button", name="Se déconnecter").click()
    # Déconnexion chez Keycloak (SESAME_OIDC_LOGOUT) : sans id_token_hint, il demande confirmation.
    page.locator("#kc-logout").click()
    expect(page.locator("h1")).to_have_text("Vous êtes déconnecté")
    assert page.url == f"{PORTAL}auth/logged-out"
    assert "sesame_session" not in browser_cookie_names(page)
    assert int(sql(user_sessions)) == before - 1
    # Session SSO terminée : revenir sur l'appli redemande le mot de passe.
    page.goto(APP)
    expect(page.locator("#password")).to_be_visible()
    page.context.close()


def test_non_admin_is_denied_the_admin_ui(browser: Browser):
    page = login(browser, "bob", start=f"{ADMIN}login")
    expect(page.locator("h1")).to_have_text("Accès refusé")
    page.context.close()


def test_admin_provisions_an_account_then_user_gets_in(browser: Browser):
    # carol est habilitée (groupe) mais n'a pas encore de compte : aucune tuile.
    carol = login(browser, "carol")
    expect(carol.get_by_text("Aucune application")).to_be_visible()

    admin = login(browser, "admin", start=f"{ADMIN}login")
    expect(admin.locator("h1")).to_have_text("Applications")
    admin.get_by_role("link", name="Appli factice").click()
    admin.fill("#user_key", "carol")
    admin.fill("#cred_username", "cdupont")
    admin.fill("#cred_password", CAROL_APP_PASSWORD)
    admin.get_by_role("button", name="Enregistrer").click()
    expect(admin.get_by_role("status")).to_contain_text("enregistré et activé")
    assert CAROL_APP_PASSWORD not in admin.content()
    expect(admin.locator("tr", has_text="carol")).to_contain_text("actif")

    carol.reload()
    carol.get_by_role("link", name=re.compile("Appli factice")).click()
    expect(carol.locator("h1")).to_have_text("Bonjour cdupont")

    # Désactivation : accès refusé sans lecture du coffre ; puis nettoyage.
    admin.locator("tr", has_text="carol").get_by_role("button", name="Désactiver").click()
    expect(admin.get_by_role("status")).to_contain_text("désactivé")
    compose("restart", "fake-app")  # force un nouveau rejeu
    carol.wait_for_timeout(3000)
    resp = carol.goto(f"{APP}account")
    assert resp is not None and resp.status == 403
    admin.once("dialog", lambda d: d.accept())
    admin.locator("tr", has_text="carol").get_by_role("button", name="Supprimer").click()
    expect(admin.get_by_role("status")).to_contain_text("supprimé")
    carol.context.close()
    admin.context.close()


def test_audit_trail_and_no_secret_in_logs():
    logs = compose("logs", "--no-color", "portal", "proxy", "admin", "nginx")
    assert APP_PASSWORD not in logs and CAROL_APP_PASSWORD not in logs
    assert "FAKEAPPSESSID=" not in logs
    audit = [line for line in logs.splitlines() if '"log_type":"audit"' in line]
    for action in (
        "portal_login",
        "secret_read",
        "login_replay",
        "app_session_expired",
        "access_denied",
        "admin_login",
        "credential_written",
        "credential_deleted",
        "account_status_changed",
    ):
        assert any(f'"action":"{action}"' in line for line in audit), action
    # Cookies applicatifs chiffrés au repos : pas de valeur en clair dans la base.
    stored = sql("SELECT encode(cookies, 'escape') FROM app_sessions")
    assert "FAKEAPPSESSID" not in stored
