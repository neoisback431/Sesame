# SPDX-License-Identifier: Apache-2.0
"""Parcours bout en bout sur l'environnement de dev (``make up`` au préalable).

Navigateur réel (Playwright) : SSO Keycloak, page « Mes applications », rejeu
du login de l'appli factice, expiration, habilitations, déconnexion,
administration (enregistrement d'un compte, désactivation, suppression, création
d'une appli servie sans redémarrage),
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
APP_BIS = "https://fake-app-bis.sesame.localhost:8443/"  # appli créée dans l'administration
ADMIN = "https://admin.sesame.localhost:8443/"
APP_PASSWORD = "dev-amartin-app-password"  # valeur de dev, voir dev/postgres/seed_secret.py, ADR 0021
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

    # Désactivation : la session applicative ouverte est révoquée, l'accès est refusé
    # immédiatement (sans attendre l'expiration) et sans lecture du coffre.
    admin.locator("tr", has_text="carol").get_by_role("button", name="Désactiver").click()
    expect(admin.get_by_role("status")).to_contain_text("désactivé")
    resp = carol.goto(f"{APP}account")
    assert resp is not None and resp.status == 403

    # Vue par utilisateur : réactivation puis désactivation en masse.
    admin.get_by_role("link", name="Utilisateurs").click()
    admin.fill("#q", "carol")
    admin.get_by_role("button", name="Rechercher").click()
    admin.get_by_role("link", name="carol").click()
    admin.get_by_role("button", name="Réactiver").click()
    expect(admin.get_by_role("status")).to_contain_text("réactivé")
    carol.goto(APP)
    expect(carol.locator("h1")).to_have_text("Bonjour cdupont")
    admin.once("dialog", lambda d: d.accept())
    admin.get_by_role("button", name="Tout désactiver").click()
    expect(admin.get_by_role("status")).to_contain_text("1 compte(s)")
    resp = carol.goto(APP)
    assert resp is not None and resp.status == 403
    admin.get_by_role("link", name="Appli factice").click()
    admin.once("dialog", lambda d: d.accept())
    admin.locator("tr", has_text="carol").get_by_role("button", name="Supprimer").click()
    expect(admin.get_by_role("status")).to_contain_text("supprimé")
    carol.context.close()
    admin.context.close()


def test_app_created_in_admin_is_served_without_restart(browser: Browser):
    """Appli créée dans l'UI (formulaire guidé + éditeur), servie par le proxy et affichée
    par le portail après rechargement à chaud, sans redémarrer aucun service.

    Sans habilitation (aucun groupe) : le compte actif suffit à autoriser l'accès."""
    admin = login(browser, "admin", start=f"{ADMIN}login")
    admin.get_by_role("link", name="Nouvelle application").click()
    for field, value in {
        "id": "fake-app-bis",
        "name": "Appli factice bis",
        "public_host": "fake-app-bis.sesame.localhost:8443",
        "base_url": "http://fake-app:8000",
        # Pas de groupe : l'habilitation repose sur le seul compte actif.
        "form_selector": "form#login-form",
        "csrf_field": "csrf_token",
        "session_cookie": "FAKEAPPSESSID",
        "failure_text": "Identifiants invalides",
    }.items():
        admin.fill(f"#{field}", value)
    admin.get_by_role("button", name="Continuer vers l'éditeur").click()
    admin.get_by_role("button", name="Vérifier").click()
    expect(admin.get_by_role("status")).to_contain_text("Descripteur valide")
    admin.get_by_role("button", name="Créer l'application").click()
    expect(admin.get_by_role("status")).to_contain_text("créée")
    admin.fill("#user_key", "alice")
    admin.fill("#cred_username", "amartin")
    admin.fill("#cred_password", APP_PASSWORD)
    admin.get_by_role("button", name="Enregistrer").click()
    expect(admin.get_by_role("status")).to_contain_text("enregistré et activé")

    alice = login(browser, "alice")
    tile = alice.get_by_role("link", name=re.compile("Appli factice bis"))
    for _ in range(30):  # SESAME_DESCRIPTORS_RELOAD : 10 s par défaut
        if tile.count():
            break
        alice.wait_for_timeout(1000)
        alice.reload()
    expect(tile).to_have_attribute("href", APP_BIS)
    tile.click()
    expect(alice.locator("h1")).to_have_text("Bonjour amartin")
    assert "FAKEAPPSESSID" not in browser_cookie_names(alice)

    # Suppression : refusée tant qu'il reste un compte, puis l'appli n'est plus servie.
    admin.once("dialog", lambda d: d.accept())
    admin.locator("tr", has_text="alice").get_by_role("button", name="Supprimer").click()
    expect(admin.get_by_role("status")).to_contain_text("supprimé")
    admin.once("dialog", lambda d: d.accept())
    admin.get_by_role("button", name="Supprimer l'application").click()
    expect(admin.get_by_role("status")).to_contain_text("supprimée")
    status = 0
    for _ in range(30):
        resp = alice.goto(APP_BIS)
        status = resp.status if resp else 0
        if status == 404:
            break
        alice.wait_for_timeout(1000)
    assert status == 404
    alice.context.close()
    admin.context.close()


def test_recorder_button_prefills_the_editor(browser: Browser):
    """Depuis l'admin, « Analyser une page de login » interroge le service recorder,
    qui ouvre l'appli factice dans un navigateur et pré-remplit l'éditeur."""
    admin = login(browser, "admin", start=f"{ADMIN}login")
    admin.get_by_role("link", name="Nouvelle application").click()
    expect(admin.get_by_role("heading", name="Analyser une page de login")).to_be_visible()
    admin.fill("#login_url", "http://fake-app:8000/login")
    admin.get_by_role("button", name="Analyser").click()
    # Éditeur pré-rempli avec un descripteur reprenant le formulaire observé.
    editor = admin.locator("#descriptor")
    expect(editor).to_be_visible()
    proposed = editor.input_value()
    assert "form_url: /login" in proposed
    assert "username" in proposed and "password" in proposed
    assert "apiVersion: sesame/v1" in proposed
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
        "descriptor_created",
        "descriptor_deleted",
        "descriptor_recorded",
    ):
        assert any(f'"action":"{action}"' in line for line in audit), action
    # Cookies applicatifs chiffrés au repos : pas de valeur en clair dans la base.
    stored = sql("SELECT encode(cookies, 'escape') FROM app_sessions")
    assert "FAKEAPPSESSID" not in stored
