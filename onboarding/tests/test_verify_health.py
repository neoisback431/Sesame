# SPDX-License-Identifier: Apache-2.0
import copy

from sesame_onboarding import health, verify
from sesame_onboarding.http import Jar

from .conftest import APP_PASSWORD, js_only_app, meta_csrf_app, serve

CREDS = {"username": "amartin", "password": APP_PASSWORD}


def test_verify_fake_app(fake_descriptor, client):
    r = verify.verify(fake_descriptor, CREDS, client)
    assert (r.ok, r.reason, r.status) == (True, "ok", 302)
    assert "FAKEAPPSESSID" in r.cookies_set
    assert APP_PASSWORD not in repr(r)


def test_verify_detects_rejected_login(fake_descriptor, client):
    r = verify.verify(fake_descriptor, {**CREDS, "password": "wrong"}, client)
    assert (r.ok, r.reason, r.status) == (False, "login_rejected", 401)


def test_verify_reports_descriptor_errors(fake_descriptor, client):
    d = copy.deepcopy(fake_descriptor)
    d["spec"]["login"]["form_selector"] = "form#autre"
    assert verify.verify(d, CREDS, client).reason == "login_form_not_found_in_raw_html"

    d = copy.deepcopy(fake_descriptor)
    d["spec"]["login"]["csrf"] = [{"source": "hidden_input", "name": "absent"}]
    assert verify.verify(d, CREDS, client).reason == "csrf_token_not_found"

    d = copy.deepcopy(fake_descriptor)
    d["spec"]["login"]["action"] = "//evil.example/login"
    assert verify.verify(d, CREDS, client).reason == "login_action_foreign_origin"

    d = copy.deepcopy(fake_descriptor)
    d["spec"]["session"]["cookies"] = ["AUTRE"]
    assert verify.verify(d, CREDS, client).reason == "session_cookie_missing"

    assert verify.verify(fake_descriptor, {"username": "amartin"}, client).reason == "secret_key_missing"


def test_verify_unreachable(fake_descriptor, client):
    d = copy.deepcopy(fake_descriptor)
    d["spec"]["upstream"]["base_url"] = "http://127.0.0.1:9"
    assert verify.verify(d, CREDS, client).reason.startswith("unreachable")


def meta_descriptor(base):
    return {
        "metadata": {"id": "meta-app"},
        "spec": {
            "upstream": {"base_url": base},
            "login": {
                "form_url": "/signin",
                "fields": {
                    "login": {"from_secret": "username"},
                    "pwd": {"from_secret": "password"},
                    "remember": {"value": "1"},
                },
                "csrf": [{"source": "meta", "name": "csrf-token", "send_as": {"header": "X-CSRF-Token"}}],
                "success": {"any_of": [{"status": [200], "cookie_set": "SID", "body_contains": "Bienvenue"}]},
                "failure": {"any_of": [{"body_contains": "incorrect"}]},
            },
            "session": {"cookies": ["SID"]},
        },
    }


def test_verify_meta_csrf_sent_as_header(client):
    srv, base = serve(meta_csrf_app())
    try:
        d = meta_descriptor(base)
        creds = {"username": "u1", "password": APP_PASSWORD}
        assert verify.verify(d, creds, client).ok
        assert verify.verify(d, {**creds, "password": "x"}, client).reason == "login_rejected"
    finally:
        srv.shutdown()


def test_javascript_only_form_is_not_replayable(client):
    srv, base = serve(js_only_app())
    try:
        d = meta_descriptor(base)
        d["spec"]["login"]["form_url"] = "/login"
        assert verify.verify(d, {"username": "u", "password": "p"}, client).reason == (
            "login_form_not_found_in_raw_html"
        )
    finally:
        srv.shutdown()


def test_health_statuses(fake_descriptor, client):
    # Le descripteur de référence porte l'empreinte réelle de l'appli factice.
    assert health.check(fake_descriptor, client).status == "ok"

    d = copy.deepcopy(fake_descriptor)
    del d["spec"]["health"]["form_fingerprint"]
    first = health.check(d, client)
    assert first.status == "no_fingerprint" and first.healthy and first.actual.startswith("sha256:")

    d["spec"]["health"]["form_fingerprint"] = "sha256:" + "0" * 64
    changed = health.check(d, client)
    assert changed.status == "changed" and not changed.healthy

    d["spec"]["login"]["form_selector"] = "form#autre"
    assert health.check(d, client).status == "form_missing"

    d["spec"]["upstream"]["base_url"] = "http://127.0.0.1:9"
    assert health.check(d, client).status == "unreachable"


def test_jar_never_prints_values():
    jar = Jar()
    assert jar.apply(["A=secret-value; Path=/", "B=2", "broken"]) == ["A", "B"]
    assert "secret-value" not in repr(jar)
    jar.apply(["A=; Max-Age=0"])
    assert jar.header() == "B=2"
