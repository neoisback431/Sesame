# SPDX-License-Identifier: Apache-2.0
from sesame_onboarding.fingerprint import input_value, meta_content, parse_form

PAGE = """<meta name="csrf" content="m1">
<form id="search"><input name="q"></form>
<form id="login" action="/login" method="post">
  <input type="hidden" name="csrf_token" value="{token}">
  <input name="username"><input type="password" name="password">
  <select name="lang"><option>fr</option></select><button type="submit">OK</button>
</form>"""


def test_parses_selected_form():
    form = parse_form(PAGE.format(token="a"), "form#login")
    assert form.action == "/login" and form.method == "POST"
    assert form.names == {"csrf_token", "username", "password", "lang"}
    assert form.hidden == (("csrf_token", "a"),)
    assert parse_form(PAGE, "form#absent") is None
    assert parse_form(PAGE, "input") is None  # pas un formulaire


def test_fingerprint_ignores_values_but_not_structure():
    a = parse_form(PAGE.format(token="a"), "form#login").fingerprint()
    b = parse_form(PAGE.format(token="b"), "form#login").fingerprint()
    assert a == b and a.startswith("sha256:") and len(a) == 71
    changed = PAGE.replace('name="username"', 'name="email"')
    assert parse_form(changed.format(token="a"), "form#login").fingerprint() != a
    moved = PAGE.replace('action="/login"', 'action="/auth"')
    assert parse_form(moved.format(token="a"), "form#login").fingerprint() != a


def test_helpers():
    assert meta_content(PAGE, "csrf") == "m1"
    assert input_value(PAGE.format(token="z"), "csrf_token") == "z"
    assert meta_content(PAGE, "absent") is None
