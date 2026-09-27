# SPDX-License-Identifier: Apache-2.0
"""``sesame-onboard record`` de bout en bout (fichier séparé : la CLI ouvre son propre Playwright)."""

import pytest
import yaml
from sesame_onboarding import descriptors, record
from sesame_onboarding.cli import main

from .test_record import DUMMY_PASSWORD, DUMMY_USER, Recorder, chromium_path, create_app

pytest.importorskip("playwright.sync_api")

pytestmark = pytest.mark.browser


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setattr(record, "dummy_credentials", lambda: (DUMMY_USER, DUMMY_PASSWORD))
    r = Recorder(create_app(users={"amartin": "Pw-real"}, session_ttl=60))
    yield r
    r.srv.shutdown()


def test_cli_writes_a_valid_descriptor_and_no_page_value(fake, tmp_path, capsys, monkeypatch):
    if chromium_path():
        monkeypatch.setenv("SESAME_ONBOARD_CHROMIUM", chromium_path())
    out = tmp_path / "proposal.yaml"
    code = main(
        [
            "record",
            f"{fake.base}/login",
            "--id",
            "fake-app",
            "--group",
            "g",
            "-o",
            str(out),
            "--probe-failure",
        ]
    )
    err = capsys.readouterr().err
    if code == 1 and "navigateur :" in err:
        pytest.skip("Chromium indisponible")
    assert code == 0, err
    text = out.read_text()
    doc = yaml.safe_load(text)
    assert descriptors.validate(doc) == [] and doc["spec"]["access"] == {"groups": ["g"]}
    assert text.startswith("# Descripteur proposé par sesame-onboard record")
    assert "sonde d'échec" in err and "jeton CSRF : hidden_input csrf_token" in err
    store = fake.app.extensions["fake_app_store"]
    values = [*store.csrf.values(), *store.csrf.keys(), DUMMY_PASSWORD, DUMMY_USER]
    leaked = [v for v in values if v in text + err]
    assert leaked == []
