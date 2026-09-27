# SPDX-License-Identifier: Apache-2.0
import json

import yaml
from sesame_onboarding.cli import main

from .conftest import APP_PASSWORD


def write(tmp_path, d, name="fake-app.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(d, allow_unicode=True))
    return path


def test_verify_command_never_prints_the_password(fake_descriptor, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SESAME_ONBOARD_USERNAME", "amartin")
    monkeypatch.setenv("SESAME_ONBOARD_PASSWORD", APP_PASSWORD)
    assert main(["verify", str(write(tmp_path, fake_descriptor))]) == 0
    out, err = capsys.readouterr()
    record = json.loads(out)
    assert record["log_type"] == "verify" and record["ok"] is True and record["app_id"] == "fake-app"
    assert APP_PASSWORD not in out + err

    monkeypatch.setenv("SESAME_ONBOARD_PASSWORD", "wrong-" + APP_PASSWORD)
    assert main(["verify", str(write(tmp_path, fake_descriptor))]) == 1
    out, err = capsys.readouterr()
    assert json.loads(out)["reason"] == "login_rejected"
    assert APP_PASSWORD not in out + err


def test_fingerprint_then_health(fake_descriptor, tmp_path, capsys):
    path = write(tmp_path, fake_descriptor)
    assert main(["fingerprint", str(path)]) == 0
    fp = capsys.readouterr().out.strip()
    assert fp.startswith("sha256:")

    fake_descriptor["spec"]["health"]["form_fingerprint"] = fp
    write(tmp_path, fake_descriptor)
    assert main(["health", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ok"

    fake_descriptor["spec"]["health"]["form_fingerprint"] = "sha256:" + "1" * 64
    write(tmp_path, fake_descriptor)
    assert main(["health", str(tmp_path), "--app", "fake-app"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "changed"


def test_invalid_descriptor(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("apiVersion: sesame/v1\n")
    assert main(["verify", str(bad)]) == 2
    assert "descripteur invalide" in capsys.readouterr().err
