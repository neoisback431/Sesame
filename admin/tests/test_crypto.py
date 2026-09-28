# SPDX-License-Identifier: Apache-2.0
"""Chiffrement des secrets écrits dans le coffre PostgreSQL (ADR 0021)."""

import base64

import pytest
from sesame_admin.crypto import InvalidKey, SecretCipher, field_aad


def cipher() -> SecretCipher:
    return SecretCipher(base64.b64encode(bytes(range(32))).decode())


def test_roundtrip_and_aad_binding():
    c = cipher()
    ct = c.encrypt("s3cret-pw", field_aad("fake-app", "alice", "password"))
    assert b"s3cret-pw" not in ct
    assert c.decrypt(ct, field_aad("fake-app", "alice", "password")) == "s3cret-pw"
    with pytest.raises(ValueError):
        c.decrypt(ct, field_aad("fake-app", "alice", "username"))
    with pytest.raises(ValueError):
        c.decrypt(ct, field_aad("other-app", "alice", "password"))


def test_rejects_bad_keys():
    with pytest.raises(InvalidKey):
        SecretCipher("trop-court")
    with pytest.raises(InvalidKey):
        SecretCipher(base64.b64encode(b"0" * 16).decode())


def test_repr_never_shows_the_key():
    assert "***" in repr(cipher())
