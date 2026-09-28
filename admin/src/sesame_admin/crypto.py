# SPDX-License-Identifier: Apache-2.0
"""Chiffrement AES-256-GCM des secrets écrits dans le coffre PostgreSQL (ADR 0021).

Même format que ``sesame_core::crypto::CookieCipher`` (Rust) : ``nonce (12 octets) ||
chiffré``, clé de 32 octets encodée en base64, lié par AAD au triplet appli /
utilisateur / champ. Les deux implémentations doivent rester interopérables : le proxy
(Rust) déchiffre ce que l'admin (ici) chiffre.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12


class InvalidKey(ValueError):
    pass


class SecretCipher:
    def __init__(self, key_b64: str) -> None:
        try:
            key = base64.b64decode(key_b64.strip(), validate=True)
        except Exception:
            raise InvalidKey("SESAME_SECRETS_ENCRYPTION_KEY : base64 invalide") from None
        if len(key) != 32:
            raise InvalidKey("SESAME_SECRETS_ENCRYPTION_KEY : 32 octets attendus")
        self._aead = AESGCM(key)

    def __repr__(self) -> str:  # jamais la clé
        return "SecretCipher(***)"

    def encrypt(self, plaintext: str, aad: bytes) -> bytes:
        nonce = os.urandom(NONCE_LEN)
        return nonce + self._aead.encrypt(nonce, plaintext.encode(), aad)

    def decrypt(self, data: bytes, aad: bytes) -> str:
        nonce, ciphertext = data[:NONCE_LEN], data[NONCE_LEN:]
        try:
            return self._aead.decrypt(nonce, ciphertext, aad).decode()
        except (InvalidTag, ValueError) as e:
            raise ValueError("secret indéchiffrable") from e


def field_aad(app_id: str, user_key: str, key: str) -> bytes:
    return f"{app_id}|{user_key}|{key}".encode()
