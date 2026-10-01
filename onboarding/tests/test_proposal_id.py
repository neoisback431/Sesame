# SPDX-License-Identifier: Apache-2.0
"""Identifiant d'appli proposé par le recorder : jamais un nom générique ni réservé."""

import pytest
from sesame_onboarding import proposal


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("compta.corp.example.com", "compta"),
        ("www.compta.example.com", "compta"),
        ("www2.compta.example.com", "compta"),
        ("login.rh.example.com", "rh"),
        ("www.example.com", "example"),
        ("www", "appli"),
        ("admin", "appli"),
        ("192.168.1.20", "appli"),
        ("::1", "appli"),
        ("", "appli"),
    ],
)
def test_id_from_host(host, expected):
    assert proposal._id_from_host(host) == expected


def test_deduced_id_is_never_reserved():
    for host in ("www.example.com", "admin.example.com", "new.example.com"):
        assert proposal._slug(proposal._id_from_host(host)) not in proposal.RESERVED_IDS
