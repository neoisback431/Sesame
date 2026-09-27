# SPDX-License-Identifier: Apache-2.0
"""Conditions des descripteurs (`success`, `failure`, `expiry`).

Même sémantique que le moteur de proxy (``crates/sesame-proxy/src/matcher.rs``) :
une condition vaut si toutes ses propriétés sont vraies ; un ensemble ``any_of``
vaut si au moins une condition vaut.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ResponseView:
    status: int
    location: str | None
    set_cookie_names: tuple[str, ...]
    body: str


def matches(m: dict[str, Any], r: ResponseView) -> bool:
    location = r.location or ""
    checks = [
        not m.get("status") or r.status in m["status"],
        "location_matches" not in m
        or (r.location is not None and re.search(m["location_matches"], location) is not None),
        "location_not_matches" not in m or not re.search(m["location_not_matches"], location),
        "cookie_set" not in m or m["cookie_set"] in r.set_cookie_names,
        "body_contains" not in m or m["body_contains"] in r.body,
        "body_not_contains" not in m or m["body_not_contains"] not in r.body,
    ]
    return all(checks)


def any_of(matcher_set: dict[str, Any] | None, r: ResponseView) -> bool:
    return bool(matcher_set) and any(matches(m, r) for m in matcher_set["any_of"])
