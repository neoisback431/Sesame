# SPDX-License-Identifier: Apache-2.0
"""Événements d'audit : même format que les services Rust (``sesame_core::audit``)."""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from .identity import AdminUser


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class AuditEvent:
    """Qui, quelle appli, quel compte, quand, résultat. Jamais de secret."""

    action: str
    outcome: str  # "success" | "failure"
    actor: str | None = None
    app_id: str | None = None
    target_user: str | None = None
    correlation_id: str | None = None
    reason: str | None = None
    timestamp: str = field(default_factory=_now)

    @classmethod
    def of(cls, action: str, outcome: str, actor: AdminUser | None, **kw: str | None) -> AuditEvent:
        return cls(action=action, outcome=outcome, actor=actor.actor if actor else None, **kw)


class AuditSink(Protocol):
    async def record(self, event: AuditEvent) -> None: ...


class StdoutAuditSink:
    """Lignes JSON sur stdout marquées ``"log_type":"audit"``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    async def record(self, event: AuditEvent) -> None:
        line = json.dumps({"log_type": "audit", **asdict(event)}, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def record(self, event: AuditEvent) -> None:
        self.events.append(event)
