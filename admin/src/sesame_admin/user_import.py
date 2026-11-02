# SPDX-License-Identifier: Apache-2.0
"""Analyse d'une liste d'utilisateurs à importer (ADR 0032), collée dans l'administration.

Une ligne par personne : ``clé[,nom[,e-mail]]``, séparateur virgule, point-virgule ou tabulation
(export CSV d'un annuaire). La clé doit être exactement la valeur du claim qui sert de clé
utilisateur à Sesame (Entra ID : l'identifiant d'objet). Aucune valeur n'a de portée d'autorisation.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field

from .identity import valid_user_key
from .ports import UserImport

MAX_BYTES = 512 * 1024
MAX_LINES = 5000
MAX_REPORTED_ERRORS = 20
_NAME_MAX, _EMAIL_MAX = 200, 254
# Premières cellules d'un en-tête d'export, ignorées.
_HEADERS = frozenset(
    {"cle", "clé", "key", "user_key", "userkey", "id", "oid", "objectid", "object id", "id d'objet"}
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+$")


class ImportTooLarge(ValueError):
    pass


@dataclass
class ParsedImport:
    entries: list[UserImport] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # « ligne N : … », tronquée à MAX_REPORTED_ERRORS
    rejected: int = 0  # lignes refusées, y compris celles dont l'erreur n'est pas listée


def _split(line: str) -> list[str]:
    delimiter = "\t" if "\t" in line else ";" if ";" in line else ","
    return [c.strip() for c in next(csv.reader([line], delimiter=delimiter))]


def parse(text: str) -> ParsedImport:
    if len(text.encode()) > MAX_BYTES:
        raise ImportTooLarge(f"liste trop volumineuse (maximum {MAX_BYTES // 1024} Kio)")
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise ImportTooLarge(f"trop de lignes (maximum {MAX_LINES})")
    out = ParsedImport()
    merged: dict[str, tuple[str | None, str | None]] = {}
    header_possible = True
    for number, raw in enumerate(lines, start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        try:
            cells = _split(raw)
        except csv.Error:
            _reject(out, number, "ligne illisible")
            continue
        key, name, email = (cells + ["", ""])[:3]
        if header_possible:
            header_possible = False
            if key.lower() in _HEADERS:
                continue
        if not valid_user_key(key):
            _reject(out, number, "clé invalide (caractères autorisés : A-Z a-z 0-9 @ . _ - +, 256 au plus)")
        elif _CONTROL.search(name) or len(name) > _NAME_MAX:
            _reject(out, number, f"nom invalide (caractères de contrôle ou plus de {_NAME_MAX} caractères)")
        elif email and (_CONTROL.search(email) or len(email) > _EMAIL_MAX or not _EMAIL.match(email)):
            _reject(out, number, "e-mail invalide")
        else:
            old = merged.get(key, (None, None))
            merged[key] = (name or old[0], email or old[1])
    out.entries = [UserImport(k, n, e) for k, (n, e) in merged.items()]
    return out


def _reject(out: ParsedImport, number: int, why: str) -> None:
    out.rejected += 1
    if len(out.errors) < MAX_REPORTED_ERRORS:
        out.errors.append(f"ligne {number} : {why}")
