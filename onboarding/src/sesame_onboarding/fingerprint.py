# SPDX-License-Identifier: Apache-2.0
"""Formulaire de login tel que le voit le moteur de proxy (HTML brut, sans JavaScript).

L'empreinte ne dépend que de la **structure** du formulaire : action, méthode et
champs (balise, type, nom). Les valeurs sont exclues, les jetons CSRF changeant
à chaque affichage.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from bs4 import BeautifulSoup
from bs4.element import Tag

FIELD_TAGS = ("input", "select", "textarea", "button")


@dataclass(frozen=True)
class Field:
    tag: str
    type: str
    name: str


@dataclass(frozen=True)
class RawForm:
    action: str
    method: str
    fields: tuple[Field, ...]
    hidden: tuple[tuple[str, str], ...]  # (nom, valeur) des champs cachés

    @property
    def names(self) -> set[str]:
        return {f.name for f in self.fields}

    def fingerprint(self) -> str:
        canonical = {
            "action": self.action,
            "method": self.method,
            "fields": sorted([f.tag, f.type, f.name] for f in self.fields),
        }
        digest = hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()
        return f"sha256:{digest}"


def _field(el: Tag) -> Field | None:
    name = el.get("name")
    if not name:
        return None
    kind = str(el.get("type", "text" if el.name == "input" else el.name)).lower()
    return Field(el.name, kind, str(name))


def parse_form(html: str, selector: str) -> RawForm | None:
    """Premier formulaire correspondant au sélecteur CSS, ou ``None``."""
    soup = BeautifulSoup(html, "html.parser")
    form = soup.select_one(selector)
    if form is None or form.name != "form":
        return None
    fields = tuple(f for el in form.find_all(FIELD_TAGS) if (f := _field(el)) is not None)
    hidden = tuple(
        (str(el["name"]), str(el.get("value", "")))
        for el in form.find_all("input")
        if str(el.get("type", "")).lower() == "hidden" and el.get("name")
    )
    return RawForm(
        action=str(form.get("action", "")),
        method=str(form.get("method", "GET")).upper(),
        fields=fields,
        hidden=hidden,
    )


def meta_content(html: str, name: str) -> str | None:
    tag = BeautifulSoup(html, "html.parser").find("meta", attrs={"name": name})
    return str(tag.get("content")) if tag and tag.get("content") is not None else None


def input_value(html: str, name: str) -> str | None:
    tag = BeautifulSoup(html, "html.parser").find("input", attrs={"name": name})
    return str(tag.get("value", "")) if tag else None
