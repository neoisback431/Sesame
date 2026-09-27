#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Déclinaisons web du logo et de la bannière (``ressources/``), pour les interfaces.

Usage : uv run scripts/build_web_assets.py
Écrit les mêmes fichiers dans ``crates/sesame-core/assets/`` (portail, pages du proxy,
embarqués dans le binaire) et ``admin/src/sesame_admin/static/`` (administration).
Relancer après toute modification des originaux.
"""
# /// script
# requires-python = ">=3.11"
# dependencies = ["pillow>=10"]
# ///

from __future__ import annotations

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "ressources"
TARGETS = [ROOT / "crates" / "sesame-core" / "assets", ROOT / "admin" / "src" / "sesame_admin" / "static"]


def trimmed(name: str) -> Image.Image:
    """Image sans ses marges transparentes."""
    im = Image.open(SOURCES / name).convert("RGBA")
    return im.crop(im.getchannel("A").getbbox())


def square(im: Image.Image, size: int) -> Image.Image:
    return im.resize((size, size), Image.Resampling.LANCZOS)


def main() -> None:
    logo = trimmed("sesamLogo.png")
    banner = trimmed("SesamBaniere.png")
    outputs = {
        "logo-64.png": square(logo, 64),  # en-têtes (affiché en 32 px, écrans denses)
        "favicon-32.png": square(logo, 32),
        "banner.webp": banner,
    }
    for target in TARGETS:
        target.mkdir(parents=True, exist_ok=True)
        for name, im in outputs.items():
            path = target / name
            if name.endswith(".webp"):
                im.save(path, "WEBP", quality=82, method=6)
            else:
                im.save(path, "PNG", optimize=True)
            print(f"{path.relative_to(ROOT)} : {path.stat().st_size // 1024} Kio")


if __name__ == "__main__":
    main()
