# SPDX-License-Identifier: Apache-2.0
"""Ligne de commande ``sesame-onboard`` : ``verify``, ``health``, ``fingerprint``.

Codes de sortie : 0 succès, 1 échec (vérification ou santé), 2 erreur d'usage.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import ssl
import sys
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urljoin

import httpx

from . import descriptors, health, verify
from .fingerprint import parse_form
from .http import Jar, get_page


def _client(args: argparse.Namespace) -> httpx.Client:
    verify_tls: ssl.SSLContext | bool = True
    if args.insecure:
        verify_tls = False
    elif args.ca_file:
        verify_tls = ssl.create_default_context()
        verify_tls.load_verify_locations(cafile=args.ca_file)
    return httpx.Client(follow_redirects=False, timeout=args.timeout, verify=verify_tls, trust_env=False)


def _credentials(keys: list[str]) -> dict[str, str]:
    """Identifiants du compte de test : variables ``SESAME_ONBOARD_<CLÉ>``, sinon saisie masquée."""
    creds = {}
    for key in keys:
        value = os.environ.get(f"SESAME_ONBOARD_{key.upper()}")
        if value is None:
            prompt = getpass.getpass if "pass" in key or "secret" in key else input
            value = prompt(f"{key} du compte de test : ")
        creds[key] = value
    return creds


def _emit(record: dict) -> None:
    print(json.dumps(record, ensure_ascii=False, separators=(",", ":")))


def cmd_verify(args: argparse.Namespace) -> int:
    d = descriptors.load(Path(args.descriptor), Path(args.schema))
    creds = _credentials(d["spec"]["credentials"]["keys"])
    with _client(args) as client:
        result = verify.verify(d, creds, client)
    creds.clear()
    record = {"log_type": "verify", "app_id": d["metadata"]["id"], **asdict(result)}
    expected = d["spec"].get("health", {}).get("form_fingerprint")
    if result.fingerprint and expected and expected != result.fingerprint:
        record["warning"] = "form_fingerprint_differs"
    _emit(record)
    return 0 if result.ok else 1


def cmd_health(args: argparse.Namespace) -> int:
    paths = [Path(p) for p in args.paths]
    docs = []
    for p in paths:
        docs.extend(
            descriptors.load_dir(p, Path(args.schema))
            if p.is_dir()
            else [descriptors.load(p, Path(args.schema))]
        )
    if args.app:
        docs = [d for d in docs if d["metadata"]["id"] in args.app]
    healthy = True
    with _client(args) as client:
        for d in docs:
            result = health.check(d, client)
            healthy &= result.healthy
            _emit({"log_type": "health", **asdict(result)})
    return 0 if healthy else 1


def cmd_fingerprint(args: argparse.Namespace) -> int:
    d = descriptors.load(Path(args.descriptor), Path(args.schema))
    spec = d["spec"]
    base = spec["upstream"]["base_url"].rstrip("/") + "/"
    with _client(args) as client:
        resp, _ = get_page(client, urljoin(base, spec["login"]["form_url"]), base, Jar())
    form = (
        parse_form(resp.text, spec["login"].get("form_selector", "form")) if resp.status_code == 200 else None
    )
    if form is None:
        print("formulaire de login introuvable dans le HTML brut", file=sys.stderr)
        return 1
    print(form.fingerprint())
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sesame-onboard", description="Embarquement des applis dans Sesame.")
    p.add_argument("--schema", default=str(descriptors.DEFAULT_SCHEMA), help="schéma JSON des descripteurs")
    p.add_argument("--ca-file", help="CA supplémentaire (PEM) pour joindre les applis")
    p.add_argument("--insecure", action="store_true", help="ne pas vérifier TLS (dev uniquement)")
    p.add_argument("--timeout", type=float, default=15.0)
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify", help="valider un descripteur avec un compte de test (rejeu sans JavaScript)")
    v.add_argument("descriptor")
    v.set_defaults(func=cmd_verify)

    h = sub.add_parser("health", help="test de santé : le formulaire de login a-t-il changé ?")
    h.add_argument("paths", nargs="+", help="descripteurs ou dossiers de descripteurs")
    h.add_argument("--app", action="append", help="limiter à cet identifiant d'appli (répétable)")
    h.set_defaults(func=cmd_health)

    f = sub.add_parser("fingerprint", help="empreinte actuelle du formulaire, à reporter dans le descripteur")
    f.add_argument("descriptor")
    f.set_defaults(func=cmd_fingerprint)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except descriptors.DescriptorError as e:
        print(f"descripteur invalide : {e}", file=sys.stderr)
        return 2
    except (httpx.HTTPError, ValueError) as e:
        print(f"erreur : {type(e).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
