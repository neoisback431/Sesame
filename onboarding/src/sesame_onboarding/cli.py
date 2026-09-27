# SPDX-License-Identifier: Apache-2.0
"""Ligne de commande ``sesame-onboard`` : ``record``, ``verify``, ``health``, ``fingerprint``.

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


def _chromium(explicit: str | None) -> str | None:
    """Chromium à utiliser : option, ``SESAME_ONBOARD_CHROMIUM``, sinon celui de Playwright."""
    return explicit or os.environ.get("SESAME_ONBOARD_CHROMIUM") or None


def cmd_record(args: argparse.Namespace) -> int:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "Playwright absent : pip install 'sesame-onboarding[capture]' puis playwright install chromium",
            file=sys.stderr,
        )
        return 2
    from . import record

    if args.probe_failure:
        print(
            "sonde d'échec : une connexion avec un identifiant factice (sesame-recorder-…) "
            "sera envoyée à l'appli",
            file=sys.stderr,
        )
    try:
        with sync_playwright() as p, _client(args) as client:
            browser = p.chromium.launch(executable_path=_chromium(args.chromium))
            try:
                rec = record.record(
                    args.login_url,
                    client,
                    browser,
                    base_url=args.base_url,
                    protected_path=args.protected_path,
                    probe_failure=args.probe_failure,
                    timeout=args.timeout,
                    ignore_https_errors=args.insecure,
                )
            finally:
                browser.close()
    except PlaywrightError as e:
        print(f"navigateur : {str(e).splitlines()[0][:200]}", file=sys.stderr)
        return 1
    except record.RecordError as e:
        print(f"erreur : {e}", file=sys.stderr)
        return 2
    for line in record.summary(rec):
        print(line, file=sys.stderr)
    if rec.password_field is None:
        return 1
    draft = record.to_descriptor(
        rec,
        app_id=args.id,
        name=args.name,
        public_host=args.public_host,
        groups=args.group,
        users=args.user,
        session_cookie=args.session_cookie,
    )
    errors = descriptors.validate(draft.document, Path(args.schema))
    if errors:
        print("descripteur proposé invalide : " + errors[0], file=sys.stderr)
        return 1
    text = record.render(draft, rec)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"descripteur écrit dans {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 1 if rec.blocking else 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sesame-onboard", description="Embarquement des applis dans Sesame.")
    p.add_argument("--schema", default=str(descriptors.DEFAULT_SCHEMA), help="schéma JSON des descripteurs")
    p.add_argument("--ca-file", help="CA supplémentaire (PEM) pour joindre les applis")
    p.add_argument("--insecure", action="store_true", help="ne pas vérifier TLS (dev uniquement)")
    p.add_argument("--timeout", type=float, default=15.0)
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser(
        "record", help="analyser une page de login (navigateur headless) et proposer un descripteur"
    )
    r.add_argument("login_url", help="URL de la page de login, telle que le proxy la joint")
    r.add_argument("--base-url", help="URL de base de l'appli (défaut : origine de la page de login)")
    r.add_argument("--protected-path", default="/", help="page protégée sondée sans session (défaut : /)")
    r.add_argument(
        "--probe-failure",
        action="store_true",
        help="envoyer une connexion factice pour observer la réponse d'échec",
    )
    r.add_argument("--id", help="metadata.id")
    r.add_argument("--name", help="metadata.name (défaut : titre de la page)")
    r.add_argument("--public-host", help="hôte public exposé par Sesame")
    r.add_argument("--group", action="append", help="groupe habilité (répétable)")
    r.add_argument("--user", action="append", help="utilisateur habilité (répétable)")
    r.add_argument("--session-cookie", help="cookie de session de l'appli, s'il est connu")
    r.add_argument("--chromium", help="exécutable Chromium (défaut : SESAME_ONBOARD_CHROMIUM ou Playwright)")
    r.add_argument("-o", "--output", help="fichier du descripteur (défaut : sortie standard)")
    r.set_defaults(func=cmd_record)

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
