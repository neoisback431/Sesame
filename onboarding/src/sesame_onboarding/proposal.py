# SPDX-License-Identifier: Apache-2.0
"""Descripteur proposé à partir d'une analyse du recorder (:mod:`.record`).

Traduit un :class:`~.record.Recording` en document ``AppDescriptor`` à relire, avec la liste
des points à confirmer, et en constat lisible. Aucune valeur sensible n'y figure : seulement
des noms, des codes, des chemins et des constantes simples observées.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import yaml

from .record import Recording, is_unnamed, path_of, regex_literal


@dataclass
class Draft:
    document: dict[str, Any]
    todo: list[str]
    # Ce qui rend ce descripteur inutilisable dans le mode choisi (en plus de rec.blocking).
    blocking: list[str] = field(default_factory=list)


# Identifiants refusés par le descripteur (miroir de RESERVED_IDS dans descriptor.rs).
RESERVED_IDS = frozenset({"new", "admin", "www"})
# Premiers labels d'hôte qui ne nomment pas l'appli (www.exemple.com, login.exemple.com…).
_GENERIC_LABELS = re.compile(r"www\d*|web|login|auth|sso|secure|m")


def _id_from_host(host: str) -> str:
    """Identifiant proposé d'après l'hôte réel de l'appli : le premier label qui la nomme."""
    if re.fullmatch(r"[0-9.]+|.*:.*", host):  # adresse IP : rien à en tirer
        return "appli"
    for label in host.split("."):
        if label and not _GENERIC_LABELS.fullmatch(label) and _slug(label) not in RESERVED_IDS:
            return label
    return "appli"


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:63].strip("-")
    return slug or "appli"


def to_descriptor(
    rec: Recording,
    *,
    app_id: str | None = None,
    name: str | None = None,
    public_host: str | None = None,
    groups: list[str] | None = None,
    users: list[str] | None = None,
    session_cookie: str | None = None,
    apps_domain: str | None = None,
    handoff: bool = False,
) -> Draft:
    todo: list[str] = []
    host = urlsplit(rec.base_url).hostname or "appli"
    # metadata.id doit être en minuscules-tirets (schéma) : on normalise l'identifiant
    # fourni comme celui déduit de l'hôte, pour ne jamais proposer un descripteur invalide.
    requested_by_caller = bool(app_id)
    requested_id = app_id or _id_from_host(host)
    app_id = _slug(requested_id)
    if app_id != requested_id:
        todo.append(f"metadata.id normalisé en « {app_id} » (minuscules et tirets requis)")
    reserved_id = app_id in RESERVED_IDS
    if reserved_id:
        todo.append(f"metadata.id « {app_id} » est réservé : choisissez-en un autre")
    elif not requested_by_caller:
        todo.append(f"metadata.id « {app_id} » déduit de l'hôte de l'appli : à confirmer")
    if not public_host:
        # Domaine des applis exposées par Sesame, issu de la configuration (ex.
        # « sesame.localhost:8443 » en dev) ; à défaut, un exemple à remplacer.
        domain = (apps_domain or os.environ.get("SESAME_APPS_DOMAIN", "")).strip().strip(".")
        public_host = f"{app_id}.{domain or 'sesame.example'}"
        if not domain:
            todo.append("spec.public.host : hôte public exposé par Sesame (SESAME_APPS_DOMAIN non défini)")
    # spec.access facultatif (ADR 0017) : sans restriction, le compte actif suffit.
    access: dict[str, Any] = {}
    if groups:
        access["groups"] = groups
    if users:
        access["users"] = users

    login_path = urlsplit(rec.form_url).path or "/"
    base = rec.base_url.rstrip("/")
    # Page atteinte après la connexion de test : la tuile du portail y mènera, la racine
    # de certaines applis affichant le formulaire de login même une fois connecté.
    start_path = None
    if rec.login and rec.login.logged_in and rec.login.final_path not in ("/", login_path):
        start_path = rec.login.final_path
    cookie = session_cookie
    # Connexion de test réussie : sa réponse fait foi (statut, cookies), même sans cookie de
    # session (cas d'une session par jeton, où l'élément vit dans la réponse / le stockage local).
    observed = rec.login if rec.login and rec.login.logged_in else None
    if not cookie and observed and observed.session_cookies:
        cookie = observed.session_cookies[0]
    # En handoff avec session par jeton (aucun cookie), le cookie reste vide : la session
    # est remise via local_storage. Sinon, on propose un cookie (ou un repère à renseigner).
    token_handoff = handoff and not cookie and bool(rec.session_token_keys)
    if not cookie and not token_handoff:
        candidates = rec.session_cookie_candidates
        cookie = candidates[0] if len(candidates) == 1 else "SESSION_COOKIE_A_RENSEIGNER"
        todo.append(
            "spec.session.cookies : cookie posé par une connexion réussie (non observable sans identifiants"
            + (f" ; candidat : {cookie}" if candidates else "")
            + ")"
        )

    login: dict[str, Any] = {"form_url": rec.form_url}
    if rec.use_form:
        login["form_selector"] = rec.form_selector or "form"
    else:
        login["use_form"] = False
    action = rec.action
    if not rec.use_form and not action and rec.submission:
        sub_url = rec.submission.url
        action = path_of(sub_url) if rec.submission.method != "GET" else urlsplit(sub_url).path
    if action:
        login["action"] = action
    login["method"] = rec.method
    login["encoding"] = rec.encoding
    if rec.use_form:
        login["include_hidden_inputs"] = rec.sent_hidden is not False
    fields: dict[str, Any] = {}
    # Noms réellement envoyés (une connexion en JavaScript peut renommer les champs, ou
    # utiliser des champs sans attribut name, notés « #n »).
    user_key = rec.sent_username_key or (None if is_unnamed(rec.username_field) else rec.username_field)
    password_key = rec.sent_password_key or (None if is_unnamed(rec.password_field) else rec.password_field)
    if password_key is None:
        password_key = "password"  # noqa: S105 (nom de champ, pas une valeur)
        todo.append("spec.login.fields : nom du champ mot de passe envoyé non observé (« password » supposé)")
    if user_key:
        fields[user_key] = {"from_secret": "username"}
    fields[password_key] = {"from_secret": "password"}
    for key, value in rec.constants.items():
        fields[key] = {"value": value}
    login["fields"] = fields
    if rec.csrf:
        login["csrf"] = rec.csrf
    success: dict[str, Any] = {
        "status": [302, 303],
        "location_not_matches": "^(" + regex_literal(base) + ")?" + regex_literal(login_path),
    }
    if observed and observed.status is not None:
        # Réponse réelle à une connexion réussie : statut observé + cookie de session posé.
        success = {"status": [observed.status]}
        if observed.location and 300 <= observed.status < 400:
            success["location_not_matches"] = (
                "^(" + regex_literal(base) + ")?" + regex_literal(login_path) + "$"
            )
        if cookie in observed.cookies_set:
            success["cookie_set"] = cookie
    elif session_cookie:
        success["cookie_set"] = session_cookie
    login["success"] = {"any_of": [success]}
    if not observed:
        todo.append("spec.login.success : à confirmer avec sesame-onboard verify et un compte de test")
    elif len(observed.session_cookies) > 1 and not session_cookie:
        todo.append(
            "spec.session.cookies : plusieurs cookies posés à la connexion ("
            + ", ".join(observed.session_cookies)
            + ") ; ajouter ceux que l'appli exige"
        )
    failure = _failure_matcher(rec, base)
    if failure:
        login["failure"] = {"any_of": [failure]}
    login["max_attempts"] = 1

    blocking: list[str] = [f"metadata.id « {app_id} » réservé"] if reserved_id else []
    if rec.session_token_keys and not handoff:
        blocking.append(
            "session_token_in_response: " + ", ".join(rec.session_token_keys) + " (session par jeton "
            "renvoyé dans la réponse, envoyé en Authorization par le JavaScript : le proxy ne peut pas "
            "la rejouer ; proposer le mode handoff, ADR 0020)"
        )

    # Session : proxy (défaut) ou handoff (remise au navigateur, ADR 0020).
    if handoff:
        h: dict[str, Any] = {}
        if cookie:
            h["set_cookies"] = [cookie]
        if rec.session_token_keys:
            h["local_storage"] = [{"key": k, "from_response": k} for k in rec.session_token_keys]
        if not h:
            todo.append(
                "spec.session.handoff : élément à remettre au navigateur non détecté "
                "(set_cookies ou local_storage à renseigner)"
            )
        session: dict[str, Any] = {"mode": "handoff"}
        if cookie:
            session["cookies"] = [cookie]
        session["handoff"] = h
    else:
        session = {"cookies": [cookie]}

    doc: dict[str, Any] = {
        "apiVersion": "sesame/v1",
        "kind": "AppDescriptor",
        "metadata": {"id": app_id, "name": name or rec.title or app_id, "revision": 1},
        "spec": {
            "upstream": {"base_url": base},
            "public": {"host": public_host, **({"start_path": start_path} if start_path else {})},
            **({"access": access} if access else {}),
            "credentials": {
                "mode": "per_user",
                "keys": ["username", "password"] if rec.username_field else ["password"],
            },
            "login": login,
            "session": session,
            "expiry": {"any_of": _expiry_matchers(rec, base, login_path)},
            "logout": {"paths": ["^/logout$"]},
            "health": {"interval": "1h"},
        },
    }
    if rec.fingerprint:
        doc["spec"]["health"]["form_fingerprint"] = rec.fingerprint
    todo.append("spec.logout.paths : chemin de déconnexion de l'appli")
    return Draft(doc, todo, blocking)


def _failure_matcher(rec: Recording, base: str) -> dict[str, Any] | None:
    f = rec.failure
    if f is None or f.status is None:
        return None
    matcher: dict[str, Any] = {"status": [f.status]}
    if f.location:
        matcher["location_matches"] = (
            "^(" + regex_literal(base) + ")?" + regex_literal(path_of(urljoin(base, f.location)))
        )
    if f.message:
        matcher["body_contains"] = f.message
    if len(matcher) == 1 and 200 <= f.status < 400:
        return None  # un simple 200 ou 302 ne distingue pas l'échec du succès
    return matcher


def _expiry_matchers(rec: Recording, base: str, login_path: str) -> list[dict[str, Any]]:
    to_login = {
        "status": [302, 303],
        "location_matches": "^(" + regex_literal(base) + ")?" + regex_literal(login_path),
    }
    matchers = [to_login]
    status, location = rec.protected_status, rec.protected_location
    if status in (301, 302, 303, 307, 308) and location:
        target = urlsplit(urljoin(base, location)).path
        if target != login_path:
            matchers[0] = {
                "status": [status],
                "location_matches": "^(" + regex_literal(base) + ")?" + regex_literal(target),
            }
        elif status not in (302, 303):
            matchers[0]["status"] = [status]
    elif status in (401, 403):
        matchers.append({"status": [status]})
    if not any(m == {"status": [401]} for m in matchers):
        matchers.append({"status": [401]})
    return matchers


def render(draft: Draft, rec: Recording) -> str:
    """YAML commenté : origine, points à confirmer, puis le descripteur."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Descripteur proposé par sesame-onboard record le {now},",
        f"# à partir de {rec.login_url} "
        + (
            "(connexion réelle avec un compte de test ; aucune valeur conservée)."
            if rec.login
            else "(sans identifiant ; aucune valeur de page conservée)."
        ),
        "# À relire, puis valider avec : sesame-onboard verify <fichier>",
    ]
    notes = draft.todo + [f"avertissement : {w}" for w in rec.warnings + rec.blocking + draft.blocking]
    if notes:
        lines.append("# À confirmer :")
        lines += [f"#   - {n}" for n in notes]
    body = yaml.safe_dump(draft.document, sort_keys=False, allow_unicode=True, width=100)
    return "\n".join(lines) + "\n" + body


def summary(rec: Recording) -> list[str]:
    """Constat lisible, sans valeur sensible."""
    out = [f"page de login : {rec.login_url}"]
    if rec.form_selector:
        out.append(
            f"formulaire : {rec.form_selector} "
            f"({'présent' if rec.raw_form_found else 'ABSENT'} dans le HTML brut)"
        )
        out.append(f"champs : identifiant={rec.username_field}, mot de passe={rec.password_field}")
        if rec.hidden_fields:
            out.append("champs cachés (renvoyés automatiquement) : " + ", ".join(rec.hidden_fields))
        if rec.other_fields:
            out.append("autres champs (non envoyés par le proxy) : " + ", ".join(rec.other_fields))
    if rec.submission:
        s = rec.submission
        out.append(f"soumission : {s.method} {path_of(s.url)} ({s.resource_type}, encodage {s.encoding})")
    for token in rec.csrf:
        send_as = token.get("send_as", {})
        target = f" → en-tête {send_as['header']}" if "header" in send_as else ""
        out.append(f"jeton CSRF : {token['source']} {token['name']}{target}")
    if rec.page_cookies:
        out.append("cookies posés par la page : " + ", ".join(rec.page_cookies))
    if rec.protected_status is not None:
        target = rec.protected_location
        where = f" → {path_of(urljoin(rec.base_url, target))}" if target else ""
        out.append(f"page protégée {rec.protected_path} sans session : {rec.protected_status}{where}")
    if rec.failure:
        f = rec.failure
        out.append(
            f"échec simulé : statut {f.status}"
            + (f", message « {f.message} »" if f.message else "")
            + (f", cookies {', '.join(f.cookies_set)}" if f.cookies_set else "")
        )
    if rec.login:
        lo = rec.login
        where = f" → {path_of(urljoin(rec.base_url, lo.location))}" if lo.location else ""
        out.append(
            f"connexion de test : statut {lo.status}{where}, "
            + ("connecté" if lo.logged_in else "TOUJOURS SUR LA PAGE DE LOGIN")
            + (f", cookies posés {', '.join(lo.cookies_set)}" if lo.cookies_set else "")
        )
        if lo.session_cookies:
            out.append("cookie(s) de session retenu(s) : " + ", ".join(lo.session_cookies))
        if lo.logged_in:
            out.append(f"page atteinte après connexion : {lo.final_path}")
        if rec.session_token_keys:
            out.append("session par jeton (réponse au login) : " + ", ".join(rec.session_token_keys))
    if rec.submission:
        out.append(
            f"champs envoyés : identifiant={rec.sent_username_key}, mot de passe={rec.sent_password_key}"
        )
        if rec.constants:
            out.append("champs constants envoyés : " + ", ".join(rec.constants))
    out += [f"avertissement : {w}" for w in rec.warnings]
    out += [f"BLOQUANT : {b}" for b in rec.blocking]
    return out
