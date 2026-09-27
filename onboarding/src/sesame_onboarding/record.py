# SPDX-License-Identifier: Apache-2.0
"""Recorder : analyse du comportement d'une page de login pour proposer un descripteur.

Sans aucun identifiant réel. Le recorder ouvre la page dans un navigateur headless
(JavaScript exécuté), repère le formulaire de login, remplit des valeurs factices et
déclenche la soumission **en l'interceptant** : il observe ce que le navigateur
enverrait (méthode, cible, encodage, noms des champs, en-têtes CSRF), puis l'annule.
Rien n'atteint l'appli, sauf avec ``probe_failure`` : la soumission factice est alors
relayée pour observer la réponse d'échec (code, redirection, message d'erreur).

Il compare ensuite avec le HTML brut, tel que le voit le moteur de proxy (sans
JavaScript), et sonde une page protégée pour déduire la règle d'expiration.

Ce qui est conservé et affiché : des noms (champs, cookies, en-têtes), des codes de
statut, des chemins, un message d'erreur visible. Jamais de valeur de champ caché,
de jeton CSRF, de cookie, ni les valeurs factices saisies.
"""

from __future__ import annotations

import contextlib
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
import yaml

from .fingerprint import parse_form
from .http import Jar, get_page, origin, same_origin

CSRF_NAME = re.compile(r"csrf|xsrf|authenticity|verification|nonce|(^|_)token$|^_token$", re.I)
SESSION_NAME = re.compile(r"sess|^sid$|jsessionid|phpsessid|aspnet|connect\.sid|_session|auth", re.I)
USERNAME_NAME = re.compile(r"user|login|mail|ident|account|compte|name", re.I)
ERROR_SELECTORS = (
    "[role=alert], .error, .errors, .alert, .alert-danger, .invalid-feedback, .flash, "
    ".message-error, .login-error, #error, #errors, .notification.is-danger"
)
MAX_MESSAGE = 80
CAPTCHA_SELECTORS = (
    'iframe[src*="recaptcha"], iframe[src*="hcaptcha"], iframe[src*="turnstile"], '
    'iframe[src*="captcha"], .g-recaptcha, .h-captcha, .cf-turnstile'
)

# Extraction de la structure des formulaires, sans aucune valeur.
_ANALYZE_JS = """() => {
  const visible = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  const forms = [...document.forms].map((f, index) => ({
    index,
    id: f.id || null,
    name: f.getAttribute('name'),
    action: f.getAttribute('action'),
    method: (f.getAttribute('method') || 'GET').toUpperCase(),
    fields: [...f.elements].filter(e => e.name).map(e => ({
      tag: e.tagName.toLowerCase(),
      type: (e.getAttribute('type') || (e.tagName === 'INPUT' ? 'text' : e.tagName.toLowerCase()))
        .toLowerCase(),
      name: e.name,
      autocomplete: e.getAttribute('autocomplete'),
      visible: visible(e),
    })),
  }));
  return {
    title: document.title,
    forms,
    orphanPassword: [...document.querySelectorAll('input[type=password]')].some(i => !i.form),
    metas: [...document.querySelectorAll('meta[name]')].map(m => m.getAttribute('name')),
  };
}"""


class RecordError(RuntimeError):
    """Analyse impossible ; message sans valeur sensible."""


@dataclass
class Submission:
    """Ce que le navigateur envoie à la soumission (noms uniquement)."""

    method: str
    url: str
    resource_type: str
    encoding: str  # form | json | query | multipart | other
    field_names: list[str]
    csrf_headers: list[str]


@dataclass
class FailureObservation:
    status: int | None
    location: str | None
    cookies_set: list[str]
    message: str | None


@dataclass
class Recording:
    login_url: str
    base_url: str
    form_url: str
    title: str = ""
    form_selector: str | None = None
    username_field: str | None = None
    password_field: str | None = None
    hidden_fields: list[str] = field(default_factory=list)
    other_fields: list[str] = field(default_factory=list)
    csrf: list[dict[str, Any]] = field(default_factory=list)
    action: str | None = None
    method: str = "POST"
    encoding: str = "form"
    raw_form_found: bool = False
    fingerprint: str | None = None
    page_cookies: list[str] = field(default_factory=list)
    submission: Submission | None = None
    protected_path: str = "/"
    protected_status: int | None = None
    protected_location: str | None = None
    failure: FailureObservation | None = None
    warnings: list[str] = field(default_factory=list)
    blocking: list[str] = field(default_factory=list)

    @property
    def session_cookie_candidates(self) -> list[str]:
        return [c for c in self.page_cookies if SESSION_NAME.search(c)]


def _regex_literal(text: str) -> str:
    """Échappement compris à l'identique par re (Python) et la crate regex (Rust)."""
    return re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", text)


def _path(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def dummy_credentials() -> tuple[str, str]:
    """Valeurs factices : identifiant reconnaissable dans les journaux de l'appli."""
    return f"sesame-recorder-{secrets.token_hex(4)}", secrets.token_urlsafe(18)


def _css_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _selector(form: dict[str, Any], forms: list[dict[str, Any]]) -> str:
    """Sélecteur CSS compris par BeautifulSoup et par le proxy (crate scraper)."""
    if form["id"] and re.fullmatch(r"[A-Za-z][\w-]*", form["id"]):
        return f"form#{form['id']}"
    if form["name"]:
        return f"form[name={_css_string(form['name'])}]"
    if form["action"] and sum(f["action"] == form["action"] for f in forms) == 1:
        return f"form[action={_css_string(form['action'])}]"
    return "form"


def _pick_login_form(forms: list[dict[str, Any]]) -> dict[str, Any] | None:
    with_password = [f for f in forms if any(x["type"] == "password" for x in f["fields"])]
    return with_password[0] if with_password else None


def _pick_username(form: dict[str, Any], password: str) -> str | None:
    candidates = [
        f
        for f in form["fields"]
        if f["tag"] == "input" and f["type"] in ("text", "email", "tel") and f["name"] != password
    ]
    for f in candidates:
        if (f["autocomplete"] or "").lower() in ("username", "email"):
            return f["name"]
    for f in candidates:
        if f["visible"] and USERNAME_NAME.search(f["name"]):
            return f["name"]
    visible = [f for f in candidates if f["visible"]]
    return (visible or candidates or [{"name": None}])[0]["name"]


def _submitted_names(request: Any) -> tuple[str, list[str]]:
    """Encodage et noms des champs envoyés. Les valeurs sont lues puis ignorées."""
    if request.method == "GET":
        return "query", sorted(parse_qs(urlsplit(request.url).query, keep_blank_values=True))
    content_type = (request.header_value("content-type") or "").lower()
    body = request.post_data or ""
    if "application/json" in content_type:
        try:
            data = request.post_data_json
        except ValueError:
            data = None
        return "json", sorted(data) if isinstance(data, dict) else []
    if "application/x-www-form-urlencoded" in content_type:
        return "form", sorted(parse_qs(body, keep_blank_values=True))
    if "multipart/form-data" in content_type:
        return "multipart", sorted(set(re.findall(r'name="([^"]+)"', body)))
    return "other", []


def _cookie_names(set_cookie_headers: list[str]) -> list[str]:
    names = []
    for raw in set_cookie_headers:
        name = raw.split(";", 1)[0].partition("=")[0].strip()
        if name and name not in names:
            names.append(name)
    return names


def _error_message(page: Any, ignored: set[str]) -> str | None:
    """Premier message d'erreur visible apparu après la soumission. ``ignored`` : textes
    déjà présents avant, et valeurs factices saisies (un message qui les reprend est écarté)."""
    try:
        texts = page.locator(ERROR_SELECTORS).all_inner_texts()
    except Exception:  # noqa: BLE001 (page fermée ou en navigation)
        return None
    for text in texts:
        text = " ".join(text.split())
        if text and text not in ignored and not any(v and v in text for v in ignored):
            return text[:MAX_MESSAGE]
    return None


def probe_protected(rec: Recording, client: httpx.Client) -> None:
    """Page protégée sans session : sa réponse sert de règle d'expiration."""
    try:
        resp = client.get(urljoin(rec.base_url, rec.protected_path))
    except httpx.HTTPError as e:
        rec.warnings.append(f"protected_path_unreachable ({type(e).__name__})")
        return
    rec.protected_status = resp.status_code
    rec.protected_location = resp.headers.get("location")
    if resp.status_code < 300:
        rec.warnings.append("protected_path_not_protected")


def check_raw_html(rec: Recording, client: httpx.Client) -> None:
    """Le formulaire existe-t-il dans le HTML brut, comme le proxy le verra ?"""
    try:
        resp, _ = get_page(client, rec.login_url, rec.base_url, Jar())
    except (ValueError, httpx.HTTPError):
        rec.blocking.append("login_page_unreachable_without_javascript")
        return
    form = parse_form(resp.text, rec.form_selector or "form") if resp.status_code == 200 else None
    if form is None or rec.password_field not in form.names:
        rec.blocking.append("login_form_not_found_in_raw_html")
        return
    rec.raw_form_found = True
    rec.fingerprint = form.fingerprint()
    raw_hidden = [name for name, _ in form.hidden]
    added = sorted(set(rec.hidden_fields) - set(raw_hidden))
    if added:
        rec.warnings.append("hidden_fields_added_by_javascript: " + ", ".join(added))
    rec.hidden_fields = raw_hidden
    for name in raw_hidden:
        if CSRF_NAME.search(name) and not any(t["name"] == name for t in rec.csrf):
            rec.csrf.append({"source": "hidden_input", "name": name})


def _analyze_submission(rec: Recording, sub: Submission, secrets_in_page: dict[str, str], sent: dict) -> None:
    """Déduit méthode, cible, encodage et jetons CSRF de la soumission observée."""
    rec.submission = sub
    if not same_origin(sub.url, rec.base_url):
        rec.blocking.append("login_action_foreign_origin")
        return
    rec.method = "GET" if sub.method == "GET" else "POST"
    if sub.encoding == "json":
        rec.encoding = "json"
    elif sub.encoding in ("multipart", "other"):
        rec.warnings.append(f"unsupported_encoding: {sub.encoding}")
    action = _path(sub.url) if sub.method != "GET" else urlsplit(sub.url).path
    if action != rec.form_url:
        rec.action = action
    if sub.resource_type in ("xhr", "fetch"):
        rec.warnings.append("login_submitted_by_javascript")
    # Jetons envoyés en en-tête : d'où vient la valeur ? (comparaison en mémoire)
    for header in sub.csrf_headers:
        value = sent["headers"].get(header)
        source = next((k for k, v in secrets_in_page.items() if v and v == value), None)
        if source is None:
            rec.warnings.append(f"csrf_header_source_unknown: {header}")
            continue
        kind, name = source.split(":", 1)
        rec.csrf.append({"source": kind, "name": name, "send_as": {"header": header}})
    known = {rec.username_field, rec.password_field, *rec.hidden_fields}
    extra = [n for n in sub.field_names if n not in known]
    csrf_fields = [n for n in extra if CSRF_NAME.search(n)]
    for name in csrf_fields:
        field_source = next(
            (k for k, v in secrets_in_page.items() if v and v == sent["fields"].get(name)), None
        )
        if field_source:
            kind, token = field_source.split(":", 1)
            rec.csrf.append({"source": kind, "name": token, "send_as": {"field": name}})
        else:
            rec.warnings.append(f"csrf_field_source_unknown: {name}")
    others = [n for n in extra if n not in csrf_fields]
    if others:
        rec.warnings.append("fields_added_on_submit: " + ", ".join(others))


def record(
    login_url: str,
    client: httpx.Client,
    browser: Any,
    *,
    base_url: str | None = None,
    protected_path: str = "/",
    probe_failure: bool = False,
    timeout: float = 15.0,
    ignore_https_errors: bool = False,
) -> Recording:
    """Analyse la page de login. ``browser`` : navigateur Playwright (API synchrone)."""
    if urlsplit(login_url).scheme not in ("http", "https"):
        raise RecordError("l'URL de login doit être en http ou https")
    base = (base_url or "{}://{}".format(*origin(login_url))).rstrip("/") + "/"
    rec = Recording(login_url=login_url, base_url=base, form_url=_path(login_url))
    rec.protected_path = protected_path
    context = browser.new_context(
        ignore_https_errors=ignore_https_errors, accept_downloads=False, service_workers="block"
    )
    context.set_default_timeout(timeout * 1000)
    state: dict[str, Any] = {"armed": False, "request": None}

    def route(route: Any, request: Any) -> None:
        submission_like = request.resource_type == "document" or (
            request.method != "GET" and request.resource_type in ("xhr", "fetch")
        )
        if state["armed"] and state["request"] is None and submission_like:
            state["request"] = request
            if probe_failure and same_origin(request.url, base):
                route.continue_()
            else:
                route.abort()
            return
        if request.method != "GET" and (state["request"] is not None or not same_origin(request.url, base)):
            # Aucune écriture hors de l'appli, et une seule soumission au plus.
            route.abort()
            return
        route.continue_()

    try:
        page = context.new_page()
        page.route("**/*", route)
        page.goto(login_url, wait_until="load")
        with contextlib.suppress(Exception):  # pages qui interrogent en continu
            page.wait_for_load_state("networkidle", timeout=5000)
        if not same_origin(page.url, base):
            rec.blocking.append("login_page_redirects_away")
            return rec
        rec.login_url, rec.form_url = page.url, _path(page.url)
        info = page.evaluate(_ANALYZE_JS)
        rec.title = info["title"] or ""
        rec.page_cookies = sorted({c["name"] for c in context.cookies()})
        if page.locator(CAPTCHA_SELECTORS).count():
            rec.blocking.append("captcha_detected")
        form = _pick_login_form(info["forms"])
        if form is None:
            if info["orphanPassword"]:
                rec.blocking.append("password_field_outside_form")
            elif any(
                f["visible"] and f["type"] in ("text", "email") for x in info["forms"] for f in x["fields"]
            ):
                rec.blocking.append("multi_step_login_suspected")
            else:
                rec.blocking.append("login_form_not_found")
            return rec
        rec.form_selector = _selector(form, info["forms"])
        passwords = [f["name"] for f in form["fields"] if f["type"] == "password"]
        rec.password_field = passwords[0]
        if len(passwords) > 1:
            rec.warnings.append("several_password_fields")
        rec.username_field = _pick_username(form, rec.password_field)
        if rec.username_field is None:
            rec.blocking.append("username_field_not_found")
        rec.hidden_fields = [f["name"] for f in form["fields"] if f["type"] == "hidden"]
        rec.other_fields = [
            f["name"]
            for f in form["fields"]
            if f["name"] not in (rec.username_field, rec.password_field, *rec.hidden_fields)
            and f["type"] not in ("submit", "button", "reset", "image")
        ]
        rec.method = form["method"] if form["method"] in ("GET", "POST") else "POST"
        dom_form = page.locator("form").nth(form["index"])

        # Valeurs de jetons présentes sur la page : servent seulement à reconnaître la
        # source d'un en-tête ou d'un champ envoyé, puis sont oubliées.
        in_page: dict[str, str] = {}
        for name in info["metas"]:
            if CSRF_NAME.search(name):
                content = page.locator(f"meta[name={_css_string(name)}]").first.get_attribute("content")
                in_page[f"meta:{name}"] = content or ""
        for c in context.cookies():
            if CSRF_NAME.search(c["name"]):
                in_page[f"cookie:{c['name']}"] = c["value"]
        for name in rec.hidden_fields:
            loc = dom_form.locator(f"input[type=hidden][name={_css_string(name)}]").first
            in_page[f"hidden_input:{name}"] = loc.get_attribute("value") or ""

        before = {" ".join(t.split()) for t in page.locator(ERROR_SELECTORS).all_inner_texts()}
        user, password = dummy_credentials()
        if rec.username_field:
            kind = next(f["type"] for f in form["fields"] if f["name"] == rec.username_field)
            # Format attendu par le champ, sinon la validation du navigateur bloque la soumission.
            value = f"{user}@example.invalid" if kind == "email" else user
            dom_form.locator(f"[name={_css_string(rec.username_field)}]").first.fill(value)
        dom_form.locator(f"[name={_css_string(rec.password_field)}]").first.fill(password)
        state["armed"] = True
        button = dom_form.locator("button[type=submit], input[type=submit], button:not([type])")
        if button.count():
            button.first.click(no_wait_after=True)
        else:
            dom_form.locator(f"[name={_css_string(rec.password_field)}]").first.press("Enter")
        deadline = time.monotonic() + timeout
        while state["request"] is None and time.monotonic() < deadline:
            page.wait_for_timeout(100)
        request = state["request"]
        if request is None:
            rec.blocking.append("submission_not_observed")
        else:
            encoding, names = _submitted_names(request)
            headers = request.headers
            csrf_headers = [h for h in headers if CSRF_NAME.search(h)]
            sent = {"headers": headers, "fields": _submitted_values(request, encoding)}
            sub = Submission(
                request.method, request.url, request.resource_type, encoding, names, csrf_headers
            )
            _analyze_submission(rec, sub, in_page, sent)
            sent.clear()
            if probe_failure and same_origin(request.url, base):
                rec.failure = _observe_failure(page, request, before | {user, password})
        in_page.clear()
        del user, password
    finally:
        context.close()
    check_raw_html(rec, client)
    probe_protected(rec, client)
    return rec


def _submitted_values(request: Any, encoding: str) -> dict[str, str]:
    """Valeurs envoyées, pour la seule comparaison des jetons CSRF (jamais conservées)."""
    if encoding == "form":
        return {k: v[0] for k, v in parse_qs(request.post_data or "", keep_blank_values=True).items()}
    if encoding == "json":
        try:
            data = request.post_data_json
        except ValueError:
            return {}
        return {k: v for k, v in data.items() if isinstance(v, str)} if isinstance(data, dict) else {}
    if encoding == "query":
        return {k: v[0] for k, v in parse_qs(urlsplit(request.url).query, keep_blank_values=True).items()}
    return {}


def _observe_failure(page: Any, request: Any, before: set[str]) -> FailureObservation:
    response = request.response()
    with contextlib.suppress(Exception):
        page.wait_for_load_state("load")
        page.wait_for_load_state("networkidle", timeout=5000)
    if response is None:
        return FailureObservation(None, None, [], _error_message(page, before))
    set_cookies = [h["value"] for h in response.headers_array() if h["name"].lower() == "set-cookie"]
    return FailureObservation(
        response.status,
        response.header_value("location"),
        _cookie_names(set_cookies),
        _error_message(page, before),
    )


# --- Descripteur proposé ------------------------------------------------------------


@dataclass
class Draft:
    document: dict[str, Any]
    todo: list[str]


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
) -> Draft:
    todo: list[str] = []
    host = urlsplit(rec.base_url).hostname or "appli"
    # metadata.id doit être en minuscules-tirets (schéma) : on normalise l'identifiant
    # fourni comme celui déduit de l'hôte, pour ne jamais proposer un descripteur invalide.
    requested_id = app_id or host.split(".")[0]
    app_id = _slug(requested_id)
    if app_id != requested_id:
        todo.append(f"metadata.id normalisé en « {app_id} » (minuscules et tirets requis)")
    if not public_host:
        public_host = f"{app_id}.sesame.example"
        todo.append("spec.public.host : hôte public exposé par Sesame")
    access: dict[str, Any] = {}
    if groups:
        access["groups"] = groups
    if users:
        access["users"] = users
    if not access:
        access["groups"] = [f"{app_id}-users"]
        todo.append("spec.access : groupes ou utilisateurs habilités")

    login_path = urlsplit(rec.form_url).path or "/"
    base = rec.base_url.rstrip("/")
    cookie = session_cookie
    if not cookie:
        candidates = rec.session_cookie_candidates
        cookie = candidates[0] if len(candidates) == 1 else "SESSION_COOKIE_A_RENSEIGNER"
        todo.append(
            "spec.session.cookies : cookie posé par une connexion réussie (non observable sans identifiants"
            + (f" ; candidat : {cookie}" if candidates else "")
            + ")"
        )

    login: dict[str, Any] = {"form_url": rec.form_url, "form_selector": rec.form_selector or "form"}
    if rec.action:
        login["action"] = rec.action
    login["method"] = rec.method
    login["encoding"] = rec.encoding
    login["include_hidden_inputs"] = True
    fields: dict[str, Any] = {}
    if rec.username_field:
        fields[rec.username_field] = {"from_secret": "username"}
    fields[rec.password_field or "password"] = {"from_secret": "password"}
    login["fields"] = fields
    if rec.csrf:
        login["csrf"] = rec.csrf
    success: dict[str, Any] = {
        "status": [302, 303],
        "location_not_matches": "^(" + _regex_literal(base) + ")?" + _regex_literal(login_path),
    }
    if session_cookie:
        success["cookie_set"] = session_cookie
    login["success"] = {"any_of": [success]}
    todo.append("spec.login.success : à confirmer avec sesame-onboard verify et un compte de test")
    failure = _failure_matcher(rec, base)
    if failure:
        login["failure"] = {"any_of": [failure]}
    login["max_attempts"] = 1

    doc: dict[str, Any] = {
        "apiVersion": "sesame/v1",
        "kind": "AppDescriptor",
        "metadata": {"id": app_id, "name": name or rec.title or app_id, "revision": 1},
        "spec": {
            "upstream": {"base_url": base},
            "public": {"host": public_host},
            "access": access,
            "credentials": {
                "mode": "per_user",
                "keys": ["username", "password"] if rec.username_field else ["password"],
            },
            "login": login,
            "session": {"cookies": [cookie]},
            "expiry": {"any_of": _expiry_matchers(rec, base, login_path)},
            "logout": {"paths": ["^/logout$"]},
            "health": {"interval": "1h"},
        },
    }
    if rec.fingerprint:
        doc["spec"]["health"]["form_fingerprint"] = rec.fingerprint
    todo.append("spec.logout.paths : chemin de déconnexion de l'appli")
    return Draft(doc, todo)


def _failure_matcher(rec: Recording, base: str) -> dict[str, Any] | None:
    f = rec.failure
    if f is None or f.status is None:
        return None
    matcher: dict[str, Any] = {"status": [f.status]}
    if f.location:
        matcher["location_matches"] = (
            "^(" + _regex_literal(base) + ")?" + _regex_literal(_path(urljoin(base, f.location)))
        )
    if f.message:
        matcher["body_contains"] = f.message
    if len(matcher) == 1 and 200 <= f.status < 400:
        return None  # un simple 200 ou 302 ne distingue pas l'échec du succès
    return matcher


def _expiry_matchers(rec: Recording, base: str, login_path: str) -> list[dict[str, Any]]:
    to_login = {
        "status": [302, 303],
        "location_matches": "^(" + _regex_literal(base) + ")?" + _regex_literal(login_path),
    }
    matchers = [to_login]
    status, location = rec.protected_status, rec.protected_location
    if status in (301, 302, 303, 307, 308) and location:
        target = urlsplit(urljoin(base, location)).path
        if target != login_path:
            matchers[0] = {
                "status": [status],
                "location_matches": "^(" + _regex_literal(base) + ")?" + _regex_literal(target),
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
        f"# à partir de {rec.login_url} (sans identifiant ; aucune valeur de page conservée).",
        "# À relire, puis valider avec : sesame-onboard verify <fichier>",
    ]
    notes = draft.todo + [f"avertissement : {w}" for w in rec.warnings + rec.blocking]
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
        out.append(f"soumission : {s.method} {_path(s.url)} ({s.resource_type}, encodage {s.encoding})")
    for token in rec.csrf:
        send_as = token.get("send_as", {})
        target = f" → en-tête {send_as['header']}" if "header" in send_as else ""
        out.append(f"jeton CSRF : {token['source']} {token['name']}{target}")
    if rec.page_cookies:
        out.append("cookies posés par la page : " + ", ".join(rec.page_cookies))
    if rec.protected_status is not None:
        where = f" → {_path(urljoin(rec.base_url, rec.protected_location))}" if rec.protected_location else ""
        out.append(f"page protégée {rec.protected_path} sans session : {rec.protected_status}{where}")
    if rec.failure:
        f = rec.failure
        out.append(
            f"échec simulé : statut {f.status}"
            + (f", message « {f.message} »" if f.message else "")
            + (f", cookies {', '.join(f.cookies_set)}" if f.cookies_set else "")
        )
    out += [f"avertissement : {w}" for w in rec.warnings]
    out += [f"BLOQUANT : {b}" for b in rec.blocking]
    return out
