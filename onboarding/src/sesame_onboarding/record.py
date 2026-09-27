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

Avec un **compte de test** (``credentials``, ADR 0019), une connexion réelle est ensuite
observée dans un contexte neuf (:func:`observe_login`) : requête qui transporte le mot de
passe (formulaire ou JavaScript), source de chaque jeton, réponse et cookie de session.
Le descripteur proposé est alors complet (succès et cookie de session observés).

Les deux passes (soumission factice, connexion de test) analysent la requête observée de
la même façon (:func:`_analyze_request`, :class:`TokenSources`). Le descripteur proposé est
rédigé par :mod:`.proposal`.

Ce qui est conservé et affiché : des noms (champs, cookies, en-têtes), des codes de
statut, des chemins, un message d'erreur visible, des constantes simples envoyées.
Jamais de valeur de champ caché, de jeton CSRF, de cookie, ni les identifiants saisis.
"""

from __future__ import annotations

import contextlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, quote, quote_plus, urljoin, urlsplit

import httpx

from .fingerprint import parse_form
from .http import Jar, get_page, origin, same_origin

CSRF_NAME = re.compile(r"csrf|xsrf|authenticity|verification|nonce|(^|_)token$|^_token$", re.I)
_CSRF_COOKIE = re.compile(r"csrf|xsrf", re.I)
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
    // Champs sans attribut name (fréquent avec React) : clé positionnelle « #n », n étant
    // le rang parmi les input/select/textarea du formulaire.
    fields: [...f.querySelectorAll('input, select, textarea')].map((e, pos) => ({
      tag: e.tagName.toLowerCase(),
      type: (e.getAttribute('type') || (e.tagName === 'INPUT' ? 'text' : e.tagName.toLowerCase()))
        .toLowerCase(),
      name: e.getAttribute('name') || ('#' + pos),
      named: !!e.getAttribute('name'),
      autocomplete: e.getAttribute('autocomplete'),
      visible: visible(e),
    })).filter(x => x.named || x.tag === 'input'),
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
class LoginObservation:
    """Réponse à la connexion réelle avec le compte de test : codes, noms et chemins."""

    status: int | None
    location: str | None
    cookies_set: list[str]  # Set-Cookie de la réponse à la requête de login
    new_cookies: list[str]  # cookies apparus ou modifiés dans le navigateur après connexion
    final_path: str  # chemin atteint après connexion (sans chaîne de requête)
    logged_in: bool  # plus de champ mot de passe visible après connexion

    @property
    def session_cookies(self) -> list[str]:
        seen = list(dict.fromkeys(self.cookies_set + self.new_cookies))
        # Seuls les noms explicitement CSRF sont écartés (un cookie « token » peut être la session).
        plain = [c for c in seen if not _CSRF_COOKIE.search(c)]
        return [c for c in plain if SESSION_NAME.search(c)] or plain


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
    login: LoginObservation | None = None
    form_index: int = 0
    session_token_keys: list[str] = field(default_factory=list)  # session par jeton (handoff)
    use_form: bool = True  # False : formulaire absent du HTML servi (construit en JavaScript)
    # Déduits de la requête de login observée (soumission factice, puis connexion de test) :
    sent_username_key: str | None = None  # nom réel du champ identifiant envoyé
    sent_password_key: str | None = None  # nom réel du champ mot de passe envoyé
    sent_hidden: bool | None = None  # les champs cachés du formulaire sont-ils envoyés ?
    constants: dict[str, str] = field(default_factory=dict)  # autres champs simples envoyés
    warnings: list[str] = field(default_factory=list)
    blocking: list[str] = field(default_factory=list)

    @property
    def session_cookie_candidates(self) -> list[str]:
        return [c for c in self.page_cookies if SESSION_NAME.search(c)]


def regex_literal(text: str) -> str:
    """Échappement compris à l'identique par re (Python) et la crate regex (Rust)."""
    return re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", text)


def path_of(url: str) -> str:
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


def _field(form: Any, key: str) -> Any:
    """Champ du formulaire (locator Playwright) : par nom, ou par rang pour une clé « #n »."""
    if key.startswith("#") and key[1:].isdigit():
        return form.locator("input, select, textarea").nth(int(key[1:]))
    return form.locator(f"[name={_css_string(key)}]").first


def is_unnamed(key: str | None) -> bool:
    return bool(key) and key.startswith("#")


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
        sub = rec.submission
        if sub is not None and same_origin(sub.url, rec.base_url) and resp.status_code == 200:
            # Formulaire construit en JavaScript : rejeu sans formulaire, vers la cible observée.
            rec.use_form = False
            rec.warnings.append("login_form_built_by_javascript: rejeu sans formulaire (use_form: false)")
        else:
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


# En-têtes posés par le navigateur lui-même : jamais des jetons applicatifs.
_BROWSER_HEADERS = re.compile(
    r"^(accept.*|content-(type|length)|cookie|user-agent|origin|referer|host|connection|sec-.*|"
    r"upgrade-insecure-requests|cache-control|pragma|priority|dnt)$",
    re.I,
)
_VALUE_CHARS = r"[^\"'<>\s]+"
_CONSTANT = re.compile(r"[\w.@:/+-]{0,64}")
_TOKEN_KEY = re.compile(r"token|jwt|bearer", re.I)
# Avertissements produits par _analyze_request : recalculés à chaque requête analysée.
_REQUEST_WARNINGS = (
    "csrf_",
    "login_submitted_by_javascript",
    "field_not_reproduced",
    "unsupported_encoding",
    "nested_json_body_unsupported",
    "password_field_not_found_in_request",
)


class TokenSources:
    """Valeurs candidates comme jetons, par source que le proxy sait reproduire : cookies,
    balises meta et champs cachés de la page, HTML servi (``regex``), réponses des appels GET
    faits par le JavaScript avant la soumission (``endpoint``). En mémoire seulement, le
    temps de reconnaître la source d'un en-tête ou d'un champ envoyé, puis effacées."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.raw_html = ""
        self.api_bodies: dict[str, str] = {}

    def watch_api(self, page: Any, base: str, active: Any) -> None:
        """Conserve les réponses aux appels GET du JavaScript tant que ``active()`` est vrai."""

        def on_response(response: Any) -> None:
            req = response.request
            if (
                active()
                and req.method == "GET"
                and req.resource_type in ("xhr", "fetch")
                and same_origin(req.url, base)
                and response.ok
            ):
                with contextlib.suppress(Exception):
                    self.api_bodies[path_of(req.url)] = response.text()[:65536]

        page.on("response", on_response)

    def collect(self, page: Any, context: Any, form: Any) -> None:
        for c in context.cookies():
            self.values.setdefault(f"cookie:{c['name']}", c["value"])
        for meta in page.locator("meta[name][content]").all():
            self.values.setdefault(f"meta:{meta.get_attribute('name')}", meta.get_attribute("content") or "")
        for hidden in form.locator("input[type=hidden][name]").all():
            self.values.setdefault(
                f"hidden_input:{hidden.get_attribute('name')}", hidden.get_attribute("value") or ""
            )

    def hidden(self, name: str) -> str | None:
        return self.values.get(f"hidden_input:{name}")

    def locate(self, value: str, label: str, send_as: dict[str, str], *, deep: bool) -> dict[str, Any] | None:
        """Entrée ``login.csrf`` reproduisant ``value``, ou ``None``. ``deep`` : chercher aussi
        dans le HTML servi et les réponses d'API (sinon, valeurs exactes de la page seulement,
        pour ne pas prendre une constante écrite dans un script pour un jeton)."""
        if len(value) < 4:
            return None
        for key, candidate in self.values.items():
            if candidate == value:
                kind, name = key.split(":", 1)
                return {"source": kind, "name": name, "send_as": send_as}
        if not deep:
            return None
        pattern = _regex_source(self.raw_html, value)
        if pattern:
            return {"source": "regex", "name": label, "pattern": pattern, "send_as": send_as}
        for api, body in self.api_bodies.items():
            if len(value) < 8 or value not in body:
                continue
            # Jeton obtenu par un appel GET du JavaScript avant le login : le proxy le refait.
            path = _json_path(body, value)
            if path:
                return {"source": "endpoint", "url": api, "name": path, "send_as": send_as}
            pattern = _regex_source(body, value)
            if pattern:
                return {
                    "source": "endpoint",
                    "url": api,
                    "name": label,
                    "pattern": pattern,
                    "send_as": send_as,
                }
        return None

    def clear(self) -> None:
        self.values.clear()
        self.api_bodies.clear()
        self.raw_html = ""


def _analyze_request(rec: Recording, request: Any, sources: TokenSources, user: str, password: str) -> None:
    """Déduit de la requête de login observée (factice ou réelle) : cible, méthode, encodage,
    noms réels des champs identifiant / mot de passe, jetons (source de chaque en-tête ou champ
    non posé par le navigateur), constantes simples. ``user`` et ``password`` ne servent qu'à
    reconnaître les champs qui les portent ; aucune valeur n'est conservée."""
    encoding, names = _submitted_names(request)
    sent = _submitted_values(request, encoding)
    headers = request.headers
    sub = Submission(
        request.method,
        request.url,
        request.resource_type,
        encoding,
        names,
        [h for h in headers if not _BROWSER_HEADERS.match(h)],
    )
    rec.warnings = [w for w in rec.warnings if not w.startswith(_REQUEST_WARNINGS)]
    rec.submission = sub
    try:
        if not same_origin(sub.url, rec.base_url):
            rec.blocking.append("login_action_foreign_origin")
            return
        rec.method = "GET" if sub.method == "GET" else "POST"
        rec.encoding = "json" if encoding == "json" else "form"
        if encoding in ("multipart", "other"):
            rec.warnings.append(f"unsupported_encoding: {encoding}")
        action = path_of(sub.url) if sub.method != "GET" else urlsplit(sub.url).path
        rec.action = action if action != rec.form_url else None
        if sub.resource_type in ("xhr", "fetch"):
            rec.warnings.append("login_submitted_by_javascript")
        raw = _raw_json(request)
        if isinstance(raw, dict) and any(isinstance(v, dict | list) for v in raw.values()):
            rec.warnings.append("nested_json_body_unsupported")

        csrf: list[dict[str, Any]] = []
        for header in sub.csrf_headers:
            token = sources.locate(headers.get(header, ""), header, {"header": header}, deep=True)
            if token:
                csrf.append(token)
            elif CSRF_NAME.search(header):
                rec.warnings.append(f"csrf_header_source_unknown: {header}")

        rec.sent_username_key = next((k for k, v in sent.items() if v == user), None)
        rec.sent_password_key = next((k for k, v in sent.items() if v == password), None)
        if rec.sent_password_key is None:
            rec.warnings.append("password_field_not_found_in_request")
        hidden = set(rec.hidden_fields)
        rec.sent_hidden = any(h in sent for h in hidden)
        constants: dict[str, str] = {}
        for key, value in sent.items():
            if key in (rec.sent_username_key, rec.sent_password_key):
                continue
            if key in hidden and sources.hidden(key) == value:
                continue  # renvoyé tel quel par include_hidden_inputs
            token = sources.locate(value, key, {"field": key}, deep=bool(CSRF_NAME.search(key)))
            if token:
                csrf.append(token)
            elif CSRF_NAME.search(key):
                rec.warnings.append(f"csrf_field_source_unknown: {key}")
            elif _CONSTANT.fullmatch(value) and not _carries(value, password) and not _carries(value, user):
                constants[key] = value
            else:
                rec.warnings.append(f"field_not_reproduced: {key}")
        rec.csrf = csrf
        rec.constants = constants
    finally:
        sent.clear()


def _new_context(browser: Any, timeout: float, ignore_https_errors: bool) -> Any:
    context = browser.new_context(
        ignore_https_errors=ignore_https_errors, accept_downloads=False, service_workers="block"
    )
    context.set_default_timeout(timeout * 1000)
    return context


def _response_text(response: Any) -> str:
    with contextlib.suppress(Exception):
        return response.text() if response else ""
    return ""


def _submit(page: Any, form: Any, password_field: str) -> None:
    button = form.locator("button[type=submit], input[type=submit], button:not([type])")
    if button.count():
        button.first.click(no_wait_after=True)
    else:
        _field(form, password_field).press("Enter")


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
    credentials: tuple[str, str] | None = None,
) -> Recording:
    """Analyse la page de login. ``browser`` : navigateur Playwright (API synchrone).

    ``credentials`` : compte de test (identifiant, mot de passe). Une connexion réelle est
    alors observée (voir :func:`observe_login`) ; les valeurs ne sont jamais conservées."""
    if urlsplit(login_url).scheme not in ("http", "https"):
        raise RecordError("l'URL de login doit être en http ou https")
    base = (base_url or "{}://{}".format(*origin(login_url))).rstrip("/") + "/"
    rec = Recording(login_url=login_url, base_url=base, form_url=path_of(login_url))
    rec.protected_path = protected_path
    context = _new_context(browser, timeout, ignore_https_errors)
    state: dict[str, Any] = {"armed": False, "request": None}
    sources = TokenSources()

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
        sources.watch_api(page, base, lambda: not state["armed"])
        sources.raw_html = _response_text(page.goto(login_url, wait_until="load"))
        with contextlib.suppress(Exception):  # pages qui interrogent en continu
            page.wait_for_load_state("networkidle", timeout=5000)
        with contextlib.suppress(Exception):  # formulaire rendu tardivement par le JavaScript
            page.wait_for_selector("input[type=password]", state="visible", timeout=min(timeout, 10) * 1000)
        if not same_origin(page.url, base):
            rec.blocking.append("login_page_redirects_away")
            return rec
        rec.login_url, rec.form_url = page.url, path_of(page.url)
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
        rec.form_index = form["index"]
        rec.hidden_fields = [f["name"] for f in form["fields"] if f["type"] == "hidden" and f["named"]]
        rec.other_fields = [
            f["name"]
            for f in form["fields"]
            if f["named"]
            and f["name"] not in (rec.username_field, rec.password_field, *rec.hidden_fields)
            and f["type"] not in ("submit", "button", "reset", "image")
        ]
        rec.method = form["method"] if form["method"] in ("GET", "POST") else "POST"
        dom_form = page.locator("form").nth(form["index"])
        sources.collect(page, context, dom_form)

        before = {" ".join(t.split()) for t in page.locator(ERROR_SELECTORS).all_inner_texts()}
        user, password = dummy_credentials()
        if rec.username_field:
            kind = next(f["type"] for f in form["fields"] if f["name"] == rec.username_field)
            # Format attendu par le champ, sinon la validation du navigateur bloque la soumission.
            user = f"{user}@example.invalid" if kind == "email" else user
            _field(dom_form, rec.username_field).fill(user)
        _field(dom_form, rec.password_field).fill(password)
        state["armed"] = True
        _submit(page, dom_form, rec.password_field)
        deadline = time.monotonic() + timeout
        while state["request"] is None and time.monotonic() < deadline:
            page.wait_for_timeout(100)
        request = state["request"]
        if request is None:
            rec.blocking.append("submission_not_observed")
        else:
            _analyze_request(rec, request, sources, user, password)
            if probe_failure and same_origin(request.url, base):
                rec.failure = _observe_failure(page, request, before | {user, password})
        user = password = ""  # noqa: F841 (références effacées)
    finally:
        sources.clear()
        context.close()
    if credentials and rec.password_field and not rec.blocking:
        observe_login(rec, browser, credentials, timeout=timeout, ignore_https_errors=ignore_https_errors)
    check_raw_html(rec, client)
    probe_protected(rec, client)
    return rec


def _carries(text: str, secret: str) -> bool:
    """La valeur figure-t-elle dans ``text``, brute ou encodée (formulaire, URL, JSON) ?"""
    if not secret or not text:
        return False
    forms = {secret, quote_plus(secret), quote(secret, safe=""), json.dumps(secret)[1:-1]}
    return any(f in text for f in forms)


def _regex_source(html: str, value: str) -> str | None:
    """Expression à un groupe de capture retrouvant ``value`` dans ``html`` d'après son contexte."""
    at = html.find(value)
    if at < 0 or len(value) < 8:
        return None
    before = html[max(0, at - 24) : at]
    after = html[at + len(value) : at + len(value) + 1]
    if not before.strip():
        return None
    pattern = re.escape(before) + f"({_VALUE_CHARS})" + (re.escape(after) if after else "")
    match = re.search(pattern, html)
    return pattern if match and match.group(1) == value else None


def observe_login(
    rec: Recording,
    browser: Any,
    credentials: tuple[str, str],
    *,
    timeout: float = 15.0,
    ignore_https_errors: bool = False,
) -> None:
    """Connexion réelle avec un compte de test, dans un contexte de navigateur neuf.

    Repère la requête qui transporte le mot de passe (formulaire ou JavaScript), la laisse
    partir vers l'appli (seule écriture autorisée), l'analyse comme la soumission factice
    (:func:`_analyze_request`), puis observe la réponse : statut, redirection, cookies posés,
    cookie de session ou jeton renvoyé, page atteinte. Les valeurs (identifiants, jetons,
    cookies) ne servent qu'à des comparaisons en mémoire et ne sont jamais conservées.
    """
    user, password = credentials
    base = rec.base_url
    context = _new_context(browser, timeout, ignore_https_errors)
    state: dict[str, Any] = {"request": None, "foreign": False}
    sources = TokenSources()

    def route(route: Any, request: Any) -> None:
        try:
            data = request.post_data or ""
        except Exception:  # corps binaire
            data = ""
        if state["request"] is None and (_carries(data, password) or _carries(request.url, password)):
            if not same_origin(request.url, base):
                state["foreign"] = True
                route.abort()
                return
            state["request"] = request
            route.continue_()
            return
        if request.method != "GET" and (state["request"] is not None or not same_origin(request.url, base)):
            route.abort()  # aucune autre écriture : une seule connexion, rien hors de l'appli
            return
        route.continue_()

    try:
        page = context.new_page()
        page.route("**/*", route)
        sources.watch_api(page, base, lambda: state["request"] is None)
        sources.raw_html = _response_text(page.goto(rec.login_url, wait_until="load"))
        with contextlib.suppress(Exception):
            page.wait_for_load_state("networkidle", timeout=5000)
        before = {c["name"]: c["value"] for c in context.cookies()}
        form = page.locator("form").nth(rec.form_index)
        sources.collect(page, context, form)

        if rec.username_field:
            _field(form, rec.username_field).fill(user)
        _field(form, rec.password_field or "password").fill(password)
        _submit(page, form, rec.password_field or "password")
        deadline = time.monotonic() + timeout
        while state["request"] is None and not state["foreign"] and time.monotonic() < deadline:
            page.wait_for_timeout(100)
        request = state["request"]
        if state["foreign"]:
            rec.blocking.append("login_action_foreign_origin")
            return
        if request is None:
            rec.warnings.append("test_login_not_observed")
            return
        response = None
        with contextlib.suppress(Exception):
            response = request.response()
        with contextlib.suppress(Exception):
            page.wait_for_load_state("load")
            page.wait_for_load_state("networkidle", timeout=5000)

        # La connexion réelle remplace les déductions de la soumission factice.
        _analyze_request(rec, request, sources, user, password)

        cookies_set: list[str] = []
        status = location = None
        token_keys: list[str] = []
        if response is not None:
            with contextlib.suppress(Exception):
                token_keys = _token_keys(response.json())  # noms seulement
            status, location = response.status, response.header_value("location")
            cookies_set = _cookie_names(
                [h["value"] for h in response.headers_array() if h["name"].lower() == "set-cookie"]
            )
        after = {c["name"]: c["value"] for c in context.cookies()}
        rec.login = LoginObservation(
            status=status,
            location=location,
            cookies_set=cookies_set,
            new_cookies=sorted(n for n, v in after.items() if before.get(n) != v),
            # Chemin seul : une chaîne de requête peut porter un jeton.
            final_path=urlsplit(page.url).path or "/",
            logged_in=page.locator("input[type=password]:visible").count() == 0,
        )
        before.clear()
        after.clear()
        if not rec.login.logged_in:
            rec.warnings.append("test_login_still_on_login_page (identifiants du compte de test ?)")
        elif not rec.login.session_cookies:
            if token_keys:
                # Session par jeton : bloquant en mode proxy seulement ; c'est la rédaction du
                # descripteur (mode choisi) qui en décide, voir proposal.to_descriptor.
                rec.session_token_keys = token_keys
            else:
                rec.blocking.append("no_session_cookie_after_login (session hors cookies : non gérée)")
    except Exception as e:  # message Playwright jamais relayé : il pourrait citer une valeur saisie
        rec.warnings.append(f"test_login_error: {type(e).__name__}")
    finally:
        sources.clear()
        context.close()
        user = password = ""  # noqa: F841 (références effacées)


def _token_keys(data: Any, prefix: str = "") -> list[str]:
    """Chemins des champs JSON qui ressemblent à un jeton de session (noms uniquement)."""
    found: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}{key}"
            if isinstance(value, str) and _TOKEN_KEY.search(str(key)) and len(value) >= 16:
                found.append(path)
            elif isinstance(value, dict):
                found += _token_keys(value, f"{path}.")
    return found


def _json_path(body: str, value: str) -> str | None:
    """Chemin pointé (``data.token``) du champ JSON valant ``value``, s'il est unique."""
    try:
        data = json.loads(body)
    except ValueError:
        return None
    found: list[str] = []

    def walk(node: Any, path: list[str]) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if isinstance(key, str) and "." not in key:
                    walk(child, [*path, key])
        elif node == value and path:
            found.append(".".join(path))

    walk(data, [])
    return found[0] if len(found) == 1 else None


def _raw_json(request: Any) -> Any:
    try:
        return request.post_data_json
    except Exception:
        return None


def _submitted_values(request: Any, encoding: str) -> dict[str, str]:
    """Valeurs envoyées, pour les seules comparaisons (jamais conservées)."""
    if encoding == "form":
        return {k: v[0] for k, v in parse_qs(request.post_data or "", keep_blank_values=True).items()}
    if encoding == "json":
        data = _raw_json(request)
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
