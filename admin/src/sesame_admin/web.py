# SPDX-License-Identifier: Apache-2.0
"""Application web d'administration (FastAPI, pages rendues côté serveur).

Pas de ``from __future__ import annotations`` : FastAPI doit résoudre les
annotations des routes, dont l'alias local ``Admin``.
"""

import hmac
import logging
import re
import secrets
import uuid
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .audit import AuditEvent, AuditSink
from .auth import Authenticator, AuthError
from .descriptors import draft
from .identity import AdminUser, ClaimsError, identity_from_claims
from .ports import NotFound, Unavailable
from .recorder import Recorder, RecorderError
from .service import AdminService, InvalidDescriptor, InvalidInput

log = logging.getLogger(__name__)
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
# Logo, favicon, bannière : générés par scripts/build_web_assets.py, publics.
STATIC = Path(__file__).parent / "static"
_REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
# Retour après une action : seulement une page locale de l'administration.
_BACK = re.compile(r"^/(apps|users)/[A-Za-z0-9@._+-]{1,256}$")
# Champs du formulaire guidé de création d'appli.
_GUIDED = (
    "id",
    "name",
    "description",
    "owner",
    "public_host",
    "base_url",
    "groups",
    "users",
    "form_url",
    "form_selector",
    "username_field",
    "password_field",
    "csrf_field",
    "session_cookie",
    "failure_text",
)


class NotAdmin(Exception):
    pass


def correlation_id(request: Request) -> str:
    rid = request.headers.get("x-request-id", "")
    return rid if _REQUEST_ID.fullmatch(rid) else str(uuid.uuid4())


def create_app(
    service: AdminService,
    authenticator: Authenticator,
    audit: AuditSink,
    *,
    public_url: str,
    session_key: str,
    admin_group: str,
    issuer: str,
    user_key_claim: str,
    groups_claim: str,
    session_ttl_secs: int = 3600,
    secure_cookies: bool = True,
    recorder: Recorder | None = None,
) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_key,
        session_cookie="sesame_admin",
        max_age=session_ttl_secs,
        same_site="lax",
        https_only=secure_cookies,
    )

    def render(request: Request, template: str, status: int = 200, **ctx: Any) -> HTMLResponse:
        session = request.session
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        flash = session.pop("flash", None)
        resp = TEMPLATES.TemplateResponse(
            request, template, {"csrf": session["csrf"], "flash": flash, **ctx}, status_code=status
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def error(request: Request, status: int, title: str, message: str) -> HTMLResponse:
        return render(
            request, "error.html", status, title=title, message=message, cid=correlation_id(request)
        )

    def current_admin(request: Request) -> AdminUser:
        raw = request.session.get("user")
        if not raw:
            raise NotAdmin
        user = AdminUser(**{**raw, "groups": tuple(raw["groups"])})
        if admin_group not in user.groups:
            raise NotAdmin
        return user

    async def check_csrf(request: Request) -> None:
        form = await request.form()
        expected = request.session.get("csrf", "")
        if not expected or not hmac.compare_digest(expected, str(form.get("csrf", ""))):
            raise InvalidInput("Jeton CSRF invalide : rechargez la page.")

    Admin = Annotated[AdminUser, Depends(current_admin)]

    @app.exception_handler(NotAdmin)
    async def not_admin(request: Request, _: NotAdmin) -> Response:
        if request.method == "GET":
            return RedirectResponse(f"/login?next={request.url.path}", status_code=302)
        return error(request, 403, "Session expirée", "Reconnectez-vous.")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/login")
    async def login(request: Request, next: str = "/") -> Response:
        request.session["next"] = next if next.startswith("/") and not next.startswith("//") else "/"
        return await authenticator.login_redirect(request, f"{public_url}/auth/callback")

    @app.get("/auth/callback")
    async def callback(request: Request) -> Response:
        cid = correlation_id(request)
        try:
            claims = await authenticator.callback(request)
            user = identity_from_claims(claims, issuer, user_key_claim, groups_claim)
        except (AuthError, ClaimsError) as e:
            log.warning("connexion admin refusée", extra={"correlation_id": cid, "reason": type(e).__name__})
            await audit.record(
                AuditEvent.of("admin_login", "failure", None, correlation_id=cid, reason="oidc_error")
            )
            return error(request, 401, "Connexion refusée", "Votre identité n'a pas pu être vérifiée.")
        if admin_group not in user.groups:
            await audit.record(
                AuditEvent.of("access_denied", "failure", user, correlation_id=cid, reason="not_admin")
            )
            request.session.clear()
            return error(
                request, 403, "Accès refusé", "Cette interface est réservée aux administrateurs Sesame."
            )
        next_url = request.session.pop("next", "/")
        request.session.clear()  # nouvelle session : pas de fixation
        request.session["user"] = {
            "issuer": user.issuer,
            "subject": user.subject,
            "user_key": user.user_key,
            "display_name": user.display_name,
            "groups": list(user.groups),
        }
        request.session["csrf"] = secrets.token_urlsafe(32)
        await audit.record(AuditEvent.of("admin_login", "success", user, correlation_id=cid))
        return RedirectResponse(next_url, status_code=302)

    @app.post("/logout")
    async def logout(request: Request, admin: Admin) -> Response:
        await check_csrf(request)
        request.session.clear()
        return RedirectResponse("/logged-out", status_code=303)

    @app.get("/logged-out")
    async def logged_out(request: Request) -> Response:
        return render(request, "logged_out.html")

    @app.get("/")
    async def apps(request: Request, admin: Admin) -> Response:
        try:
            counts = await service.accounts.count_by_app()
            catalog = await service.catalog()
        except Unavailable:
            return error(request, 503, "Service indisponible", "La base de données est injoignable.")
        rows = [(a, counts.get(a.id, {})) for a in sorted(catalog.apps.values(), key=lambda a: a.name)]
        return render(request, "apps.html", admin=admin, rows=rows, rejected=catalog.rejected)

    # --- Création / modification / suppression d'appli ------------------------------

    def editor(
        request: Request,
        admin: AdminUser,
        *,
        text: str,
        app_id: str | None = None,
        revision: int = 0,
        errors: list[str] | None = None,
        valid: bool = False,
        notes: list[str] | None = None,
        status: int = 200,
    ) -> HTMLResponse:
        return render(
            request,
            "descriptor_edit.html",
            status,
            admin=admin,
            text=text,
            app_id=app_id,
            revision=revision,
            errors=errors or [],
            valid=valid,
            notes=notes or [],
        )

    @app.get("/apps/new")
    async def app_new(request: Request, admin: Admin) -> Response:
        return render(request, "app_new.html", admin=admin, recorder_enabled=recorder is not None)

    @app.post("/apps/analyze")
    async def app_analyze(request: Request, admin: Admin, login_url: Annotated[str, Form()]) -> Response:
        """Analyse une page de login via le recorder et pré-remplit l'éditeur."""
        cid = correlation_id(request)
        try:
            await check_csrf(request)
        except InvalidInput as e:
            return error(request, 400, "Requête refusée", str(e))
        if recorder is None:
            return error(request, 404, "Indisponible", "L'analyse de page de login n'est pas configurée.")
        login_url = login_url.strip()
        host = urlsplit(login_url).hostname or ""
        if urlsplit(login_url).scheme not in ("http", "https") or not host:
            msg = "URL de login invalide (http ou https attendu)."
            request.session["flash"] = {"kind": "error", "text": msg}
            return RedirectResponse("/apps/new", status_code=303)
        probe = "probe_failure" in await request.form()
        try:
            result = await recorder.analyze(login_url, probe_failure=probe)
        except RecorderError as e:
            await audit.record(
                AuditEvent.of("descriptor_recorded", "failure", admin, correlation_id=cid, reason=host)
            )
            request.session["flash"] = {"kind": "error", "text": f"Analyse impossible : {e}"}
            return RedirectResponse("/apps/new", status_code=303)
        await audit.record(
            AuditEvent.of("descriptor_recorded", "success", admin, correlation_id=cid, reason=host)
        )
        if result.yaml is None:
            msg = "Aucun formulaire de login exploitable détecté."
            request.session["flash"] = {"kind": "error", "text": msg}
            return render(request, "app_new.html", admin=admin, recorder_enabled=True, notes=result.notes)
        return editor(request, admin, text=result.yaml, notes=result.notes)

    @app.post("/apps/new")
    async def app_draft(request: Request, admin: Admin) -> Response:
        """Formulaire guidé → premier jet dans l'éditeur (rien n'est enregistré)."""
        try:
            await check_csrf(request)
        except InvalidInput as e:
            return error(request, 400, "Requête refusée", str(e))
        form = await request.form()
        doc = draft({k: str(form.get(k, ""))[:1000] for k in _GUIDED})
        return editor(request, admin, text=service.validator.to_yaml(doc))

    @app.post("/apps")
    async def app_create(request: Request, admin: Admin, descriptor: Annotated[str, Form()]) -> Response:
        cid = correlation_id(request)
        try:
            await check_csrf(request)
            if "check" in await request.form():
                service.parse(descriptor, 1)
                return editor(request, admin, text=descriptor, valid=True)
            app_id, _ = await service.create_descriptor(admin, descriptor, cid)
        except InvalidDescriptor as e:
            return editor(request, admin, text=descriptor, errors=e.errors, status=422)
        except InvalidInput as e:
            return editor(request, admin, text=descriptor, errors=[str(e)], status=400)
        except Unavailable:
            log.error("brique externe indisponible", extra={"correlation_id": cid})
            return error(request, 503, "Service indisponible", "La base de données est injoignable.")
        request.session["flash"] = {
            "kind": "ok",
            "text": f"Appli « {app_id} » créée : accessible via Sesame d'ici quelques secondes.",
        }
        return RedirectResponse(f"/apps/{app_id}", status_code=303)

    @app.get("/apps/{app_id}/descriptor")
    async def descriptor_edit(request: Request, app_id: str, admin: Admin) -> Response:
        if app_id in service.files:
            return error(
                request,
                409,
                "Lecture seule",
                "Cette appli est décrite par un fichier Git : modifiez-la par merge request.",
            )
        try:
            stored = await service.stored(app_id)
        except NotFound:
            return error(request, 404, "Application inconnue", "Aucun descripteur ne porte cet identifiant.")
        except Unavailable:
            return error(request, 503, "Service indisponible", "La base de données est injoignable.")
        return editor(
            request,
            admin,
            text=service.validator.to_yaml(stored.document),
            app_id=app_id,
            revision=stored.revision,
        )

    @app.post("/apps/{app_id}/descriptor")
    async def descriptor_update(
        request: Request,
        app_id: str,
        admin: Admin,
        descriptor: Annotated[str, Form()],
        revision: Annotated[int, Form()],
    ) -> Response:
        cid = correlation_id(request)
        args = {"text": descriptor, "app_id": app_id, "revision": revision}
        try:
            await check_csrf(request)
            if "check" in await request.form():
                service.parse(descriptor, revision + 1)
                return editor(request, admin, valid=True, **args)
            new_revision = await service.update_descriptor(admin, app_id, descriptor, revision, cid)
        except InvalidDescriptor as e:
            return editor(request, admin, errors=e.errors, status=422, **args)
        except InvalidInput as e:
            return editor(request, admin, errors=[str(e)], status=400, **args)
        except NotFound:
            return error(request, 404, "Application inconnue", "Ce descripteur a été supprimé entre-temps.")
        except Unavailable:
            log.error("brique externe indisponible", extra={"correlation_id": cid})
            return error(request, 503, "Service indisponible", "La base de données est injoignable.")
        request.session["flash"] = {
            "kind": "ok",
            "text": f"Descripteur enregistré (révision {new_revision}), actif sous quelques secondes.",
        }
        return RedirectResponse(f"/apps/{app_id}", status_code=303)

    @app.post("/apps/{app_id}/delete")
    async def app_delete(
        request: Request, app_id: str, admin: Admin, revision: Annotated[int, Form()]
    ) -> Response:
        cid = correlation_id(request)
        try:
            await check_csrf(request)
            await service.delete_descriptor(admin, app_id, revision, cid)
        except InvalidInput as e:
            request.session["flash"] = {"kind": "error", "text": str(e)}
            return RedirectResponse(f"/apps/{app_id}", status_code=303)
        except NotFound:
            request.session["flash"] = {"kind": "error", "text": "Application introuvable."}
            return RedirectResponse("/", status_code=303)
        except Unavailable:
            log.error("brique externe indisponible", extra={"correlation_id": cid})
            request.session["flash"] = {
                "kind": "error",
                "text": f"Opération impossible : service indisponible (référence {cid}).",
            }
            return RedirectResponse(f"/apps/{app_id}", status_code=303)
        request.session["flash"] = {"kind": "ok", "text": f"Appli « {app_id} » supprimée."}
        return RedirectResponse("/", status_code=303)

    @app.get("/apps/{app_id}/history")
    async def app_history(request: Request, app_id: str, admin: Admin) -> Response:
        try:
            entries = await service.descriptors.history(app_id)
        except Unavailable:
            return error(request, 503, "Service indisponible", "La base de données est injoignable.")
        if not entries:
            return error(request, 404, "Aucun historique", "Aucune révision en base pour cet identifiant.")
        revisions = [(e, service.validator.to_yaml(e.document) if e.document else None) for e in entries]
        return render(request, "history.html", admin=admin, app_id=app_id, revisions=revisions)

    @app.get("/apps/{app_id}")
    async def app_detail(request: Request, app_id: str, admin: Admin) -> Response:
        try:
            target = await service.app(app_id)
            accounts = await service.accounts.list_accounts(app_id)
            known = await service.accounts.known_users(500)
        except NotFound:
            if app_id not in service.files and await service.descriptors.get_descriptor(app_id):
                # En base mais écarté du catalogue : l'éditeur permet de le corriger.
                return RedirectResponse(f"/apps/{app_id}/descriptor", status_code=302)
            return error(request, 404, "Application inconnue", "Aucun descripteur ne porte cet identifiant.")
        except Unavailable:
            return error(request, 503, "Service indisponible", "La base de données est injoignable.")
        return render(request, "app.html", admin=admin, app=target, accounts=accounts, known_users=known)

    async def act(request: Request, app_id: str, operation) -> Response:
        cid = correlation_id(request)
        back = str((await request.form()).get("back", ""))
        target = back if _BACK.fullmatch(back) else f"/apps/{app_id}"
        try:
            await check_csrf(request)
            message = await operation(cid)
            request.session["flash"] = {"kind": "ok", "text": message}
        except InvalidInput as e:
            request.session["flash"] = {"kind": "error", "text": str(e)}
        except NotFound:
            request.session["flash"] = {"kind": "error", "text": "Compte ou application introuvable."}
        except Unavailable:
            log.error("brique externe indisponible", extra={"correlation_id": cid})
            request.session["flash"] = {
                "kind": "error",
                "text": f"Opération impossible : service indisponible (référence {cid}).",
            }
        return RedirectResponse(target, status_code=303)

    @app.post("/apps/{app_id}/open-access")
    async def open_access(request: Request, app_id: str, admin: Admin) -> Response:
        async def op(cid: str) -> str:
            revision = await service.open_access(admin, app_id, cid)
            return (
                f"Restriction retirée (révision {revision}) : tout utilisateur ayant un compte actif "
                "voit l'appli dans son portail d'ici quelques secondes."
            )

        return await act(request, app_id, op)

    @app.post("/apps/{app_id}/accounts")
    async def provision(
        request: Request, app_id: str, admin: Admin, user_key: Annotated[str, Form()]
    ) -> Response:
        async def op(cid: str) -> str:
            target = await service.app(app_id)
            form = await request.form()
            fields = {k: str(form.get(f"cred_{k}", "")) for k in target.credential_keys}
            await service.provision(admin, app_id, user_key, fields, cid)
            done = f"Compte de « {user_key.strip()} » enregistré et activé."
            if not target.access_open:
                done += " Attention : accès restreint à des groupes, l'appli n'apparaîtra qu'à leurs membres."
            return done

        return await act(request, app_id, op)

    @app.post("/apps/{app_id}/accounts/{user_key}/status")
    async def set_status(
        request: Request, app_id: str, user_key: str, admin: Admin, status: Annotated[str, Form()]
    ) -> Response:
        async def op(cid: str) -> str:
            await service.set_status(admin, app_id, user_key, status, cid)
            return f"Compte de « {user_key} » {'réactivé' if status == 'active' else 'désactivé'}."

        return await act(request, app_id, op)

    @app.post("/apps/{app_id}/accounts/{user_key}/delete")
    async def delete(request: Request, app_id: str, user_key: str, admin: Admin) -> Response:
        async def op(cid: str) -> str:
            await service.delete(admin, app_id, user_key, cid)
            return f"Compte de « {user_key} » supprimé (coffre et registre)."

        return await act(request, app_id, op)

    @app.get("/users")
    async def users(request: Request, admin: Admin, q: str = "") -> Response:
        try:
            rows = await service.accounts.search_users(q.strip(), 200)
        except Unavailable:
            return error(request, 503, "Service indisponible", "Le registre des comptes est injoignable.")
        return render(request, "users.html", admin=admin, rows=rows, q=q.strip())

    @app.get("/users/{user_key}")
    async def user_detail(request: Request, user_key: str, admin: Admin) -> Response:
        try:
            accounts = await service.accounts.list_user_accounts(user_key)
            apps = (await service.catalog()).apps
        except Unavailable:
            return error(request, 503, "Service indisponible", "La base de données est injoignable.")
        return render(request, "user.html", admin=admin, user_key=user_key, accounts=accounts, apps=apps)

    @app.post("/users/{user_key}/disable-all")
    async def disable_all(request: Request, user_key: str, admin: Admin) -> Response:
        cid = correlation_id(request)
        try:
            await check_csrf(request)
            n = await service.disable_all(admin, user_key, cid)
            request.session["flash"] = {
                "kind": "ok",
                "text": f"{n} compte(s) de « {user_key} » désactivé(s).",
            }
        except InvalidInput as e:
            request.session["flash"] = {"kind": "error", "text": str(e)}
        except Unavailable:
            log.error("brique externe indisponible", extra={"correlation_id": cid})
            request.session["flash"] = {
                "kind": "error",
                "text": f"Opération impossible : service indisponible (référence {cid}).",
            }
        return RedirectResponse(f"/users/{user_key}", status_code=303)

    return app
