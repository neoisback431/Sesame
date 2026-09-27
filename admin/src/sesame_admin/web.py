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

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .audit import AuditEvent, AuditSink
from .auth import Authenticator, AuthError
from .identity import AdminUser, ClaimsError, identity_from_claims
from .ports import NotFound, Unavailable
from .service import AdminService, InvalidInput

log = logging.getLogger(__name__)
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")


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
) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
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
        except Unavailable:
            return error(request, 503, "Service indisponible", "Le registre des comptes est injoignable.")
        rows = [(a, counts.get(a.id, {})) for a in sorted(service.apps.values(), key=lambda a: a.name)]
        return render(request, "apps.html", admin=admin, rows=rows)

    @app.get("/apps/{app_id}")
    async def app_detail(request: Request, app_id: str, admin: Admin) -> Response:
        try:
            target = service.app(app_id)
            accounts = await service.accounts.list_accounts(app_id)
        except NotFound:
            return error(request, 404, "Application inconnue", "Aucun descripteur ne porte cet identifiant.")
        except Unavailable:
            return error(request, 503, "Service indisponible", "Le registre des comptes est injoignable.")
        return render(request, "app.html", admin=admin, app=target, accounts=accounts)

    async def act(request: Request, app_id: str, operation) -> Response:
        cid = correlation_id(request)
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
        return RedirectResponse(f"/apps/{app_id}", status_code=303)

    @app.post("/apps/{app_id}/accounts")
    async def provision(
        request: Request, app_id: str, admin: Admin, user_key: Annotated[str, Form()]
    ) -> Response:
        async def op(cid: str) -> str:
            target = service.app(app_id)
            form = await request.form()
            fields = {k: str(form.get(f"cred_{k}", "")) for k in target.credential_keys}
            await service.provision(admin, app_id, user_key, fields, cid)
            return f"Compte de « {user_key.strip()} » enregistré et activé."

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

    return app
