from __future__ import annotations

import hmac
import math
from datetime import UTC, datetime
from typing import cast

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.responses import Response

from ezopenpn.web.dependencies import (
    CSRF_COOKIE,
    PREAUTH_COOKIE,
    SESSION_COOKIE,
    authenticated_browser,
)

router = APIRouter()
_MAX_FORM_BYTES = 16 * 1024


def _set_preauth_cookie(response: HTMLResponse, nonce: str) -> None:
    response.set_cookie(
        PREAUTH_COOKIE,
        nonce,
        max_age=5 * 60,
        path="/login",
        secure=True,
        httponly=True,
        samesite="strict",
    )


def _login_page(
    request: Request,
    *,
    status_code: int = 200,
    error: str | None = None,
    retry_after: int | None = None,
) -> HTMLResponse:
    challenge = request.app.state.services.preauth.issue()
    response = cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"csrf": challenge.form_token, "error": error},
            status_code=status_code,
        ),
    )
    if retry_after is not None:
        response.headers["Retry-After"] = str(retry_after)
    _set_preauth_cookie(response, challenge.cookie_nonce)
    return response


async def _form(request: Request) -> dict[str, str]:
    body = await request.body()
    if len(body) > _MAX_FORM_BYTES:
        return {}
    parsed = await request.form()
    values: dict[str, str] = {}
    for key in ("login", "password", "csrf"):
        value = parsed.get(key, "")
        if isinstance(value, str):
            values[key] = value
    return values


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> Response:
    if authenticated_browser(request) is not None:
        return RedirectResponse("/", status_code=303)
    return _login_page(request)


@router.post("/login")
async def login(request: Request) -> Response:
    values = await _form(request)
    services = request.app.state.services
    cookie_nonce = request.cookies.get(PREAUTH_COOKIE, "")
    if not services.preauth.consume(cookie_nonce, values.get("csrf", "")):
        return HTMLResponse("Запрос устарел. Откройте страницу входа снова.", status_code=403)

    login_value = values.get("login", "")[:1024]
    password_value = values.get("password", "")[:1024]
    client_ip = request.state.client_ip
    now = datetime.now(UTC)
    waiting = services.throttle.retry_after(client_ip, login_value, now)
    if waiting.total_seconds() > 0:
        return _login_page(
            request,
            status_code=429,
            error="Слишком много попыток. Подождите и попробуйте снова.",
            retry_after=math.ceil(waiting.total_seconds()),
        )

    administrator = services.admins.verify_credentials(login_value, password_value, now)
    if administrator is None:
        delay = services.throttle.register_failure(client_ip, login_value, now)
        return _login_page(
            request,
            status_code=401,
            error="Логин или пароль не подошли.",
            retry_after=math.ceil(delay.total_seconds()),
        )

    services.throttle.clear(client_ip, login_value)
    grant = services.sessions.create(administrator.id, now)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        grant.raw_token,
        max_age=7 * 24 * 60 * 60,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    response.set_cookie(
        CSRF_COOKIE,
        grant.csrf_token,
        max_age=7 * 24 * 60 * 60,
        path="/",
        secure=True,
        httponly=False,
        samesite="strict",
    )
    response.delete_cookie(
        PREAUTH_COOKIE,
        path="/login",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    return response


@router.post("/logout")
async def logout(request: Request) -> Response:
    browser = authenticated_browser(request)
    values = await _form(request)
    if (
        browser is None
        or not values.get("csrf", "").isascii()
        or not hmac.compare_digest(values.get("csrf", ""), browser.csrf_token)
        or not request.app.state.services.sessions.validate_csrf(
            browser.identity, values.get("csrf", "")
        )
    ):
        return HTMLResponse("Действие отклонено.", status_code=403)
    request.app.state.services.sessions.revoke(browser.identity.session_id, datetime.now(UTC))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(
        SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict"
    )
    response.delete_cookie(
        CSRF_COOKIE, path="/", secure=True, httponly=False, samesite="strict"
    )
    return response
