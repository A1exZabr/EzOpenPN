from __future__ import annotations

import hmac
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.responses import Response

from ezopenpn.profiles.repository import (
    InvalidProfileTransition,
    ProfileConflict,
    ProfileNotFound,
)
from ezopenpn.profiles.service import InvalidProfileName
from ezopenpn.web.dependencies import authenticated_browser

router = APIRouter()
_MAX_FORM_BYTES = 16 * 1024


async def _form(request: Request) -> dict[str, str]:
    body = await request.body()
    if len(body) > _MAX_FORM_BYTES:
        return {}
    parsed = await request.form()
    result: dict[str, str] = {}
    for key in ("csrf", "name", "confirm"):
        value = parsed.get(key, "")
        if isinstance(value, str):
            result[key] = value
    return result


def _valid_csrf(request: Request, submitted: str) -> bool:
    browser = authenticated_browser(request)
    if (
        browser is None
        or not submitted.isascii()
        or not 1 <= len(submitted) <= 128
        or not hmac.compare_digest(browser.csrf_token, submitted)
    ):
        return False
    return cast(
        bool,
        request.app.state.services.sessions.validate_csrf(browser.identity, submitted),
    )


def _profile_id(value: str) -> UUID | None:
    try:
        return UUID(value)
    except ValueError:
        return None


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> Response:
    browser = authenticated_browser(request)
    if browser is None:
        return RedirectResponse("/login", status_code=303)
    records = request.app.state.services.profiles.list()
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={"browser": browser, "csrf": browser.csrf_token, "profiles": records},
        ),
    )


@router.post("/profiles")
async def create_profile(request: Request) -> Response:
    values = await _form(request)
    if not _valid_csrf(request, values.get("csrf", "")):
        return HTMLResponse("Действие отклонено.", status_code=403)
    try:
        result = request.app.state.services.runtime.create(values.get("name", ""))
    except InvalidProfileName:
        return HTMLResponse("Проверьте имя устройства.", status_code=400)
    except ProfileConflict:
        return HTMLResponse("Не удалось создать профиль. Повторите попытку.", status_code=409)
    return RedirectResponse(f"/profiles/{result.profile_id}", status_code=303)


@router.get("/profiles/{profile_id}", response_class=HTMLResponse)
def profile_page(request: Request, profile_id: str) -> Response:
    browser = authenticated_browser(request)
    if browser is None:
        return RedirectResponse("/login", status_code=303)
    parsed_id = _profile_id(profile_id)
    if parsed_id is None:
        return HTMLResponse("Профиль не найден.", status_code=404)
    try:
        record = request.app.state.services.profiles.get(parsed_id)
    except ProfileNotFound:
        return HTMLResponse("Профиль не найден.", status_code=404)
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name="profile.html",
            context={
                "browser": browser,
                "csrf": browser.csrf_token,
                "profile": record,
                "links": None,
            },
        ),
    )


async def _change_state(request: Request, profile_id: str, operation: str) -> Response:
    values = await _form(request)
    if not _valid_csrf(request, values.get("csrf", "")):
        return HTMLResponse("Действие отклонено.", status_code=403)
    parsed_id = _profile_id(profile_id)
    if parsed_id is None:
        return HTMLResponse("Профиль не найден.", status_code=404)
    try:
        if operation == "disable":
            request.app.state.services.runtime.disable(parsed_id)
        else:
            request.app.state.services.runtime.enable(parsed_id)
    except ProfileNotFound:
        return HTMLResponse("Профиль не найден.", status_code=404)
    except InvalidProfileTransition:
        return HTMLResponse("Состояние профиля уже изменилось.", status_code=409)
    return RedirectResponse(f"/profiles/{parsed_id}", status_code=303)


@router.post("/profiles/{profile_id}/disable")
async def disable_profile(request: Request, profile_id: str) -> Response:
    return await _change_state(request, profile_id, "disable")


@router.post("/profiles/{profile_id}/enable")
async def enable_profile(request: Request, profile_id: str) -> Response:
    return await _change_state(request, profile_id, "enable")


@router.post("/profiles/{profile_id}/delete")
async def delete_profile(request: Request, profile_id: str) -> Response:
    values = await _form(request)
    if not _valid_csrf(request, values.get("csrf", "")):
        return HTMLResponse("Действие отклонено.", status_code=403)
    if values.get("confirm") != "remove":
        return HTMLResponse("Подтвердите удаление профиля.", status_code=400)
    parsed_id = _profile_id(profile_id)
    if parsed_id is None:
        return HTMLResponse("Профиль не найден.", status_code=404)
    try:
        request.app.state.services.runtime.delete(parsed_id)
    except ProfileNotFound:
        return HTMLResponse("Профиль не найден.", status_code=404)
    return RedirectResponse("/", status_code=303)
