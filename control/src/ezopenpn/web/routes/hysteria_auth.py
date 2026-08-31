from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from ezopenpn.models import ProfileState

router = APIRouter()
_MAX_BODY_BYTES = 2048
_PRIVATE_HEADERS = {"Cache-Control": "no-store"}
_DENIED = {"ok": False, "id": ""}


def _response(ok: bool, runtime_id: str = "") -> JSONResponse:
    return JSONResponse(
        {"ok": ok, "id": runtime_id},
        status_code=200,
        headers=_PRIVATE_HEADERS,
    )


def _payload(body: bytes) -> str | None:
    if not 1 <= len(body) <= _MAX_BODY_BYTES:
        return None
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or set(value) != {"addr", "auth", "tx"}:
        return None
    address = value.get("addr")
    auth = value.get("auth")
    tx = value.get("tx")
    if (
        not isinstance(address, str)
        or not 1 <= len(address) <= 512
        or not isinstance(auth, str)
        or not 1 <= len(auth) <= 512
        or not auth.isascii()
        or isinstance(tx, bool)
        or not isinstance(tx, int)
        or not 0 <= tx <= 2**63 - 1
    ):
        return None
    return auth


@router.post("/internal/hysteria/auth", response_class=JSONResponse)
async def authorize(request: Request) -> JSONResponse:
    auth = _payload(await request.body())
    if auth is None:
        return JSONResponse(_DENIED, status_code=200, headers=_PRIVATE_HEADERS)
    try:
        record = request.app.state.services.profiles.find_by_hysteria_secret(auth)
    except SQLAlchemyError:
        return JSONResponse(_DENIED, status_code=200, headers=_PRIVATE_HEADERS)
    if record is None or record.state is not ProfileState.ACTIVE:
        return JSONResponse(_DENIED, status_code=200, headers=_PRIVATE_HEADERS)
    return _response(True, record.runtime_id)
