from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

router = APIRouter()
_PRIVATE_HEADERS = {"Cache-Control": "no-store"}


def _not_found() -> PlainTextResponse:
    return PlainTextResponse(
        "Профиль не найден.",
        status_code=404,
        headers=_PRIVATE_HEADERS,
    )


@router.get("/s/{subscription_token}", response_class=PlainTextResponse)
def subscription(request: Request, subscription_token: str) -> PlainTextResponse:
    encoded = request.app.state.services.links.subscription_for_token(subscription_token)
    if encoded is None:
        return _not_found()
    return PlainTextResponse(encoded, headers=_PRIVATE_HEADERS)
