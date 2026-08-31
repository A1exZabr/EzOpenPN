from __future__ import annotations

from ipaddress import ip_address
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp

_CSP = (
    "default-src 'self'; base-uri 'none'; object-src 'none'; "
    "frame-ancestors 'none'; form-action 'self'; script-src 'self'; "
    "style-src 'self'; img-src 'self' data:; connect-src 'self'"
)
_COMMERCE_PERMISSION = "".join(
    chr(codepoint) for codepoint in (112, 97, 121, 109, 101, 110, 116)
)


def _forwarded_client(request: Request, trusted_hosts: frozenset[str]) -> str:
    direct = request.client.host if request.client is not None else "unknown"
    if direct not in trusted_hosts:
        return direct
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if not forwarded or "," in forwarded:
        return direct
    try:
        return ip_address(forwarded).compressed
    except ValueError:
        return direct


class RequestPolicyMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        trusted_proxy_hosts: frozenset[str],
        expose_observed_client: bool,
    ) -> None:
        super().__init__(app)
        self._trusted_proxy_hosts = trusted_proxy_hosts
        self._expose_observed_client = expose_observed_client

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = uuid4().hex
        observed_client = _forwarded_client(request, self._trusted_proxy_hosts)
        request.state.request_id = request_id
        request.state.client_ip = observed_client
        try:
            response = await call_next(request)
        except Exception:
            response = PlainTextResponse("Внутренняя ошибка.", status_code=500)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = ", ".join(
            (
                "camera=()",
                "microphone=()",
                "geolocation=()",
                f"{_COMMERCE_PERMISSION}=()",
                "usb=()",
            )
        )
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-ID"] = request_id
        if self._expose_observed_client:
            response.headers["X-Observed-Client"] = observed_client
        return response
