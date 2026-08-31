from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Request

from ezopenpn.security.sessions import SessionIdentity

SESSION_COOKIE = "ezop_session"
CSRF_COOKIE = "ezop_csrf"
PREAUTH_COOKIE = "ezop_preauth"


@dataclass(frozen=True, slots=True)
class AuthenticatedBrowser:
    identity: SessionIdentity
    csrf_token: str


def authenticated_browser(request: Request) -> AuthenticatedBrowser | None:
    services = request.app.state.services
    session_token = request.cookies.get(SESSION_COOKIE, "")
    identity = services.sessions.authenticate(session_token, datetime.now(UTC))
    if identity is None:
        return None
    csrf_token = request.cookies.get(CSRF_COOKIE, "")
    if not services.sessions.validate_csrf(identity, csrf_token):
        return None
    return AuthenticatedBrowser(identity=identity, csrf_token=csrf_token)
