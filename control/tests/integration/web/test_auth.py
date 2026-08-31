import re

from starlette.testclient import TestClient

from ezopenpn.profiles.runtime import ReconcileResult


def extract_csrf(page: str) -> str:
    match = re.search(r'name="csrf" value="([^"\s]+)"', page)
    assert match is not None
    return match.group(1)


def _login(client: TestClient, phrase: str = "correct passphrase"):
    csrf = extract_csrf(client.get("/login").text)
    return client.post(
        "/login",
        data={"login": "owner", "password": phrase, "csrf": csrf},
        follow_redirects=False,
    )


def test_login_rotates_session_and_sets_secure_cookie(web_client: TestClient) -> None:
    web_client.cookies.set("ezop_session", "attacker-fixed-value")

    response = _login(web_client)

    assert response.status_code == 303
    cookie = response.headers["set-cookie"]
    assert "ezop_session=" in cookie
    assert "attacker-fixed-value" not in cookie
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/" in cookie


def test_login_requires_one_time_preauth_csrf(web_client: TestClient) -> None:
    response = web_client.post(
        "/login",
        data={"login": "owner", "password": "correct passphrase", "csrf": "wrong"},
        follow_redirects=False,
    )

    assert response.status_code == 403


def test_preauth_challenge_cannot_be_replayed(web_client: TestClient) -> None:
    csrf = extract_csrf(web_client.get("/login").text)
    old_cookie = web_client.cookies.get("ezop_preauth")
    assert old_cookie is not None
    first = web_client.post(
        "/login",
        data={"login": "missing", "password": "correct passphrase", "csrf": csrf},
    )

    replay = web_client.post(
        "/login",
        data={"login": "missing", "password": "correct passphrase", "csrf": csrf},
        headers={"cookie": f"ezop_preauth={old_cookie}"},
    )

    assert first.status_code == 401
    assert replay.status_code == 403


def test_unknown_login_and_wrong_password_share_public_copy(web_app) -> None:
    client_options = {"base_url": "https://203.0.113.10:9443"}
    with TestClient(web_app, client=("198.51.100.1", 50000), **client_options) as first:
        unknown_csrf = extract_csrf(first.get("/login").text)
        unknown = first.post(
            "/login",
            data={
                "login": "missing",
                "password": "correct passphrase",
                "csrf": unknown_csrf,
            },
        )
    with TestClient(web_app, client=("198.51.100.2", 50000), **client_options) as second:
        wrong_csrf = extract_csrf(second.get("/login").text)
        wrong = second.post(
            "/login",
            data={
                "login": "owner",
                "password": "incorrect passphrase",
                "csrf": wrong_csrf,
            },
        )

    assert unknown.status_code == wrong.status_code == 401
    assert "Логин или пароль не подошли" in unknown.text
    assert "Логин или пароль не подошли" in wrong.text


def test_logout_requires_session_csrf_and_revokes_cookie(web_client: TestClient) -> None:
    assert _login(web_client).status_code == 303

    rejected = web_client.post("/logout", follow_redirects=False)
    assert rejected.status_code == 403

    dashboard = web_client.get("/")
    csrf = extract_csrf(dashboard.text)
    response = web_client.post("/logout", data={"csrf": csrf}, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert web_client.get("/", follow_redirects=False).status_code == 303


def test_security_headers_and_private_schema_are_enabled(web_client: TestClient) -> None:
    response = web_client.get("/login")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"]
    assert web_client.get("/docs").status_code == 404
    assert web_client.get("/openapi.json").status_code == 404


def test_unhandled_errors_are_redacted_and_keep_security_headers(web_app) -> None:
    @web_app.get("/test-only-error")
    def test_only_error() -> None:
        raise RuntimeError("fixture-sensitive-detail")

    with TestClient(
        web_app,
        base_url="https://203.0.113.10:9443",
        raise_server_exceptions=False,
    ) as client:
        response = client.get("/test-only-error")

    assert response.status_code == 500
    assert "fixture-sensitive-detail" not in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-request-id"]


def test_runtime_degradation_keeps_live_and_login_available(
    web_app, web_client: TestClient
) -> None:
    web_app.state.services.runtime_health.update(
        ReconcileResult(error_code="runtime_reconcile_failed")
    )

    assert web_client.get("/health/live").json() == {"status": "ok"}
    ready = web_client.get("/health/ready")
    assert ready.status_code == 503
    assert ready.json() == {
        "status": "not_ready",
        "code": "runtime_reconcile_failed",
    }
    assert web_client.get("/login").status_code == 200
