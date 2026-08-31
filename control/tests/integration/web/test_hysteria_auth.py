from __future__ import annotations

import logging
from urllib.parse import unquote, urlsplit

from starlette.testclient import TestClient

from ezopenpn.models import ProfileState


def _active_auth(web_app) -> tuple[str, str]:
    created = web_app.state.services.runtime.create("Телефон")
    web_app.state.services.profiles.set_state(created.profile_id, ProfileState.ACTIVE)
    record = web_app.state.services.profiles.get(created.profile_id)
    link = web_app.state.services.links.bundle_for_record(record).hysteria_link
    auth = unquote(urlsplit(link).username or "")
    return auth, created.runtime_id


def test_active_auth_is_allowed_with_opaque_runtime_id(
    web_client: TestClient, web_app
) -> None:
    auth, runtime_id = _active_auth(web_app)

    response = web_client.post(
        "/internal/hysteria/auth",
        json={"addr": "198.51.100.4:50000", "auth": auth, "tx": 1_250_000},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True, "id": runtime_id}
    assert response.headers["cache-control"] == "no-store"


def test_disabled_and_unknown_auth_are_denied_identically(
    web_client: TestClient, web_app
) -> None:
    auth, runtime_id = _active_auth(web_app)
    record = next(
        profile
        for profile in web_app.state.services.profiles.list()
        if profile.runtime_id == runtime_id
    )
    web_app.state.services.profiles.set_state(record.profile_id, ProfileState.DISABLED)

    disabled = web_client.post(
        "/internal/hysteria/auth",
        json={"addr": "198.51.100.4:50000", "auth": auth, "tx": 0},
    )
    unknown = web_client.post(
        "/internal/hysteria/auth",
        json={"addr": "198.51.100.4:50000", "auth": "unknown", "tx": 0},
    )

    assert disabled.status_code == unknown.status_code == 200
    assert disabled.json() == unknown.json() == {"ok": False, "id": ""}


def test_malformed_auth_is_denied_with_status_200(web_client: TestClient) -> None:
    responses = (
        web_client.post(
            "/internal/hysteria/auth",
            content=b"not-json",
            headers={"content-type": "application/json"},
        ),
        web_client.post(
            "/internal/hysteria/auth",
            json={"addr": "198.51.100.4:50000", "auth": "x" * 513, "tx": 0},
        ),
        web_client.post(
            "/internal/hysteria/auth",
            json={"addr": "198.51.100.4:50000", "auth": "value", "tx": True},
        ),
    )

    assert all(response.status_code == 200 for response in responses)
    assert all(response.json() == {"ok": False, "id": ""} for response in responses)


def test_auth_input_is_not_written_to_logs(
    web_client: TestClient, caplog
) -> None:
    source = "198.51.100.77:54321"
    presented = "unique-presented-value"

    with caplog.at_level(logging.DEBUG):
        response = web_client.post(
            "/internal/hysteria/auth",
            json={"addr": source, "auth": presented, "tx": 0},
        )

    assert response.status_code == 200
    assert source not in caplog.text
    assert presented not in caplog.text
