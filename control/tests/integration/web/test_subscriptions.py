from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlsplit

from starlette.testclient import TestClient

from ezopenpn.models import ProfileState


def test_active_subscription_is_private_and_contains_two_transports(
    web_client: TestClient, web_app
) -> None:
    created = web_app.state.services.runtime.create("Телефон")
    assert created.subscription_token is not None
    web_app.state.services.profiles.set_state(created.profile_id, ProfileState.ACTIVE)

    response = web_client.get(f"/s/{created.subscription_token}")

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.headers["cache-control"] == "no-store"
    decoded = base64.b64decode(response.text).decode("utf-8")
    assert decoded.count("\n") == 1
    vless_link, hysteria_link = decoded.splitlines()
    assert parse_qs(urlsplit(vless_link).query)["mode"] == ["packet-up"]
    assert parse_qs(urlsplit(hysteria_link).query)["obfs"] == ["salamander"]


def test_disabled_missing_and_malformed_subscriptions_are_indistinguishable(
    web_client: TestClient, web_app
) -> None:
    created = web_app.state.services.runtime.create("Ноутбук")
    assert created.subscription_token is not None
    web_app.state.services.profiles.set_state(created.profile_id, ProfileState.ACTIVE)
    web_app.state.services.profiles.set_state(created.profile_id, ProfileState.DISABLED)

    disabled = web_client.get(f"/s/{created.subscription_token}")
    missing = web_client.get("/s/unknown-token")
    malformed = web_client.get(f"/s/{'x' * 129}")

    assert disabled.status_code == missing.status_code == malformed.status_code == 404
    assert disabled.text == missing.text == malformed.text
    assert disabled.headers["cache-control"] == "no-store"
