from __future__ import annotations

import json

import httpx
import pytest
import respx

from ezopenpn.integrations.hysteria import (
    HttpHysteriaClient,
    HysteriaRuntimeUnavailable,
    InvalidHysteriaRuntimeIdentifier,
)

RUNTIME_ID = "p_abcdefghijklmnopqrstuvwx23"


@respx.mock
def test_kick_uses_authorization_header_and_one_id_list() -> None:
    route = respx.post("http://hysteria:9999/kick").mock(
        return_value=httpx.Response(200)
    )
    client = HttpHysteriaClient("http://hysteria:9999", "stats-value")

    client.kick(RUNTIME_ID)

    assert route.called
    request = route.calls[0].request
    assert request.headers["authorization"] == "stats-value"
    assert json.loads(request.content) == [RUNTIME_ID]


@respx.mock
def test_kick_error_does_not_expose_runtime_response() -> None:
    respx.post("http://hysteria:9999/kick").mock(
        return_value=httpx.Response(503, text="sensitive runtime response")
    )
    client = HttpHysteriaClient("http://hysteria:9999", "stats-value")

    with pytest.raises(
        HysteriaRuntimeUnavailable, match="Hysteria2 runtime unavailable"
    ) as captured:
        client.kick(RUNTIME_ID)

    assert "sensitive runtime response" not in str(captured.value)


@respx.mock
def test_invalid_runtime_id_is_rejected_before_http() -> None:
    route = respx.post("http://hysteria:9999/kick").mock(
        return_value=httpx.Response(200)
    )
    client = HttpHysteriaClient("http://hysteria:9999", "stats-value")

    with pytest.raises(InvalidHysteriaRuntimeIdentifier):
        client.kick("device-name")

    assert not route.called
