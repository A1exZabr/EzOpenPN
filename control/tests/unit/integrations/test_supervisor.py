from __future__ import annotations

import httpx
import pytest

from ezopenpn.integrations.supervisor import (
    SupervisorUnavailable,
    UnixXraySupervisorClient,
)


def test_restart_uses_an_empty_fixed_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(202)

    http_client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://supervisor",
    )
    client = UnixXraySupervisorClient.from_client(http_client)

    client.restart()

    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert requests[0].url.path == "/restart"
    assert requests[0].content == b""


def test_restart_error_has_no_response_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(503, text="sensitive process detail")

    http_client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://supervisor",
    )
    client = UnixXraySupervisorClient.from_client(http_client)

    with pytest.raises(SupervisorUnavailable, match="Xray supervisor unavailable") as captured:
        client.restart()

    assert "sensitive process detail" not in str(captured.value)
