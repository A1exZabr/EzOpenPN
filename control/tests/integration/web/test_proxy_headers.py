from starlette.testclient import TestClient


def test_untrusted_forwarded_address_is_ignored(web_app) -> None:
    with TestClient(
        web_app,
        base_url="https://203.0.113.10:9443",
        client=("untrusted-peer", 50000),
    ) as client:
        response = client.get(
            "/health/live", headers={"x-forwarded-for": "198.51.100.7"}
        )

    assert response.headers["x-observed-client"] == "untrusted-peer"


def test_trusted_gateway_supplies_one_valid_client_address(web_app) -> None:
    with TestClient(
        web_app,
        base_url="https://203.0.113.10:9443",
        client=("gateway", 50000),
    ) as client:
        accepted = client.get(
            "/health/live", headers={"x-forwarded-for": "198.51.100.7"}
        )
        ambiguous = client.get(
            "/health/live",
            headers={"x-forwarded-for": "198.51.100.7, 203.0.113.9"},
        )

    assert accepted.headers["x-observed-client"] == "198.51.100.7"
    assert ambiguous.headers["x-observed-client"] == "gateway"
