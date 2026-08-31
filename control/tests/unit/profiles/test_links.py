from __future__ import annotations

import base64
from ipaddress import IPv4Address
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import UUID

import pytest

from ezopenpn.profiles.links import (
    HysteriaMaterial,
    LinkValueTooLong,
    VlessMaterial,
    build_hysteria_link,
    build_qr_svg,
    build_subscription,
    build_vless_link,
)


def test_vless_link_contains_required_xhttp_parameters() -> None:
    link = build_vless_link(
        VlessMaterial(
            user_id=UUID("11111111-1111-4111-8111-111111111111"),
            host=IPv4Address("203.0.113.10"),
            public_key="public-key",
            server_name="www.example.org",
            short_id="a1b2c3d4e5f60708",
            path="/r4nd0m",
        ),
        "Телефон",
    )

    parsed = urlsplit(link)
    query = parse_qs(parsed.query)
    assert parsed.scheme == "vless"
    assert parsed.hostname == "203.0.113.10"
    assert parsed.port == 443
    assert unquote(parsed.fragment) == "Телефон"
    assert query == {
        "type": ["xhttp"],
        "security": ["reality"],
        "encryption": ["none"],
        "pbk": ["public-key"],
        "fp": ["chrome"],
        "sni": ["www.example.org"],
        "sid": ["a1b2c3d4e5f60708"],
        "path": ["/r4nd0m"],
        "mode": ["packet-up"],
    }
    assert [part.split("=", 1)[0] for part in parsed.query.split("&")] == [
        "type",
        "security",
        "encryption",
        "pbk",
        "fp",
        "sni",
        "sid",
        "path",
        "mode",
    ]


def test_hysteria_link_uses_salamander_without_unsafe_certificate_flags() -> None:
    link = build_hysteria_link(
        HysteriaMaterial(
            secret="profile",
            host=IPv4Address("203.0.113.10"),
            obfs_password="obfs-secret",
        ),
        "Планшет",
    )

    parsed = urlsplit(link)
    query = parse_qs(parsed.query)
    assert parsed.scheme == "hysteria2"
    assert parsed.username == "profile"
    assert parsed.hostname == "203.0.113.10"
    assert parsed.port == 443
    assert query == {"obfs": ["salamander"], "obfs-password": ["obfs-secret"]}
    assert "insecure" not in parsed.query.casefold()
    assert unquote(parsed.fragment) == "Планшет"


def test_subscription_is_base64_of_exactly_two_lines() -> None:
    encoded = build_subscription("first://one", "second://two")

    assert base64.b64decode(encoded).decode("utf-8") == "first://one\nsecond://two"


def test_qr_svg_does_not_embed_source_markup() -> None:
    svg = build_qr_svg("https://203.0.113.10:9443/s/<script>alert(1)</script>")

    assert svg.lstrip().startswith("<svg")
    assert "<script>" not in svg


def test_qr_rejects_values_above_the_explicit_limit() -> None:
    with pytest.raises(LinkValueTooLong):
        build_qr_svg("я" * 4097)
