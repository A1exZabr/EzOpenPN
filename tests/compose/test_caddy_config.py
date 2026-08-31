from __future__ import annotations

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def caddyfile() -> str:
    return (_ROOT / "deploy" / "caddy" / "Caddyfile").read_text(
        encoding="utf-8"
    )


def test_caddy_uses_short_lived_public_acme_profile(caddyfile: str) -> None:
    assert "tls force_automate" in caddyfile
    assert "issuer acme" in caddyfile
    assert "profile shortlived" in caddyfile
    assert "https://acme-v02.api.letsencrypt.org/directory" in caddyfile
    assert "disable_tlsalpn_challenge" in caddyfile
    assert "tls internal" not in caddyfile
    assert "local_certs" not in caddyfile


def test_caddy_has_no_admin_api_and_uses_unprivileged_ports(
    caddyfile: str,
) -> None:
    assert "admin off" in caddyfile
    assert "persist_config off" in caddyfile
    assert "http_port 8080" in caddyfile
    assert "https_port 9443" in caddyfile
    assert "storage file_system /data/caddy" in caddyfile


def test_internal_routes_are_not_proxied(caddyfile: str) -> None:
    assert "path /internal/*" in caddyfile
    assert "respond @internal 404" in caddyfile


def test_forwarded_address_is_overwritten(caddyfile: str) -> None:
    assert "header_up -X-Forwarded-For" in caddyfile
    assert "header_up X-Forwarded-For {remote_host}" in caddyfile
    assert "header_up -Forwarded" in caddyfile
    assert "header_up -X-Real-IP" in caddyfile


def test_browser_security_headers_are_explicit(caddyfile: str) -> None:
    assert "Strict-Transport-Security" in caddyfile
    assert "Content-Security-Policy" in caddyfile
    assert "frame-ancestors 'none'" in caddyfile
    assert "X-Content-Type-Options" in caddyfile
    assert "Referrer-Policy" in caddyfile
    assert "Permissions-Policy" in caddyfile
    assert "X-Frame-Options" in caddyfile
