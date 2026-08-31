from __future__ import annotations

import re
from typing import Protocol, cast

import httpx

_RUNTIME_ID_PATTERN = re.compile(r"p_[a-z2-7]{26}")
_REQUEST_TIMEOUT_SECONDS = 3.0


class HysteriaRuntimeUnavailable(RuntimeError):
    pass


class InvalidHysteriaRuntimeIdentifier(ValueError):
    pass


class KickHttpClient(Protocol):
    def post(self, url: str, *, json: object) -> httpx.Response: ...

    def close(self) -> None: ...


def _runtime_id(value: str) -> str:
    if _RUNTIME_ID_PATTERN.fullmatch(value) is None:
        raise InvalidHysteriaRuntimeIdentifier("runtime identifier is invalid")
    return value


class HttpHysteriaClient:
    def __init__(self, stats_url: str, api_secret: str) -> None:
        parsed_url = httpx.URL(stats_url)
        if (
            parsed_url.scheme not in {"http", "https"}
            or parsed_url.userinfo
            or parsed_url.query
            or parsed_url.fragment
            or parsed_url.path not in {"", "/"}
        ):
            raise ValueError("Hysteria2 stats URL is invalid")
        if (
            not 1 <= len(api_secret) <= 512
            or not api_secret.isascii()
            or "\r" in api_secret
            or "\n" in api_secret
        ):
            raise ValueError("Hysteria2 API secret is invalid")
        self._client = cast(
            KickHttpClient,
            httpx.Client(
                base_url=parsed_url,
                headers={"Authorization": api_secret},
                timeout=_REQUEST_TIMEOUT_SECONDS,
            ),
        )

    @classmethod
    def from_client(cls, client: KickHttpClient) -> HttpHysteriaClient:
        instance = cls.__new__(cls)
        instance._client = client
        return instance

    def kick(self, runtime_id: str) -> None:
        try:
            response = self._client.post("/kick", json=[_runtime_id(runtime_id)])
        except httpx.HTTPError:
            raise HysteriaRuntimeUnavailable("Hysteria2 runtime unavailable") from None
        if not 200 <= response.status_code < 300:
            raise HysteriaRuntimeUnavailable("Hysteria2 runtime unavailable")

    def close(self) -> None:
        self._client.close()
