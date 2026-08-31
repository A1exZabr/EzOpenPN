from __future__ import annotations

from pathlib import Path
from typing import Protocol

import httpx


class SupervisorUnavailable(RuntimeError):
    pass


class HttpClient(Protocol):
    def post(self, url: str, *, content: bytes) -> httpx.Response: ...

    def close(self) -> None: ...


class UnixXraySupervisorClient:
    def __init__(self, socket_path: Path) -> None:
        if not socket_path.is_absolute():
            raise ValueError("supervisor socket path must be absolute")
        transport = httpx.HTTPTransport(uds=str(socket_path))
        self._client: HttpClient = httpx.Client(
            transport=transport,
            base_url="http://supervisor",
            timeout=4.0,
        )

    @classmethod
    def from_client(cls, client: HttpClient) -> UnixXraySupervisorClient:
        instance = cls.__new__(cls)
        instance._client = client
        return instance

    def restart(self) -> None:
        try:
            response = self._client.post("/restart", content=b"")
        except httpx.HTTPError:
            raise SupervisorUnavailable("Xray supervisor unavailable") from None
        if response.status_code != 202:
            raise SupervisorUnavailable("Xray supervisor unavailable")

    def close(self) -> None:
        self._client.close()
