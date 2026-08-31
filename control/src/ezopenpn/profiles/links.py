from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from io import BytesIO
from ipaddress import IPv4Address
from urllib.parse import quote, urlencode
from uuid import UUID

import segno
from nacl.exceptions import CryptoError

from ezopenpn.models import ProfileState
from ezopenpn.profiles.repository import ProfileRepository
from ezopenpn.profiles.types import LinkBundle, ProfileRecord, profile_value_context
from ezopenpn.security.secrets import SecretCipher

_MAX_QR_VALUE_BYTES = 8192
_TOKEN_LIMIT = 128
_SHORT_ID_PATTERN = re.compile(r"[0-9a-f]{2,16}")


class LinkValueTooLong(ValueError):
    pass


class ProfileLinksUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class VlessMaterial:
    user_id: UUID
    host: IPv4Address
    public_key: str
    server_name: str
    short_id: str
    path: str
    port: int = 443


@dataclass(frozen=True, slots=True)
class HysteriaMaterial:
    secret: str = field(repr=False)
    host: IPv4Address
    obfs_password: str = field(repr=False)
    port: int = 443


@dataclass(frozen=True, slots=True)
class TransportLinkConfig:
    host: IPv4Address
    reality_public_key: str
    reality_server_name: str
    reality_short_id: str
    xhttp_path: str
    hysteria_obfs_password: str = field(repr=False)
    public_port: int = 443
    panel_port: int = 9443

    def __post_init__(self) -> None:
        for value in (
            self.reality_public_key,
            self.reality_server_name,
            self.hysteria_obfs_password,
        ):
            if not value or not value.isascii() or any(character.isspace() for character in value):
                raise ValueError("transport link configuration is invalid")
        if _SHORT_ID_PATTERN.fullmatch(self.reality_short_id) is None:
            raise ValueError("transport link configuration is invalid")
        if (
            not self.xhttp_path.startswith("/")
            or len(self.xhttp_path) > 256
            or any(character in self.xhttp_path for character in "?#\r\n")
        ):
            raise ValueError("transport link configuration is invalid")
        if not 1 <= self.public_port <= 65535 or not 1 <= self.panel_port <= 65535:
            raise ValueError("transport link ports are invalid")


def build_vless_link(material: VlessMaterial, label: str) -> str:
    query = urlencode(
        (
            ("type", "xhttp"),
            ("security", "reality"),
            ("encryption", "none"),
            ("pbk", material.public_key),
            ("fp", "chrome"),
            ("sni", material.server_name),
            ("sid", material.short_id),
            ("path", material.path),
            ("mode", "packet-up"),
        )
    )
    authority = f"{quote(str(material.user_id), safe='')}@{material.host}:{material.port}"
    return f"vless://{authority}?{query}#{quote(label, safe='')}"


def build_hysteria_link(material: HysteriaMaterial, label: str) -> str:
    query = urlencode(
        (("obfs", "salamander"), ("obfs-password", material.obfs_password))
    )
    authority = f"{quote(material.secret, safe='')}@{material.host}:{material.port}"
    return f"hysteria2://{authority}/?{query}#{quote(label, safe='')}"


def build_subscription(vless_link: str, hysteria_link: str) -> str:
    payload = f"{vless_link}\n{hysteria_link}".encode()
    return base64.b64encode(payload).decode("ascii")


def build_qr_svg(value: str) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) > _MAX_QR_VALUE_BYTES:
        raise LinkValueTooLong("QR value is too long")
    output = BytesIO()
    try:
        segno.make(value, error="m", encoding="utf-8", micro=False).save(
            output,
            kind="svg",
            xmldecl=False,
            svgns=True,
            scale=4,
        )
    except segno.DataOverflowError as error:
        raise LinkValueTooLong("QR value is too long") from error
    return output.getvalue().decode("utf-8")


def encode_url_secret(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class ProfileLinkService:
    def __init__(
        self,
        repository: ProfileRepository,
        cipher: SecretCipher,
        config: TransportLinkConfig,
    ) -> None:
        self._repository = repository
        self._cipher = cipher
        self._config = config

    def _plaintext(self, record: ProfileRecord) -> tuple[UUID, str, str]:
        if record.wrapped_profile_key is None:
            raise ProfileLinksUnavailable("profile links are unavailable")
        try:
            profile_key = self._cipher.unwrap_profile_key(
                record.profile_id, record.wrapped_profile_key
            )
            user_id = UUID(
                bytes=self._cipher.decrypt_profile_value(
                    profile_key,
                    record.user_id_ciphertext,
                    profile_value_context(record.profile_id, "user-id"),
                )
            )
            hysteria_secret = encode_url_secret(
                self._cipher.decrypt_profile_value(
                    profile_key,
                    record.hysteria_secret_ciphertext,
                    profile_value_context(record.profile_id, "hysteria-auth"),
                )
            )
            subscription_token = self._cipher.decrypt_profile_value(
                profile_key,
                record.subscription_token_ciphertext,
                profile_value_context(record.profile_id, "subscription-token"),
            ).decode("ascii")
        except (CryptoError, UnicodeError, ValueError) as error:
            raise ProfileLinksUnavailable("profile links are unavailable") from error
        if (
            not 1 <= len(subscription_token) <= _TOKEN_LIMIT
            or not subscription_token.isascii()
        ):
            raise ProfileLinksUnavailable("profile links are unavailable")
        return user_id, hysteria_secret, subscription_token

    def bundle_for_record(self, record: ProfileRecord) -> LinkBundle:
        if record.state is not ProfileState.ACTIVE:
            raise ProfileLinksUnavailable("profile links are unavailable")
        user_id, hysteria_secret, subscription_token = self._plaintext(record)
        vless_link = build_vless_link(
            VlessMaterial(
                user_id=user_id,
                host=self._config.host,
                public_key=self._config.reality_public_key,
                server_name=self._config.reality_server_name,
                short_id=self._config.reality_short_id,
                path=self._config.xhttp_path,
                port=self._config.public_port,
            ),
            record.name,
        )
        hysteria_link = build_hysteria_link(
            HysteriaMaterial(
                secret=hysteria_secret,
                host=self._config.host,
                obfs_password=self._config.hysteria_obfs_password,
                port=self._config.public_port,
            ),
            record.name,
        )
        combined_url = (
            f"https://{self._config.host}:{self._config.panel_port}/s/"
            f"{quote(subscription_token, safe='')}"
        )
        return LinkBundle(
            combined_url=combined_url,
            vless_link=vless_link,
            hysteria_link=hysteria_link,
        )

    def subscription_for_token(self, token: str) -> str | None:
        record = self._repository.find_by_subscription_token(token)
        if record is None or record.state is not ProfileState.ACTIVE:
            return None
        try:
            bundle = self.bundle_for_record(record)
        except ProfileLinksUnavailable:
            return None
        return build_subscription(bundle.vless_link, bundle.hysteria_link)
