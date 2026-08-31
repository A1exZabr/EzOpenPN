from __future__ import annotations

import json
import math
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, TypeGuard

VLESS_TRANSPORT = "vless-reality-xhttp"
HYSTERIA_TRANSPORT = "hysteria2-salamander"
TRANSPORTS = (VLESS_TRANSPORT, HYSTERIA_TRANSPORT)
NETWORK_TYPES = ("fixed", "mobile")
REQUIRED_CLIENTS = {
    ("Hiddify Next", "Android"),
    ("Happ", "iOS"),
    ("v2rayN", "Windows"),
}

_MINIMUM_BYTES = 100 * 1024 * 1024
_MINIMUM_MEDIAN_MBPS = 2.0
_MAXIMUM_STALL_SECONDS = 10.0
_MAXIMUM_REVOCATION_SECONDS = 10.0
_MINIMUM_RECONNECT_OBSERVATION_SECONDS = 10.0
_MAXIMUM_RECONNECT_OBSERVATION_SECONDS = 60.0
_MAXIMUM_FILE_BYTES = 1024 * 1024
_UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_VERSION_PATTERN = re.compile(r"^v\d+\.\d+\.\d+$")
_CLIENT_VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+() -]{0,63}$")
_REGION_PATTERN = re.compile(r"^[A-Z]{2}$")
_UUID_PATTERN = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
_LINK_PATTERN = re.compile(r"(?i)\b(?:https?|vless|hysteria2)://")
_FORBIDDEN_KEYS = {
    "source_ip",
    "client_ip",
    "server_ip",
    "server_address",
    "profile_id",
    "uuid",
    "token",
    "connection_link",
    "full_link",
    "url",
    "ssid",
    "provider_account",
    "browsing_destination",
    "destination_host",
    "destination_url",
}


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    code: str


def _success() -> ValidationResult:
    return ValidationResult(ok=True, code="ok")


def _failure(code: str) -> ValidationResult:
    return ValidationResult(ok=False, code=code)


def _number(value: object) -> TypeGuard[int | float]:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _positive_number(value: object) -> TypeGuard[int | float]:
    return _number(value) and float(value) > 0


def _exact_object(value: object, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _timestamp(value: object) -> bool:
    if not isinstance(value, str) or _UTC_PATTERN.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _short_text(value: object, *, maximum: int = 64) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 1 <= len(value) <= maximum
        and all(ord(character) >= 32 for character in value)
    )


def _contains_raw_address(value: str) -> bool:
    candidate = value.strip().strip("[]")
    try:
        ip_address(candidate)
    except ValueError:
        return False
    return True


def _sanitized(value: object) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                return False
            normalized = key.strip().casefold().replace("-", "_")
            if normalized in _FORBIDDEN_KEYS or not _sanitized(child):
                return False
        return True
    if isinstance(value, list):
        return all(_sanitized(child) for child in value)
    if isinstance(value, str):
        return not (
            _contains_raw_address(value)
            or _UUID_PATTERN.search(value)
            or _LINK_PATTERN.search(value)
            or "BEGIN PRIVATE KEY" in value
        )
    return value is None or isinstance(value, (bool, int, float))


def _validate_trial(trial: object, expected_number: int) -> ValidationResult:
    keys = {
        "trial",
        "handshake",
        "external_server_verified",
        "bytes_transferred",
        "duration_seconds",
        "median_mbps",
        "max_stall_seconds",
        "passed",
    }
    if not _exact_object(trial, keys):
        return _failure("schema_invalid")
    assert isinstance(trial, dict)
    if trial["trial"] != expected_number or isinstance(trial["trial"], bool):
        return _failure("trial_matrix_incomplete")
    if trial["handshake"] is not True:
        return _failure("handshake_missing")
    if trial["external_server_verified"] is not True:
        return _failure("external_server_unverified")
    if (
        not isinstance(trial["bytes_transferred"], int)
        or isinstance(trial["bytes_transferred"], bool)
        or trial["bytes_transferred"] < _MINIMUM_BYTES
        or not _positive_number(trial["duration_seconds"])
        or not _number(trial["median_mbps"])
        or float(trial["median_mbps"]) < _MINIMUM_MEDIAN_MBPS
    ):
        return _failure("throughput_missing")
    if (
        not _number(trial["max_stall_seconds"])
        or float(trial["max_stall_seconds"]) < 0
        or float(trial["max_stall_seconds"]) > _MAXIMUM_STALL_SECONDS
    ):
        return _failure("stall_limit_exceeded")
    if trial["passed"] is not True:
        return _failure("trial_failed")
    return _success()


def _validate_transport_revocation(value: object) -> ValidationResult:
    keys = {
        "fourth_transfer_started",
        "transfer_terminated",
        "termination_seconds",
        "reconnect_attempted",
        "reconnect_succeeded",
        "reconnect_observation_seconds",
        "passed",
    }
    if not _exact_object(value, keys):
        return _failure("schema_invalid")
    assert isinstance(value, dict)
    if value["fourth_transfer_started"] is not True or value["transfer_terminated"] is not True:
        return _failure("active_revocation_missing")
    if (
        not _positive_number(value["termination_seconds"])
        or float(value["termination_seconds"]) > _MAXIMUM_REVOCATION_SECONDS
    ):
        return _failure("revocation_too_slow")
    if value["reconnect_attempted"] is not True:
        return _failure("revocation_reconnect_untested")
    if value["reconnect_succeeded"] is not False:
        return _failure("revocation_reconnect_succeeded")
    if (
        not _number(value["reconnect_observation_seconds"])
        or not _MINIMUM_RECONNECT_OBSERVATION_SECONDS
        <= float(value["reconnect_observation_seconds"])
        <= _MAXIMUM_RECONNECT_OBSERVATION_SECONDS
    ):
        return _failure("revocation_observation_incomplete")
    if value["passed"] is not True:
        return _failure("active_revocation_failed")
    return _success()


def _validate_revocation(value: object) -> ValidationResult:
    if not _exact_object(value, {"transports", "other_active_vless_profile"}):
        return _failure("schema_invalid")
    assert isinstance(value, dict)
    transports = value["transports"]
    if not _exact_object(transports, set(TRANSPORTS)):
        return _failure("revocation_matrix_incomplete")
    assert isinstance(transports, dict)
    for transport in TRANSPORTS:
        result = _validate_transport_revocation(transports[transport])
        if not result.ok:
            return result

    continuity = value["other_active_vless_profile"]
    if not _exact_object(continuity, {"reconnected", "reconnect_seconds", "passed"}):
        return _failure("schema_invalid")
    assert isinstance(continuity, dict)
    if (
        continuity["reconnected"] is not True
        or not _positive_number(continuity["reconnect_seconds"])
        or float(continuity["reconnect_seconds"]) > _MAXIMUM_REVOCATION_SECONDS
        or continuity["passed"] is not True
    ):
        return _failure("continuity_failed")
    return _success()


def validate_network_result(value: object) -> ValidationResult:
    if not _sanitized(value):
        return _failure("evidence_not_sanitized")
    keys = {
        "evidence_kind",
        "schema_version",
        "recorded_at",
        "application_version",
        "usage_region",
        "network_type",
        "client",
        "external_server_verified",
        "trials",
        "revocation",
        "passed",
    }
    if not _exact_object(value, keys):
        return _failure("schema_invalid")
    assert isinstance(value, dict)
    if (
        value["evidence_kind"] != "network"
        or value["schema_version"] != 1
        or isinstance(value["schema_version"], bool)
        or not _timestamp(value["recorded_at"])
        or not isinstance(value["application_version"], str)
        or _VERSION_PATTERN.fullmatch(value["application_version"]) is None
        or not isinstance(value["usage_region"], str)
        or _REGION_PATTERN.fullmatch(value["usage_region"]) is None
        or value["network_type"] not in NETWORK_TYPES
    ):
        return _failure("schema_invalid")
    if not _exact_object(value["client"], {"name", "version"}):
        return _failure("schema_invalid")
    client = value["client"]
    assert isinstance(client, dict)
    if (
        not _short_text(client["name"])
        or not isinstance(client["version"], str)
        or _CLIENT_VERSION_PATTERN.fullmatch(client["version"]) is None
    ):
        return _failure("schema_invalid")
    if value["external_server_verified"] is not True:
        return _failure("external_server_unverified")
    trials = value["trials"]
    if not _exact_object(trials, set(TRANSPORTS)):
        return _failure("trial_matrix_incomplete")
    assert isinstance(trials, dict)
    for transport in TRANSPORTS:
        transport_trials = trials[transport]
        if not isinstance(transport_trials, list) or len(transport_trials) != 3:
            return _failure("trial_matrix_incomplete")
        for expected_number, trial in enumerate(transport_trials, start=1):
            result = _validate_trial(trial, expected_number)
            if not result.ok:
                return result
    revocation = _validate_revocation(value["revocation"])
    if not revocation.ok:
        return revocation
    if value["passed"] is not True:
        return _failure("network_result_failed")
    return _success()


def _validate_client_transport(value: object) -> ValidationResult:
    keys = {"connected", "external_server_verified", "data_transferred"}
    if not _exact_object(value, keys):
        return _failure("schema_invalid")
    assert isinstance(value, dict)
    if any(value[key] is not True for key in keys):
        return _failure("client_transport_failed")
    return _success()


def validate_client_result(value: object) -> ValidationResult:
    if not _sanitized(value):
        return _failure("evidence_not_sanitized")
    keys = {
        "evidence_kind",
        "schema_version",
        "recorded_at",
        "application_version",
        "usage_region",
        "clients",
        "passed",
    }
    if not _exact_object(value, keys):
        return _failure("schema_invalid")
    assert isinstance(value, dict)
    if (
        value["evidence_kind"] != "clients"
        or value["schema_version"] != 1
        or isinstance(value["schema_version"], bool)
        or not _timestamp(value["recorded_at"])
        or not isinstance(value["application_version"], str)
        or _VERSION_PATTERN.fullmatch(value["application_version"]) is None
        or not isinstance(value["usage_region"], str)
        or _REGION_PATTERN.fullmatch(value["usage_region"]) is None
        or not isinstance(value["clients"], list)
    ):
        return _failure("schema_invalid")
    clients = value["clients"]
    combinations: set[tuple[str, str]] = set()
    for item in clients:
        if not isinstance(item, dict):
            return _failure("schema_invalid")
        application = item.get("application")
        platform = item.get("platform")
        if not isinstance(application, str) or not isinstance(platform, str):
            return _failure("schema_invalid")
        combinations.add((application, platform))
    if len(clients) != len(REQUIRED_CLIENTS) or combinations != REQUIRED_CLIENTS:
        return _failure("client_matrix_incomplete")
    item_keys = {
        "application",
        "platform",
        "version",
        "release_channel",
        "stable_release_verified_at",
        "combined_link_imported",
        "transports",
        "revocation_observed",
        "passed",
    }
    for item in clients:
        if not _exact_object(item, item_keys):
            return _failure("schema_invalid")
        assert isinstance(item, dict)
        if (
            not isinstance(item["version"], str)
            or _CLIENT_VERSION_PATTERN.fullmatch(item["version"]) is None
        ):
            return _failure("schema_invalid")
        if item["release_channel"] != "stable" or not _timestamp(
            item["stable_release_verified_at"]
        ):
            return _failure("stable_client_unverified")
        if item["combined_link_imported"] is not True:
            return _failure("combined_import_failed")
        transports = item["transports"]
        if not _exact_object(transports, set(TRANSPORTS)):
            return _failure("client_transport_failed")
        assert isinstance(transports, dict)
        for transport in TRANSPORTS:
            result = _validate_client_transport(transports[transport])
            if not result.ok:
                return result
        if item["revocation_observed"] is not True or item["passed"] is not True:
            return _failure("client_revocation_failed")
    if value["passed"] is not True:
        return _failure("client_result_failed")
    return _success()


def validate_release_evidence(
    network_results: Sequence[Mapping[str, Any]], client_evidence: object
) -> ValidationResult:
    for network in network_results:
        result = validate_network_result(network)
        if not result.ok:
            return result
    network_types = [network.get("network_type") for network in network_results]
    if len(network_types) != len(NETWORK_TYPES) or set(network_types) != set(NETWORK_TYPES):
        return _failure("network_matrix_incomplete")
    clients = validate_client_result(client_evidence)
    if not clients.ok:
        return clients
    assert isinstance(client_evidence, dict)
    versions = {network.get("application_version") for network in network_results}
    versions.add(client_evidence.get("application_version"))
    regions = {network.get("usage_region") for network in network_results}
    regions.add(client_evidence.get("usage_region"))
    if len(versions) != 1 or len(regions) != 1:
        return _failure("evidence_scope_mismatch")
    return _success()


class DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKey(key)
        result[key] = value
    return result


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_json_document(
    path: Path, *, require_canonical: bool = True
) -> tuple[object | None, ValidationResult]:
    try:
        metadata = path.lstat()
    except OSError:
        return None, _failure("evidence_file_invalid")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAXIMUM_FILE_BYTES:
        return None, _failure("evidence_file_invalid")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJSONKey,
        RecursionError,
    ):
        return None, _failure("evidence_file_invalid")
    if require_canonical and raw != canonical_json_bytes(value):
        return None, _failure("evidence_not_canonical")
    return value, _success()


def validate_evidence_directory(directory: Path) -> ValidationResult:
    try:
        metadata = directory.lstat()
    except OSError:
        return _failure("evidence_directory_missing")
    if not stat.S_ISDIR(metadata.st_mode):
        return _failure("evidence_directory_invalid")
    expected_files = {"fixed.json", "mobile.json", "clients.json"}
    try:
        actual_files = {path.name for path in directory.iterdir()}
    except OSError:
        return _failure("evidence_directory_invalid")
    if not expected_files.issubset(actual_files):
        return _failure("evidence_files_missing")
    if actual_files != expected_files:
        return _failure("evidence_files_unexpected")

    loaded: dict[str, object] = {}
    for name in sorted(expected_files):
        value, result = load_json_document(directory / name)
        if not result.ok:
            return result
        loaded[name] = value

    fixed = loaded["fixed.json"]
    mobile = loaded["mobile.json"]
    clients = loaded["clients.json"]
    if not isinstance(fixed, dict) or fixed.get("network_type") != "fixed":
        return _failure("evidence_file_mismatch")
    if not isinstance(mobile, dict) or mobile.get("network_type") != "mobile":
        return _failure("evidence_file_mismatch")
    return validate_release_evidence([fixed, mobile], clients)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv if argv is not None else sys.argv[1:])
    if len(arguments) != 1:
        print('{"code":"usage","ok":false}')
        return 2
    result = validate_evidence_directory(Path(arguments[0]))
    print(json.dumps({"code": result.code, "ok": result.ok}, sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
