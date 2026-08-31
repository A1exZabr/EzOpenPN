from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

RELEASE_TEST_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(RELEASE_TEST_ROOT))

from record_network_result import (  # noqa: E402
    EvidenceWriteError,
    write_client_result,
    write_network_result,
)
from validate_evidence import (  # noqa: E402
    HYSTERIA_TRANSPORT,
    VLESS_TRANSPORT,
    validate_client_result,
    validate_evidence_directory,
    validate_network_result,
    validate_release_evidence,
)

MIB = 1024 * 1024


def _trial(number: int) -> dict[str, object]:
    return {
        "trial": number,
        "handshake": True,
        "external_server_verified": True,
        "bytes_transferred": 120 * MIB,
        "duration_seconds": 48.0,
        "median_mbps": 20.0,
        "max_stall_seconds": 0.8,
        "passed": True,
    }


def _transport_revocation() -> dict[str, object]:
    return {
        "fourth_transfer_started": True,
        "transfer_terminated": True,
        "termination_seconds": 4.0,
        "reconnect_attempted": True,
        "reconnect_succeeded": False,
        "reconnect_observation_seconds": 10.0,
        "passed": True,
    }


def network_result(network_type: str = "fixed") -> dict[str, Any]:
    return {
        "evidence_kind": "network",
        "schema_version": 1,
        "recorded_at": "2026-08-31T10:00:00Z",
        "application_version": "v0.1.0",
        "usage_region": "RU",
        "network_type": network_type,
        "client": {"name": "Fixture Client", "version": "1.2.3"},
        "external_server_verified": True,
        "trials": {
            VLESS_TRANSPORT: [_trial(index) for index in range(1, 4)],
            HYSTERIA_TRANSPORT: [_trial(index) for index in range(1, 4)],
        },
        "revocation": {
            "transports": {
                VLESS_TRANSPORT: _transport_revocation(),
                HYSTERIA_TRANSPORT: _transport_revocation(),
            },
            "other_active_vless_profile": {
                "reconnected": True,
                "reconnect_seconds": 3.0,
                "passed": True,
            },
        },
        "passed": True,
    }


def client_result() -> dict[str, Any]:
    clients = []
    for application, platform in (
        ("Hiddify Next", "Android"),
        ("Happ", "iOS"),
        ("v2rayN", "Windows"),
    ):
        clients.append(
            {
                "application": application,
                "platform": platform,
                "version": "9.9.9",
                "release_channel": "stable",
                "stable_release_verified_at": "2026-08-31T09:00:00Z",
                "combined_link_imported": True,
                "transports": {
                    VLESS_TRANSPORT: {
                        "connected": True,
                        "external_server_verified": True,
                        "data_transferred": True,
                    },
                    HYSTERIA_TRANSPORT: {
                        "connected": True,
                        "external_server_verified": True,
                        "data_transferred": True,
                    },
                },
                "revocation_observed": True,
                "passed": True,
            }
        )
    return {
        "evidence_kind": "clients",
        "schema_version": 1,
        "recorded_at": "2026-08-31T11:00:00Z",
        "application_version": "v0.1.0",
        "usage_region": "RU",
        "clients": clients,
        "passed": True,
    }


def test_release_rejects_handshake_only_result() -> None:
    result = network_result()
    first_trial = result["trials"][VLESS_TRANSPORT][0]
    first_trial["bytes_transferred"] = 0
    first_trial["median_mbps"] = 0.0
    assert validate_network_result(result).code == "throughput_missing"


def test_release_requires_both_network_types() -> None:
    result = validate_release_evidence([network_result("fixed")], client_result())
    assert result.code == "network_matrix_incomplete"


@pytest.mark.parametrize("transport", [VLESS_TRANSPORT, HYSTERIA_TRANSPORT])
def test_each_transport_requires_three_substantial_trials(transport: str) -> None:
    too_few = network_result()
    too_few["trials"][transport].pop()
    assert validate_network_result(too_few).code == "trial_matrix_incomplete"

    too_small = network_result()
    too_small["trials"][transport][1]["bytes_transferred"] = 100 * MIB - 1
    assert validate_network_result(too_small).code == "throughput_missing"


def test_stall_and_external_server_limits_are_enforced() -> None:
    stalled = network_result()
    stalled["trials"][HYSTERIA_TRANSPORT][2]["max_stall_seconds"] = 10.1
    assert validate_network_result(stalled).code == "stall_limit_exceeded"

    wrong_server = network_result()
    wrong_server["trials"][VLESS_TRANSPORT][0]["external_server_verified"] = False
    assert validate_network_result(wrong_server).code == "external_server_unverified"


def test_active_revocation_and_other_profile_recovery_are_mandatory() -> None:
    slow = network_result()
    slow["revocation"]["transports"][VLESS_TRANSPORT]["termination_seconds"] = 10.1
    assert validate_network_result(slow).code == "revocation_too_slow"

    reconnected = network_result()
    reconnected["revocation"]["transports"][HYSTERIA_TRANSPORT]["reconnect_succeeded"] = True
    assert validate_network_result(reconnected).code == "revocation_reconnect_succeeded"

    stranded = network_result()
    stranded["revocation"]["other_active_vless_profile"]["reconnected"] = False
    assert validate_network_result(stranded).code == "continuity_failed"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("source_ip", "198.51.100.20"),
        ("profile_id", "51ba954e-4bc4-4db0-a9ec-d731fb28958d"),
        ("connection_link", "https:" + "//example.invalid/full-material"),
        ("ssid", "fixture-wireless-name"),
        ("provider_account", "fixture-account"),
        ("browsing_destination", "example.invalid"),
    ],
)
def test_network_evidence_rejects_sensitive_or_identifying_fields(key: str, value: str) -> None:
    result = network_result()
    result["operator_notes"] = {key: value}
    assert validate_network_result(result).code == "evidence_not_sanitized"


def test_client_matrix_requires_exact_stable_cross_platform_set() -> None:
    incomplete = client_result()
    incomplete["clients"].pop()
    assert validate_client_result(incomplete).code == "client_matrix_incomplete"

    unstable = client_result()
    unstable["clients"][0]["release_channel"] = "preview"
    assert validate_client_result(unstable).code == "stable_client_unverified"

    one_transport = client_result()
    one_transport["clients"][1]["transports"][HYSTERIA_TRANSPORT]["connected"] = False
    assert validate_client_result(one_transport).code == "client_transport_failed"


def test_release_requires_matching_version_and_region() -> None:
    fixed = network_result("fixed")
    mobile = network_result("mobile")
    mobile["usage_region"] = "ZZ"
    assert (
        validate_release_evidence([fixed, mobile], client_result()).code
        == "evidence_scope_mismatch"
    )


def _write_canonical(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_evidence_directory_requires_exact_canonical_files(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _write_canonical(evidence / "fixed.json", network_result("fixed"))
    assert validate_evidence_directory(evidence).code == "evidence_files_missing"

    _write_canonical(evidence / "mobile.json", network_result("mobile"))
    _write_canonical(evidence / "clients.json", client_result())
    assert validate_evidence_directory(evidence).ok is True

    (evidence / "fixed.json").write_text("{\n}\n", encoding="utf-8")
    assert validate_evidence_directory(evidence).code == "evidence_not_canonical"


def test_recorder_writes_only_valid_canonical_network_evidence(tmp_path: Path) -> None:
    draft = tmp_path / "draft.json"
    output = tmp_path / "fixed.json"
    draft.write_text(json.dumps(network_result("fixed")), encoding="utf-8")

    write_network_result(draft, output, "fixed")
    assert output.read_text(encoding="utf-8") == (
        json.dumps(network_result("fixed"), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    assert output.stat().st_mode & 0o777 == 0o644
    with pytest.raises(EvidenceWriteError):
        write_network_result(draft, output, "fixed")

    unsafe = copy.deepcopy(network_result("fixed"))
    unsafe["source_ip"] = "198.51.100.20"
    draft.write_text(json.dumps(unsafe), encoding="utf-8")
    with pytest.raises(EvidenceWriteError, match="evidence_not_sanitized"):
        write_network_result(draft, tmp_path / "unsafe.json", "fixed")


def test_recorder_writes_valid_canonical_client_evidence(tmp_path: Path) -> None:
    draft = tmp_path / "clients-draft.json"
    output = tmp_path / "clients.json"
    draft.write_text(json.dumps(client_result()), encoding="utf-8")
    write_client_result(draft, output)
    assert output.read_bytes().endswith(b"\n")
    assert validate_client_result(json.loads(output.read_text(encoding="utf-8"))).ok


def test_client_validator_rejects_malformed_unhashable_identity() -> None:
    malformed = client_result()
    malformed["clients"][0]["application"] = ["unexpected"]
    assert validate_client_result(malformed).code == "schema_invalid"


def test_evidence_workflow_is_manual_and_commit_bound() -> None:
    workflow = Path(".github/workflows/evidence.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "\n  push:" not in workflow
    assert "source_commit:" in workflow
    assert "validate_evidence.py docs/releases/evidence" in workflow
    assert "release-evidence-${{ steps.source.outputs.commit }}" in workflow


def test_published_schemas_are_strict_and_match_schema_version() -> None:
    for name in ("network-result.schema.json", "client-result.schema.json"):
        schema = json.loads((Path("docs/releases") / name).read_text(encoding="utf-8"))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["additionalProperties"] is False
        assert schema["properties"]["schema_version"]["const"] == 1
