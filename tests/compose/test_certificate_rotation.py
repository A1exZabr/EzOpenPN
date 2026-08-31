from __future__ import annotations

import pytest
from tests.compose.test_stack_health import StackHarness, prepared_stack_harness


@pytest.fixture(scope="module")
def stack_fixture() -> StackHarness:
    harness = prepared_stack_harness()
    harness.start_without_certificate()
    yield harness


@pytest.mark.integration
def test_rotation_changes_leaf_without_container_restart(
    stack_fixture: StackHarness,
) -> None:
    stack = stack_fixture
    if stack.health("cert-sync") != "healthy":
        stack.install_test_certificate()
        stack.wait_healthy("cert-sync", timeout=20)
    if stack.health("hysteria") != "healthy":
        stack.start_hysteria()
        stack.wait_healthy("hysteria", timeout=30)

    before_id = stack.container_id("hysteria")
    before_fingerprint = stack.exported_leaf_fingerprint()
    rotated_ca = stack.install_rotated_test_certificate()
    after_fingerprint = stack.wait_for_new_export(before_fingerprint, timeout=15)

    assert after_fingerprint != before_fingerprint
    assert stack.container_id("hysteria") == before_id
    stack.verify_hysteria_handshake(rotated_ca)
