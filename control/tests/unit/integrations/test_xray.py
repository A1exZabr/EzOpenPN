from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import grpc
import pytest

from ezopenpn.integrations.xray import (
    GrpcXrayClient,
    InvalidRuntimeIdentifier,
    RuntimeUnavailable,
)
from ezopenpn.integrations.xray_proto.app.proxyman.command import command_pb2
from ezopenpn.integrations.xray_proto.common.protocol import user_pb2
from ezopenpn.integrations.xray_proto.proxy.vless import account_pb2

RUNTIME_ID = "p_abcdefghijklmnopqrstuvwx23"


class FakeRpcError(grpc.RpcError):
    def code(self) -> grpc.StatusCode:
        return grpc.StatusCode.UNAVAILABLE

    def details(self) -> str:
        return "sensitive runtime response"


@dataclass
class FakeHandlerStub:
    alter_requests: list[Any] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    fail: bool = False
    readiness_failures: int = 0
    deadlines: list[float] = field(default_factory=list)

    def AlterInbound(self, request: Any, timeout: float) -> Any:
        self.deadlines.append(timeout)
        if self.fail:
            raise FakeRpcError()
        self.alter_requests.append(request)
        return command_pb2.AlterInboundResponse()

    def GetInboundUsers(self, request: Any, timeout: float) -> Any:
        del request
        self.deadlines.append(timeout)
        if self.fail:
            raise FakeRpcError()
        return command_pb2.GetInboundUserResponse(
            users=[user_pb2.User(email=value) for value in self.users]
        )

    def GetInboundUsersCount(self, request: Any, timeout: float) -> Any:
        del request
        self.deadlines.append(timeout)
        if self.readiness_failures > 0:
            self.readiness_failures -= 1
            raise FakeRpcError()
        return command_pb2.GetInboundUsersCountResponse(count=len(self.users))


def test_add_user_wraps_vless_account() -> None:
    stub = FakeHandlerStub()
    client = GrpcXrayClient.from_stub(stub, inbound_tag="protected-entry")

    client.add_user(
        RUNTIME_ID,
        UUID("11111111-1111-4111-8111-111111111111"),
    )

    request = stub.alter_requests[0]
    assert request.tag == "protected-entry"
    operation = command_pb2.AddUserOperation.FromString(request.operation.value)
    assert request.operation.type == operation.DESCRIPTOR.full_name
    assert operation.user.email == RUNTIME_ID
    account = account_pb2.Account.FromString(operation.user.account.value)
    assert operation.user.account.type == account.DESCRIPTOR.full_name
    assert account.id == "11111111-1111-4111-8111-111111111111"
    assert account.encryption == "none"
    assert stub.deadlines == [3.0]


def test_remove_and_list_use_the_fixed_inbound() -> None:
    stub = FakeHandlerStub(users=[RUNTIME_ID])
    client = GrpcXrayClient.from_stub(stub, inbound_tag="protected-entry")

    assert client.list_users() == {RUNTIME_ID}
    client.remove_user(RUNTIME_ID)

    request = stub.alter_requests[0]
    operation = command_pb2.RemoveUserOperation.FromString(request.operation.value)
    assert request.tag == "protected-entry"
    assert operation.email == RUNTIME_ID
    assert stub.deadlines == [2.0, 3.0]


def test_invalid_runtime_id_is_rejected_before_an_rpc() -> None:
    stub = FakeHandlerStub()
    client = GrpcXrayClient.from_stub(stub, inbound_tag="protected-entry")

    with pytest.raises(InvalidRuntimeIdentifier):
        client.remove_user("device-name")

    assert stub.alter_requests == []
    assert stub.deadlines == []


def test_rpc_error_does_not_expose_runtime_details() -> None:
    stub = FakeHandlerStub(fail=True)

    with pytest.raises(RuntimeUnavailable, match="Xray runtime unavailable") as captured:
        GrpcXrayClient.from_stub(stub, "protected-entry").list_users()

    assert "sensitive runtime response" not in str(captured.value)


def test_readiness_retries_with_bounded_backoff() -> None:
    stub = FakeHandlerStub(readiness_failures=2)
    now = 0.0
    sleeps: list[float] = []

    def monotonic() -> float:
        return now

    def sleep(delay: float) -> None:
        nonlocal now
        sleeps.append(delay)
        now += delay

    client = GrpcXrayClient.from_stub(
        stub,
        "protected-entry",
        monotonic=monotonic,
        sleep=sleep,
    )

    client.wait_ready(1.0)

    assert sleeps == [0.05, 0.1]
    assert max(stub.deadlines) <= 2.0
