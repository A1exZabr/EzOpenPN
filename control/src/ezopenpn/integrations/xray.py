from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any, NoReturn, Protocol, cast
from uuid import UUID

import grpc

from ezopenpn.integrations.xray_proto.app.proxyman.command import (
    command_pb2,
    command_pb2_grpc,
)
from ezopenpn.integrations.xray_proto.common.protocol import user_pb2
from ezopenpn.integrations.xray_proto.common.serial import typed_message_pb2
from ezopenpn.integrations.xray_proto.proxy.vless import account_pb2

_RUNTIME_ID_PATTERN = re.compile(r"p_[a-z2-7]{26}")
_MUTATION_TIMEOUT_SECONDS = 3.0
_LIST_TIMEOUT_SECONDS = 2.0
_INITIAL_READY_DELAY_SECONDS = 0.05
_MAX_READY_DELAY_SECONDS = 0.25
_UNAVAILABLE_CODES = frozenset(
    {
        grpc.StatusCode.CANCELLED,
        grpc.StatusCode.DEADLINE_EXCEEDED,
        grpc.StatusCode.RESOURCE_EXHAUSTED,
        grpc.StatusCode.UNAVAILABLE,
    }
)


class RuntimeUnavailable(RuntimeError):
    pass


class RuntimeRejected(RuntimeError):
    pass


class InvalidRuntimeIdentifier(ValueError):
    pass


class HandlerStub(Protocol):
    def AlterInbound(self, request: Any, timeout: float) -> Any: ...

    def GetInboundUsers(self, request: Any, timeout: float) -> Any: ...

    def GetInboundUsersCount(self, request: Any, timeout: float) -> Any: ...


def _runtime_id(value: str) -> str:
    if _RUNTIME_ID_PATTERN.fullmatch(value) is None:
        raise InvalidRuntimeIdentifier("runtime identifier is invalid")
    return value


def _raise_rpc(error: grpc.RpcError) -> NoReturn:
    if error.code() in _UNAVAILABLE_CODES:
        raise RuntimeUnavailable("Xray runtime unavailable") from None
    raise RuntimeRejected("Xray runtime rejected operation") from None


def _typed(message: Any) -> Any:
    return typed_message_pb2.TypedMessage(
        type=message.DESCRIPTOR.full_name,
        value=message.SerializeToString(),
    )


class GrpcXrayClient:
    _channel: grpc.Channel | None
    _stub: HandlerStub
    _inbound_tag: str
    _monotonic: Callable[[], float]
    _sleep: Callable[[float], None]

    def __init__(self, target: str, inbound_tag: str) -> None:
        if not target.strip() or not inbound_tag.strip():
            raise ValueError("Xray target and inbound tag must not be empty")
        channel = grpc.insecure_channel(target)
        self._channel = channel
        self._stub = cast(HandlerStub, command_pb2_grpc.HandlerServiceStub(channel))
        self._inbound_tag = inbound_tag
        self._monotonic = time.monotonic
        self._sleep = time.sleep

    @classmethod
    def from_stub(
        cls,
        stub: HandlerStub,
        inbound_tag: str,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> GrpcXrayClient:
        if not inbound_tag.strip():
            raise ValueError("Xray inbound tag must not be empty")
        instance = cls.__new__(cls)
        instance._channel = None
        instance._stub = stub
        instance._inbound_tag = inbound_tag
        instance._monotonic = monotonic
        instance._sleep = sleep
        return instance

    def close(self) -> None:
        if self._channel is not None:
            self._channel.close()
            self._channel = None

    def add_user(self, runtime_id: str, user_id: UUID) -> None:
        email = _runtime_id(runtime_id)
        account = account_pb2.Account(id=str(user_id), encryption="none")
        user = user_pb2.User(
            level=0,
            email=email,
            account=_typed(account),
        )
        operation = command_pb2.AddUserOperation(user=user)
        request = command_pb2.AlterInboundRequest(
            tag=self._inbound_tag,
            operation=_typed(operation),
        )
        try:
            self._stub.AlterInbound(request, timeout=_MUTATION_TIMEOUT_SECONDS)
        except grpc.RpcError as error:
            _raise_rpc(error)

    def remove_user(self, runtime_id: str) -> None:
        operation = command_pb2.RemoveUserOperation(email=_runtime_id(runtime_id))
        request = command_pb2.AlterInboundRequest(
            tag=self._inbound_tag,
            operation=_typed(operation),
        )
        try:
            self._stub.AlterInbound(request, timeout=_MUTATION_TIMEOUT_SECONDS)
        except grpc.RpcError as error:
            _raise_rpc(error)

    def list_users(self) -> set[str]:
        request = command_pb2.GetInboundUserRequest(tag=self._inbound_tag)
        try:
            response = self._stub.GetInboundUsers(
                request,
                timeout=_LIST_TIMEOUT_SECONDS,
            )
        except grpc.RpcError as error:
            _raise_rpc(error)
        return {str(user.email) for user in response.users}

    def wait_ready(self, timeout_seconds: float) -> None:
        if timeout_seconds <= 0:
            raise ValueError("readiness timeout must be positive")
        deadline = self._monotonic() + timeout_seconds
        delay = _INITIAL_READY_DELAY_SECONDS
        request = command_pb2.GetInboundUserRequest(tag=self._inbound_tag)
        while True:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise RuntimeUnavailable("Xray runtime unavailable")
            try:
                self._stub.GetInboundUsersCount(
                    request,
                    timeout=min(_LIST_TIMEOUT_SECONDS, remaining),
                )
            except grpc.RpcError as error:
                if error.code() not in _UNAVAILABLE_CODES:
                    _raise_rpc(error)
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    raise RuntimeUnavailable("Xray runtime unavailable") from None
                pause = min(delay, _MAX_READY_DELAY_SECONDS, remaining)
                self._sleep(pause)
                delay = min(delay * 2, _MAX_READY_DELAY_SECONDS)
            else:
                return
