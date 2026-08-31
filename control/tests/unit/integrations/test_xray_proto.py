from __future__ import annotations

from ezopenpn.integrations.xray_proto.app.proxyman.command import command_pb2
from ezopenpn.integrations.xray_proto.common.protocol import user_pb2
from ezopenpn.integrations.xray_proto.common.serial import typed_message_pb2
from ezopenpn.integrations.xray_proto.proxy.vless import account_pb2


def test_add_user_operation_has_expected_type_names_and_field_numbers() -> None:
    account = account_pb2.Account(
        id="11111111-1111-4111-8111-111111111111", encryption="none"
    )
    wrapped = typed_message_pb2.TypedMessage(
        type="xray.proxy.vless.Account",
        value=account.SerializeToString(),
    )
    user = user_pb2.User(
        level=0,
        email="p_abcdefghijklmnopqrstuvwx12",
        account=wrapped,
    )
    operation = command_pb2.AddUserOperation(user=user)

    assert operation.DESCRIPTOR.full_name == (
        "xray.app.proxyman.command.AddUserOperation"
    )
    assert account.DESCRIPTOR.fields_by_name["id"].number == 1
    assert account.DESCRIPTOR.fields_by_name["flow"].number == 2
    assert account.DESCRIPTOR.fields_by_name["encryption"].number == 3
    assert user.DESCRIPTOR.fields_by_name["account"].number == 3


def test_handler_service_exposes_only_the_required_management_calls() -> None:
    service = command_pb2.DESCRIPTOR.services_by_name["HandlerService"]

    assert [method.name for method in service.methods] == [
        "AlterInbound",
        "GetInboundUsers",
        "GetInboundUsersCount",
    ]
