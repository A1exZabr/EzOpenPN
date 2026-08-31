# Xray protobuf provenance

The reduced schemas in this directory are derived from the official XTLS/Xray-core repository.

- Upstream tag: `v26.3.27`
- Upstream commit: `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`
- License: MPL-2.0, reproduced in `LICENSE`
- TypedMessage source: <https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/common/serial/typed_message.proto>
- User source: <https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/common/protocol/user.proto>
- VLESS account source: <https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/proxy/vless/account.proto>
- HandlerService source: <https://github.com/XTLS/Xray-core/blob/d2758a023cd7f4174a5a5fa4ff66e487d4342ba0/app/proxyman/command/command.proto>

Only the messages and fields needed by EzOpenPN are retained. Package names, message names, RPC names and wire field numbers remain identical to upstream.
