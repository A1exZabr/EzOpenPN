# EzOpenPN Transport Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the control plane to real Xray and Hysteria2 runtimes, issue two valid links per profile and make create, disable, enable, delete and reconciliation behavior deterministic.

**Architecture:** Python adapters talk to Xray HandlerService over the private Compose network and to Hysteria2 Traffic Stats API over private HTTP. A minimal Go PID 1 supervises only the Xray child and exposes a fixed Unix-socket restart operation so active sessions can be closed without Docker control privileges.

**Tech Stack:** Python 3.12, gRPC Python 1.83.1, Protobuf 7.36.0, HTTPX 0.28.1, Go 1.26, Xray 26.3.27, Hysteria2 2.12.2 and pytest.

**Spec:** `docs/superpowers/specs/2026-08-31-ezopenpn-design.md`

## Global Constraints

- Apply every constraint in `docs/superpowers/plans/2026-08-31-ezopenpn-implementation-index.md`.
- Xray HandlerService and Hysteria2 management endpoints never bind a host port.
- Only the fixed Xray supervisor operation `POST /restart` is accepted; request bodies and arbitrary commands are rejected.
- Runtime IDs are opaque and contain no profile name or administrator data.
- Hysteria2 auth returns HTTP 200 for allow and deny decisions.
- Disable first blocks durable authorization, then closes Hysteria2 sessions, removes the Xray user and restarts Xray.
- A failed runtime operation never causes plaintext credentials to enter an exception or log.
- The issued XHTTP mode is exactly `packet-up`.

---

### Task 1: Transport Link and Combined Subscription Encoding

**Files:**
- Create: `control/src/ezopenpn/profiles/links.py`
- Create: `control/src/ezopenpn/web/routes/subscriptions.py`
- Create: `control/tests/unit/profiles/test_links.py`
- Create: `control/tests/integration/web/test_subscriptions.py`

**Interfaces:**
- Produces: `build_vless_link(material: VlessMaterial, label: str) -> str`
- Produces: `build_hysteria_link(material: HysteriaMaterial, label: str) -> str`
- Produces: `build_subscription(vless_link: str, hysteria_link: str) -> str`
- Produces: `build_qr_svg(value: str) -> str`
- Produces: `GET /s/{subscription_token}` for active profiles only.

- [ ] **Step 1: Write failing deterministic link tests**

```python
def test_vless_link_contains_required_xhttp_parameters() -> None:
    link = build_vless_link(VlessMaterial(
        user_id=UUID("11111111-1111-4111-8111-111111111111"),
        host=IPv4Address("203.0.113.10"),
        public_key="public-key",
        server_name="www.example.org",
        short_id="a1b2c3d4e5f60708",
        path="/r4nd0m",
    ), "Телефон")
    query = parse_qs(urlsplit(link).query)
    assert query["type"] == ["xhttp"]
    assert query["mode"] == ["packet-up"]
    assert query["security"] == ["reality"]
    assert query["encryption"] == ["none"]


def test_subscription_is_base64_of_two_lines() -> None:
    encoded = build_subscription("first://one", "second://two")
    assert base64.b64decode(encoded).decode("utf-8") == "first://one\nsecond://two"


def test_subscription_response_is_private(subscription_client: TestClient, active_profile: ProfileFixture) -> None:
    response = subscription_client.get(f"/s/{active_profile.subscription_token}")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["cache-control"] == "no-store"
    assert base64.b64decode(response.text).decode("utf-8").count("\n") == 1


def test_disabled_subscription_is_not_disclosed(subscription_client: TestClient, disabled_profile: ProfileFixture) -> None:
    response = subscription_client.get(f"/s/{disabled_profile.subscription_token}")
    assert response.status_code == 404
```

- [ ] **Step 2: Run and confirm missing link functions**

Run: `uv run pytest control/tests/unit/profiles/test_links.py control/tests/integration/web/test_subscriptions.py -q`

Expected: FAIL on missing imports.

- [ ] **Step 3: Implement strict URI construction and SVG output**

Use `urllib.parse.urlencode` and quote auth, path and fragment values exactly once. The VLESS query order is `type`, `security`, `encryption`, `pbk`, `fp`, `sni`, `sid`, `path`, `mode`. The Hysteria2 URI uses the public IP as authority, includes `obfs=salamander` and `obfs-password`, and omits insecure certificate flags. Generate QR as escaped inline SVG with Segno and reject values above 8192 UTF-8 bytes. The subscription route performs HMAC lookup, requires `active`, builds links only after decrypting the profile key, returns Base64 of exactly two newline-separated UTF-8 lines, sets `text/plain; charset=utf-8` and `Cache-Control: no-store`, and uses the same 404 for missing, disabled and malformed tokens.

- [ ] **Step 4: Run focused tests and URI round trips**

Run: `uv run pytest control/tests/unit/profiles/test_links.py control/tests/integration/web/test_subscriptions.py -q && uv run ruff check control/src/ezopenpn/profiles/links.py control/src/ezopenpn/web/routes/subscriptions.py`

Expected: PASS with non-ASCII labels round-tripping through URL parsing.

- [ ] **Step 5: Commit link generation**

```bash
git add control/src/ezopenpn/profiles/links.py control/src/ezopenpn/web/routes/subscriptions.py control/tests/unit/profiles/test_links.py control/tests/integration/web/test_subscriptions.py
git commit -m "feat: generate dual transport links"
```

### Task 2: Minimal Pinned Xray Protobuf Surface

**Files:**
- Create: `proto/xray/common/serial/typed_message.proto`
- Create: `proto/xray/common/protocol/user.proto`
- Create: `proto/xray/proxy/vless/account.proto`
- Create: `proto/xray/app/proxyman/command/command.proto`
- Create: `proto/xray/LICENSE`
- Create: `proto/xray/UPSTREAM.md`
- Create: `tools/generate_xray_proto.sh`
- Create: generated `control/src/ezopenpn/integrations/xray_proto/*_pb2.py`
- Create: generated `control/src/ezopenpn/integrations/xray_proto/*_pb2_grpc.py`
- Create: `control/tests/unit/integrations/test_xray_proto.py`

**Interfaces:**
- Produces the exact protobuf packages `xray.common.serial`, `xray.common.protocol`, `xray.proxy.vless` and `xray.app.proxyman.command`.
- Produces HandlerService methods `AlterInbound`, `GetInboundUsers` and `GetInboundUsersCount`.

- [ ] **Step 1: Write a failing wire-format test**

```python
def test_add_user_operation_has_expected_type_names() -> None:
    account = account_pb2.Account(id="11111111-1111-4111-8111-111111111111", encryption="none")
    wrapped = typed_message_pb2.TypedMessage(
        type="xray.proxy.vless.Account",
        value=account.SerializeToString(),
    )
    user = user_pb2.User(level=0, email="p_abcdefghijklmnopqrstuvwx12", account=wrapped)
    operation = command_pb2.AddUserOperation(user=user)
    assert operation.DESCRIPTOR.full_name == "xray.app.proxyman.command.AddUserOperation"
```

- [ ] **Step 2: Run and confirm generated modules are missing**

Run: `uv run pytest control/tests/unit/integrations/test_xray_proto.py -q`

Expected: FAIL on missing `xray_proto` modules.

- [ ] **Step 3: Add reduced upstream-compatible schemas and generator**

Copy only field numbers 1 to 3 of the VLESS Account message, TypedMessage, User, AddUserOperation, RemoveUserOperation, AlterInbound request and response, GetInboundUser request and both responses. Keep exact package names and the HandlerService RPC names. Preserve MPL-2.0 file headers, include the upstream license, and make `UPSTREAM.md` record tag `v26.3.27`, commit `d2758a0` and source URLs. Generate with:

```bash
uv run python -m grpc_tools.protoc \
  -I proto/xray \
  --python_out=control/src/ezopenpn/integrations/xray_proto \
  --grpc_python_out=control/src/ezopenpn/integrations/xray_proto \
  proto/xray/common/serial/typed_message.proto \
  proto/xray/common/protocol/user.proto \
  proto/xray/proxy/vless/account.proto \
  proto/xray/app/proxyman/command/command.proto
```

The script runs generation in a temporary directory, fixes package-relative Python imports, compares output with committed files and supports `--write` for deliberate updates.

- [ ] **Step 4: Run generation reproducibility and descriptor tests**

Run: `bash tools/generate_xray_proto.sh --check && uv run pytest control/tests/unit/integrations/test_xray_proto.py -q`

Expected: PASS and no generated diff.

- [ ] **Step 5: Commit the pinned API surface**

```bash
git add proto/xray tools/generate_xray_proto.sh control/src/ezopenpn/integrations/xray_proto control/tests/unit/integrations/test_xray_proto.py
git commit -m "build: add pinned Xray API schema"
```

### Task 3: Xray HandlerService Adapter

**Files:**
- Create: `control/src/ezopenpn/integrations/__init__.py`
- Create: `control/src/ezopenpn/integrations/xray.py`
- Create: `control/tests/unit/integrations/test_xray.py`

**Interfaces:**
- Produces: `GrpcXrayClient.add_user(runtime_id: str, user_id: UUID) -> None`
- Produces: `GrpcXrayClient.remove_user(runtime_id: str) -> None`
- Produces: `GrpcXrayClient.list_users() -> set[str]`
- Produces: `GrpcXrayClient.wait_ready(timeout_seconds: float) -> None`
- Raises: `RuntimeUnavailable` or `RuntimeRejected`, with safe fixed messages.

- [ ] **Step 1: Write failing adapter tests against a fake stub**

```python
def test_add_user_wraps_vless_account(fake_handler_stub: FakeHandlerStub) -> None:
    client = GrpcXrayClient.from_stub(fake_handler_stub, inbound_tag="protected-entry")
    client.add_user("p_abcdefghijklmnopqrstuvwx12", UUID("11111111-1111-4111-8111-111111111111"))
    request = fake_handler_stub.alter_requests[0]
    assert request.tag == "protected-entry"
    operation = command_pb2.AddUserOperation.FromString(request.operation.value)
    account = account_pb2.Account.FromString(operation.user.account.value)
    assert account.encryption == "none"


def test_rpc_error_does_not_expose_runtime_details(fake_handler_stub: FakeHandlerStub) -> None:
    fake_handler_stub.fail_with("secret runtime response")
    with pytest.raises(RuntimeUnavailable, match="Xray runtime unavailable") as error:
        GrpcXrayClient.from_stub(fake_handler_stub, "protected-entry").list_users()
    assert "secret runtime response" not in str(error.value)
```

- [ ] **Step 2: Run and confirm the adapter is missing**

Run: `uv run pytest control/tests/unit/integrations/test_xray.py -q`

Expected: FAIL on missing `GrpcXrayClient`.

- [ ] **Step 3: Implement bounded gRPC calls**

Use an insecure channel only because the endpoint is confined to the internal Compose network. Set a 3-second deadline for mutations, a 2-second deadline for listing and exponential readiness polling capped at 250 ms. Wrap AddUserOperation and RemoveUserOperation in TypedMessage with their exact descriptor full names. Validate runtime IDs before sending.

- [ ] **Step 4: Run adapter and descriptor suites**

Run: `uv run pytest control/tests/unit/integrations/test_xray.py control/tests/unit/integrations/test_xray_proto.py -q`

Expected: PASS.

- [ ] **Step 5: Commit Xray integration**

```bash
git add control/src/ezopenpn/integrations control/tests/unit/integrations/test_xray.py
git commit -m "feat: manage Xray runtime users"
```

### Task 4: Narrow Xray Process Supervisor

**Files:**
- Create: `runtime/go.mod`
- Create: `runtime/cmd/xray-supervisor/main.go`
- Create: `runtime/internal/supervisor/process.go`
- Create: `runtime/internal/supervisor/server.go`
- Create: `runtime/internal/supervisor/process_test.go`
- Create: `runtime/internal/supervisor/server_test.go`
- Create: `control/src/ezopenpn/integrations/supervisor.py`
- Create: `control/tests/unit/integrations/test_supervisor.py`

**Interfaces:**
- Produces Unix HTTP: `GET /health`, `POST /restart`
- Produces: `UnixXraySupervisorClient.restart() -> None`
- Environment fixed at image build: child binary `/usr/local/bin/xray`, config `/etc/xray/config.json`, socket `/run/ezopenpn-xray/control.sock`.

- [ ] **Step 1: Write failing Go route and restart serialization tests**

```go
func TestServerRejectsRequestBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/restart", strings.NewReader("unexpected"))
	NewServer(&fakeRestarter{}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestRestartsAreSerialized(t *testing.T) {
	process := newFakeProcess()
	restarter := NewRestarter(process)
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); _ = restarter.Restart(context.Background()) }()
	go func() { defer group.Done(); _ = restarter.Restart(context.Background()) }()
	group.Wait()
	if process.maxConcurrent != 1 {
		t.Fatalf("concurrent restarts = %d", process.maxConcurrent)
	}
}
```

- [ ] **Step 2: Run and confirm missing Go packages**

Run: `cd runtime && go test ./...`

Expected: FAIL because the supervisor package does not exist.

- [ ] **Step 3: Implement PID 1 behavior and Python UDS client**

Start the fixed child command, forward SIGTERM and SIGINT, reap every child, and exit nonzero if the child repeatedly fails more than five times in one minute. For restart, send SIGTERM, wait up to 3 seconds, send SIGKILL if needed, start a new child and return 202 only after it remains alive for 500 ms. Create the socket directory, remove only an existing socket owned by the current UID, bind with umask `0007` and reject all methods and paths except the two listed. The Python client uses `httpx.HTTPTransport(uds=...)`, an empty body and a 4-second timeout.

- [ ] **Step 4: Run Go, Python and race tests**

Run: `cd runtime && go test -race ./... && cd .. && uv run pytest control/tests/unit/integrations/test_supervisor.py -q`

Expected: PASS with serialized restarts and no arbitrary process arguments.

- [ ] **Step 5: Commit the supervisor**

```bash
git add runtime control/src/ezopenpn/integrations/supervisor.py control/tests/unit/integrations/test_supervisor.py
git commit -m "feat: add isolated Xray supervisor"
```

### Task 5: Hysteria2 Auth Route and Kick Adapter

**Files:**
- Create: `control/src/ezopenpn/integrations/hysteria.py`
- Create: `control/src/ezopenpn/web/routes/hysteria_auth.py`
- Create: `control/tests/unit/integrations/test_hysteria.py`
- Create: `control/tests/integration/web/test_hysteria_auth.py`

**Interfaces:**
- Produces: `HttpHysteriaClient.kick(runtime_id: str) -> None`
- Produces: `POST /internal/hysteria/auth`
- Auth input: `{"addr": "198.51.100.4:50000", "auth": "opaque-value", "tx": 1250000}`
- Auth output: `{"ok": true, "id": "p_..."}` or `{"ok": false, "id": ""}`

- [ ] **Step 1: Write failing allow, deny and kick tests**

```python
def test_active_token_is_allowed(internal_client: TestClient, active_profile: ProfileFixture) -> None:
    response = internal_client.post("/internal/hysteria/auth", json={"addr": "198.51.100.4:50000", "auth": active_profile.hysteria_secret, "tx": 1250000})
    assert response.status_code == 200
    assert response.json() == {"ok": True, "id": active_profile.runtime_id}


def test_kick_uses_authorization_header(respx_mock: MockRouter) -> None:
    route = respx_mock.post("http://hysteria:9999/kick").mock(return_value=Response(200))
    HttpHysteriaClient("http://hysteria:9999", "stats-secret").kick("p_abcdefghijklmnopqrstuvwx12")
    assert route.calls[0].request.headers["authorization"] == "stats-secret"
    assert json.loads(route.calls[0].request.content) == ["p_abcdefghijklmnopqrstuvwx12"]
```

- [ ] **Step 2: Run and confirm missing route and adapter**

Run: `uv run pytest control/tests/unit/integrations/test_hysteria.py control/tests/integration/web/test_hysteria_auth.py -q`

Expected: FAIL on missing modules.

- [ ] **Step 3: Implement HMAC lookup and fixed public responses**

Reject malformed payloads and auth values over 512 bytes. The route is reachable only on the internal control listener, and Plan 03 explicitly rejects `/internal/` at the gateway. Use the repository HMAC lookup and require `active` state. Do not log `addr` or `auth`. Kick posts a one-element JSON list with the separate stats secret in `Authorization`, uses a 3-second timeout and maps all response bodies to safe fixed errors.

- [ ] **Step 4: Run auth, adapter and log-capture tests**

Run: `uv run pytest control/tests/unit/integrations/test_hysteria.py control/tests/integration/web/test_hysteria_auth.py -q`

Expected: PASS; captured logs contain neither auth input nor source address.

- [ ] **Step 5: Commit Hysteria2 integration**

```bash
git add control/src/ezopenpn/integrations/hysteria.py control/src/ezopenpn/web/routes/hysteria_auth.py control/tests/unit/integrations/test_hysteria.py control/tests/integration/web/test_hysteria_auth.py
git commit -m "feat: authenticate and revoke Hysteria2 profiles"
```

### Task 6: Transactional Profile Coordinator

**Files:**
- Create: `control/src/ezopenpn/profiles/coordinator.py`
- Modify: `control/src/ezopenpn/web/app.py`
- Modify: `control/src/ezopenpn/web/routes/profiles.py`
- Create: `control/tests/unit/profiles/test_coordinator.py`
- Modify: `control/tests/integration/web/test_profiles.py`

**Interfaces:**
- Produces the `ProfileCoordinator` interface from the index.
- Consumes: `GrpcXrayClient`, `HttpHysteriaClient`, `UnixXraySupervisorClient`, `ProfileRepository`, `SecretCipher` and link builders.

- [ ] **Step 1: Write failing ordered-call tests**

```python
def test_disable_blocks_auth_before_kick_and_restart(fixture: CoordinatorFixture) -> None:
    fixture.coordinator.disable(fixture.active_profile_id)
    assert fixture.events == [
        "database:disabled",
        "hysteria:kick",
        "xray:remove",
        "xray:restart",
        "xray:ready",
        "xray:reconcile-active",
    ]


def test_failed_create_never_returns_links(fixture: CoordinatorFixture) -> None:
    fixture.xray.reject_add = True
    with pytest.raises(ProfileProvisioningFailed):
        fixture.coordinator.create("Телефон")
    assert fixture.repository.only_profile().state is ProfileState.ERROR
```

- [ ] **Step 2: Run and confirm coordinator is missing**

Run: `uv run pytest control/tests/unit/profiles/test_coordinator.py -q`

Expected: FAIL on missing `ProfileCoordinator`.

- [ ] **Step 3: Implement explicit operation phases**

Create writes pending material, adds the Xray user, marks active and only then returns links. Disable commits disabled state before remote calls, then attempts every revocation phase even when an earlier remote call fails: kick Hysteria2, remove the Xray user, restart Xray, wait at most 6 seconds and re-add every other active runtime user. Aggregate only fixed error codes. Enable adds Xray first and commits active only after confirmation. Delete calls disable, deletes the wrapped per-profile data key before deleting ciphertext and lookup rows, checkpoints the WAL, and leaves only a safe audit event. Every failure records a fixed error code and a retryable state without exception details.

- [ ] **Step 4: Run coordinator and web lifecycle tests**

Run: `uv run pytest control/tests/unit/profiles/test_coordinator.py control/tests/integration/web/test_profiles.py -q`

Expected: PASS and the web routes render actual links only for active profiles.

- [ ] **Step 5: Commit runtime lifecycle orchestration**

```bash
git add control/src/ezopenpn/profiles/coordinator.py control/src/ezopenpn/web control/tests/unit/profiles/test_coordinator.py control/tests/integration/web/test_profiles.py
git commit -m "feat: coordinate profile runtime lifecycle"
```

### Task 7: Startup Reconciliation and Degraded Health

**Files:**
- Create: `control/src/ezopenpn/profiles/reconcile.py`
- Modify: `control/src/ezopenpn/web/routes/health.py`
- Create: `control/tests/unit/profiles/test_reconcile.py`
- Modify: `control/tests/integration/web/test_auth.py`

**Interfaces:**
- Produces: `RuntimeReconciler.run() -> ReconcileResult`
- `ReconcileResult` contains added, removed, restarted and error-code fields without credentials.

- [ ] **Step 1: Write failing set-difference tests**

```python
def test_reconcile_adds_missing_and_removes_extra(reconcile_fixture: ReconcileFixture) -> None:
    reconcile_fixture.database_active = {"p_active_one", "p_active_two"}
    reconcile_fixture.xray_users = {"p_active_two", "p_unknown"}
    result = reconcile_fixture.reconciler.run()
    assert result.added == ("p_active_one",)
    assert result.removed == ("p_unknown",)
    assert result.restarted is True
```

- [ ] **Step 2: Run and confirm missing reconciler**

Run: `uv run pytest control/tests/unit/profiles/test_reconcile.py -q`

Expected: FAIL on missing `RuntimeReconciler`.

- [ ] **Step 3: Implement fail-closed reconciliation**

Compare active database runtime IDs with HandlerService users. Remove extras first. If any extra existed, restart Xray to close its prior sessions, wait ready and re-add the complete active set. Otherwise add only missing users. Run once in FastAPI lifespan before readiness, every 60 seconds afterward, and immediately after a runtime mutation error. A runtime error leaves `/health/live` green and `/health/ready` at 503 with code `runtime_reconcile_failed`; it never prevents password reset or local diagnostics.

- [ ] **Step 4: Run reconcile and health tests**

Run: `uv run pytest control/tests/unit/profiles/test_reconcile.py control/tests/integration/web/test_auth.py -q`

Expected: PASS.

- [ ] **Step 5: Commit reconciliation**

```bash
git add control/src/ezopenpn/profiles/reconcile.py control/src/ezopenpn/web/routes/health.py control/tests
git commit -m "feat: reconcile durable and runtime profiles"
```

### Task 8: Runtime Configuration Templates and Real Integration Harness

**Files:**
- Create: `deploy/xray/config.json.tmpl`
- Create: `deploy/hysteria/config.yaml.tmpl`
- Create: `deploy/masquerade/index.html`
- Create: `tools/render_runtime_config.py`
- Create: `tests/compose/runtime-compose.yaml`
- Create: `tests/compose/test_runtime.py`

**Interfaces:**
- Produces: `render_runtime_config.py --values FILE --output-root DIR`
- Xray internal gRPC: `xray:10085`
- Xray public container listener: `8443/tcp`
- Hysteria2 public container listener: `8443/udp`
- Hysteria2 stats listener: `9999/tcp` on backend only.

- [ ] **Step 1: Write failing template and runtime tests**

```python
def test_rendered_xray_config_has_no_static_profiles(rendered_config: dict[str, object]) -> None:
    inbound = next(item for item in rendered_config["inbounds"] if item["tag"] == "protected-entry")
    assert inbound["settings"]["clients"] == []
    assert inbound["streamSettings"]["network"] == "xhttp"
    assert inbound["streamSettings"]["realitySettings"]["show"] is False


def test_rendered_hysteria_is_fail_closed(rendered_hysteria: dict[str, object]) -> None:
    assert rendered_hysteria["auth"]["type"] == "http"
    assert rendered_hysteria["auth"]["http"]["url"] == "http://control:8000/internal/hysteria/auth"
```

- [ ] **Step 2: Run and confirm missing templates**

Run: `uv run pytest tests/compose/test_runtime.py -q`

Expected: FAIL because templates are absent.

- [ ] **Step 3: Implement strict rendering and real containers**

Render JSON and YAML from a schema-validated values file using Jinja2 strict undefined mode, write to a temporary sibling and atomically rename after `xray run -test -config` and Hysteria2 server config validation. Xray includes one VLESS inbound with XHTTP and Reality, empty clients, randomized fallback limits, one private API inbound and direct, block and API routes. Hysteria2 uses file TLS, Salamander, HTTP auth, string masquerade content and a secret-protected stats API. The test harness uses ephemeral self-signed IP material only inside its temporary directory.

- [ ] **Step 4: Run template tests and actual management calls**

Run: `uv run pytest tests/compose/test_runtime.py -q -m integration`

Expected: PASS after starting both pinned runtimes, adding and listing one Xray user, authenticating one Hysteria2 token and kicking its runtime ID.

- [ ] **Step 5: Commit runtime configuration**

```bash
git add deploy/xray deploy/hysteria deploy/masquerade tools/render_runtime_config.py tests/compose
git commit -m "feat: configure and verify both runtimes"
```

## Plan 02 Checkpoint

Run:

```bash
make check
cd runtime && go test -race ./...
cd ..
uv run pytest tests/compose/test_runtime.py -q -m integration
git status --short
```

Expected outcome: creating a profile yields two links; disabling it blocks new auth, kicks Hysteria2, removes the Xray account, restarts Xray through the narrow socket and reconciles all remaining active profiles.
