# EzOpenPN Edge and Compose Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package the control plane and both runtimes into a hardened Compose stack with exact host ports, automatic trusted IPv4 certificates and safe certificate delivery to Hysteria2.

**Architecture:** Five containers share two explicit bridge networks. Caddy owns HTTP and panel TLS, Xray owns TCP 443, Hysteria2 owns UDP 443, control stays internal, and a networkless Go process exports the current Caddy certificate into a read-only Hysteria2 mount.

**Tech Stack:** Docker Engine, Compose v2, Caddy 2.11.4, Xray 26.3.27, Hysteria2 2.12.2, Go 1.26, OpenSSL test fixtures and pytest.

**Spec:** `docs/superpowers/specs/2026-08-31-ezopenpn-design.md`

## Global Constraints

- Apply every constraint in `docs/superpowers/plans/2026-08-31-ezopenpn-implementation-index.md`.
- Publish only 80/tcp, 443/tcp, 443/udp and 9443/tcp.
- Map low host ports to unprivileged container ports.
- Use two bridge networks named `edge` and `backend`; mark `backend` internal.
- `cert-sync` has `network_mode: none`.
- Drop all capabilities and keep root filesystems read-only unless a documented write path requires otherwise.
- No image reference is accepted without an immutable amd64 digest in `deploy/images.lock`.
- The production Caddy configuration never falls back to an internal or untrusted certificate.
- The Hysteria2 container must not start ready until a matching, unexpired IPv4 certificate and private key are present.

---

### Task 1: Immutable Image Lock and Runtime Images

**Files:**
- Create: `deploy/images.toml`
- Create: `deploy/images.lock`
- Create: `tools/lock_images.sh`
- Create: `runtime/Dockerfile.xray`
- Create: `runtime/Dockerfile.cert-sync`
- Create: `tests/compose/test_image_lock.py`

**Interfaces:**
- Produces: `tools/lock_images.sh --check|--write`
- Produces images: `ezopenpn-xray:dev`, `ezopenpn-cert-sync:dev`
- Consumes upstream: `ghcr.io/xtls/xray-core:26.3.27`, `tobyxdd/hysteria:v2.12.2`, `caddy:2.11.4-alpine`, `python:3.12.11-slim-bookworm`.

- [ ] **Step 1: Write failing lock validation tests**

```python
def test_every_production_image_has_amd64_digest(image_lock: ImageLock) -> None:
    assert set(image_lock.images) == {"python-base", "go-builder", "distroless-base", "xray-upstream", "hysteria", "caddy"}
    for image in image_lock.images.values():
        assert image.digest.startswith("sha256:")
        assert len(image.digest) == 71
        assert image.platform == "linux/amd64"
```

- [ ] **Step 2: Run and confirm lock files are missing**

Run: `uv run pytest tests/compose/test_image_lock.py -q`

Expected: FAIL because `deploy/images.lock` does not exist.

- [ ] **Step 3: Implement reproducible lock resolution and images**

`images.toml` contains human-readable upstream repositories and versions. `lock_images.sh --write` resolves only `linux/amd64` with `docker buildx imagetools inspect`, writes sorted TOML atomically and refuses a manifest without the requested platform. `--check` resolves again and fails on drift without modifying files. Project-owned image digests are outputs of Plan 05 and enter rendered Compose through the signed release manifest, avoiding a source-build circular dependency.

`Dockerfile.xray` compiles the supervisor in a pinned Go builder, copies the Xray binary and license from the official pinned image, and runs UID 10002 with shared control GID 11001. `Dockerfile.cert-sync` contains only the static exporter binary, CA roots and a non-root UID 10004 with certificate GID 11003.

- [ ] **Step 4: Resolve locks, build and inspect images**

Run: `bash tools/lock_images.sh --write && docker build -f runtime/Dockerfile.xray -t ezopenpn-xray:dev . && docker build -f runtime/Dockerfile.cert-sync -t ezopenpn-cert-sync:dev . && uv run pytest tests/compose/test_image_lock.py -q`

Expected: PASS; both runtime images have non-root users and no shell in the final stage.

- [ ] **Step 5: Commit image locking**

```bash
git add deploy/images.toml deploy/images.lock tools/lock_images.sh runtime/Dockerfile.xray runtime/Dockerfile.cert-sync tests/compose/test_image_lock.py
git commit -m "build: lock and package runtime images"
```

### Task 2: Networkless Certificate Exporter

**Files:**
- Create: `runtime/cmd/cert-sync/main.go`
- Create: `runtime/internal/certsync/discover.go`
- Create: `runtime/internal/certsync/export.go`
- Create: `runtime/internal/certsync/discover_test.go`
- Create: `runtime/internal/certsync/export_test.go`

**Interfaces:**
- Consumes: `--source /caddy-data`, `--output /hysteria-certs`, `--ip 203.0.113.10`, `--interval 60s`
- Produces: `fullchain.pem`, `privkey.pem`, `health.json`
- Produces: `cert-sync --healthcheck /hysteria-certs/health.json --min-validity 30m`
- `health.json`: `{"ip":"203.0.113.10","not_after":"RFC3339","fingerprint":"sha256 hex"}`

- [ ] **Step 1: Write failing certificate selection and atomicity tests**

```go
func TestDiscoverSelectsNewestMatchingIPCertificate(t *testing.T) {
	root := t.TempDir()
	writeCertificatePair(t, root, "older", net.ParseIP("203.0.113.10"), time.Now().Add(2*time.Hour))
	newest := writeCertificatePair(t, root, "newer", net.ParseIP("203.0.113.10"), time.Now().Add(6*time.Hour))
	writeCertificatePair(t, root, "wrong", net.ParseIP("198.51.100.8"), time.Now().Add(8*time.Hour))
	result, err := Discover(root, net.ParseIP("203.0.113.10"), time.Now())
	if err != nil || result.CertificatePath != newest.CertificatePath {
		t.Fatalf("unexpected result: %#v %v", result, err)
	}
}

func TestExportRejectsMismatchedPrivateKey(t *testing.T) {
	pair := newTestCertificate(t, net.ParseIP("203.0.113.10"))
	pair.PrivateKeyPEM = newTestCertificate(t, net.ParseIP("203.0.113.10")).PrivateKeyPEM
	if err := Export(pair, t.TempDir()); err == nil {
		t.Fatal("expected key mismatch")
	}
}
```

- [ ] **Step 2: Run and confirm certsync package is absent**

Run: `cd runtime && go test ./internal/certsync`

Expected: FAIL because the package does not exist.

- [ ] **Step 3: Implement safe discovery and atomic export**

Walk regular `.crt` and `.pem` files without following symlinks. Parse every certificate chain, require the leaf IP SAN to equal the configured IP, require at least 30 minutes remaining, find the paired private key and compare marshaled public keys. Select the greatest `NotAfter`. Write files in the destination filesystem with `CreateTemp`, fsync, chmod `0640`, rename and fsync the directory. Never print PEM data or source filenames at info level.

- [ ] **Step 4: Run unit, race and repeated-export tests**

Run: `cd runtime && go test -race ./internal/certsync ./cmd/cert-sync`

Expected: PASS, including an unchanged export that does not rewrite files.

- [ ] **Step 5: Commit certificate synchronization**

```bash
git add runtime/cmd/cert-sync runtime/internal/certsync
git commit -m "feat: export trusted IP certificates safely"
```

### Task 3: Caddy IP Certificate and Reverse Proxy Configuration

**Files:**
- Create: `deploy/caddy/Caddyfile`
- Create: `tests/compose/test_caddy_config.py`
- Create: `tests/compose/caddy-adapt.sh`

**Interfaces:**
- Consumes: `PUBLIC_IP`, backend `control:8000`
- Listens in container: `8080/tcp`, `9443/tcp`
- Produces trusted short-lived ACME certificate in `/data/caddy`.

- [ ] **Step 1: Write failing Caddy policy tests**

```python
def test_caddy_uses_short_lived_acme_profile(caddyfile: str) -> None:
    assert "profile shortlived" in caddyfile
    assert "tls force_automate" in caddyfile
    assert "tls internal" not in caddyfile
    assert "admin off" in caddyfile


def test_internal_routes_are_not_proxied(caddyfile: str) -> None:
    assert "path /internal/*" in caddyfile
    assert "respond @internal 404" in caddyfile


def test_forwarded_address_is_overwritten(caddyfile: str) -> None:
    assert "header_up -X-Forwarded-For" in caddyfile
    assert "header_up X-Forwarded-For {remote_host}" in caddyfile
```

- [ ] **Step 2: Run and confirm the Caddyfile is missing**

Run: `uv run pytest tests/compose/test_caddy_config.py -q`

Expected: FAIL because the Caddyfile does not exist.

- [ ] **Step 3: Implement the exact Caddy policy**

Set global `admin off`, `http_port 8080`, storage under `/data/caddy` and production Let’s Encrypt ACME. Define only `https://{$PUBLIC_IP}:9443`; let automatic HTTPS own the port-8080 challenge and redirect route. Use `tls force_automate` because an IP would otherwise be eligible for Caddy's local issuer, then configure the ACME issuer with the production directory and `profile shortlived`. Add HSTS, CSP compatible with local CSS and JavaScript, no-referrer, no-sniff, permissions policy and frame denial. Match `/internal/*` first and return 404 without proxying. In `reverse_proxy control:8000`, delete incoming forwarding headers and set host, scheme and client address from Caddy values.

- [ ] **Step 4: Adapt the Caddyfile with the pinned image**

Run: `PUBLIC_IP=203.0.113.10 bash tests/compose/caddy-adapt.sh && uv run pytest tests/compose/test_caddy_config.py -q`

Expected: `caddy adapt --validate` exits 0 and tests pass.

- [ ] **Step 5: Commit edge proxy configuration**

```bash
git add deploy/caddy tests/compose/test_caddy_config.py tests/compose/caddy-adapt.sh
git commit -m "feat: configure trusted IP panel TLS"
```

### Task 4: Hardened Five-Service Compose Stack

**Files:**
- Create: `deploy/compose.yaml`
- Create: `deploy/control.toml.tmpl`
- Create: `deploy/README.internal.md`
- Create: `tests/compose/fixtures/stack.env`
- Create: `tests/compose/test_compose_policy.py`
- Create: `tests/compose/test_compose_render.py`

**Interfaces:**
- Produces services: `control`, `xray`, `hysteria`, `gateway`, `cert-sync`
- Produces networks: `edge`, `backend`
- Produces named or bind volumes matching the spec paths.

- [ ] **Step 1: Write failing structure and privilege tests**

```python
def test_only_expected_host_ports(compose: dict[str, object]) -> None:
    published = collect_published_ports(compose)
    assert published == {(80, "tcp"), (443, "tcp"), (443, "udp"), (9443, "tcp")}


def test_every_host_port_binds_only_public_ipv4(compose: dict[str, object]) -> None:
    for binding in collect_port_bindings(compose):
        assert binding.host_ip == "203.0.113.10"


def test_no_service_has_broad_host_control(compose: dict[str, object]) -> None:
    for service in compose["services"].values():
        assert service.get("privileged") is not True
        assert service.get("network_mode") not in {"host", "service:docker"}
        assert "/var/run/docker.sock" not in json.dumps(service)
        assert service.get("cap_add", []) == []
        assert service.get("cap_drop") == ["ALL"]


def test_rendered_compose_has_only_digest_references(rendered_compose: str) -> None:
    for line in rendered_compose.splitlines():
        if "image:" in line:
            assert "@sha256:" in line
```

- [ ] **Step 2: Run and confirm Compose is missing**

Run: `uv run pytest tests/compose/test_compose_policy.py tests/compose/test_compose_render.py -q`

Expected: FAIL because `deploy/compose.yaml` does not exist.

- [ ] **Step 3: Implement services, mounts and health dependencies**

Bind every published port explicitly to `${PUBLIC_IP}`, then map host `80/tcp` to gateway `8080`, host `443/tcp` to Xray `8443`, host `443/udp` to Hysteria2 `8443`, and host `9443/tcp` to gateway `9443`. This keeps the first release IPv4-only even when IPv6 is enabled on the host. Attach gateway, Xray and Hysteria2 to `edge`; attach gateway, control, Xray and Hysteria2 to `backend`; set `backend.internal: true`; set cert-sync to no network. Add read-only root filesystems, `tmpfs` for `/tmp`, `no-new-privileges`, PIDs limits, memory limits, log rotation, init handling and service healthchecks. Use numeric UIDs and only the shared GIDs required for supervisor socket and exported certificate access. Resolve `CONTROL_IMAGE`, `XRAY_IMAGE` and `CERT_SYNC_IMAGE` from the signed release manifest; test fixtures use local digests, never tags.

The control image receives non-secret config by read-only file and secrets by individual read-only files. No administrator value is present in Compose, environment or labels.

- [ ] **Step 4: Render Compose and run policy tests**

Run: `docker compose -f deploy/compose.yaml --env-file tests/compose/fixtures/stack.env config > /tmp/ezopenpn-compose.json && uv run pytest tests/compose/test_compose_policy.py tests/compose/test_compose_render.py -q`

Expected: PASS and rendered config contains exactly the four published host bindings.

- [ ] **Step 5: Commit hardened Compose**

```bash
git add deploy/compose.yaml deploy/control.toml.tmpl deploy/README.internal.md tests/compose
git commit -m "feat: compose the isolated service stack"
```

### Task 5: First-Start Certificate Dependency and Local Stack Harness

**Files:**
- Create: `tests/compose/fixtures/test-ip-cert.sh`
- Create: `tests/compose/stack-up.sh`
- Create: `tests/compose/stack-down.sh`
- Create: `tests/compose/test_stack_health.py`

**Interfaces:**
- Produces local test profile `test-edge` that mounts a temporary trusted test CA and never uses production ACME.
- Production Compose remains unchanged; the override exists only below `tests/compose`.

- [ ] **Step 1: Write a failing stack readiness test**

```python
def test_hysteria_waits_for_exported_certificate(stack: StackHarness) -> None:
    stack.start_without_certificate()
    assert stack.health("gateway") == "healthy"
    assert stack.health("cert-sync") == "starting"
    assert stack.health("hysteria") != "healthy"
    stack.install_test_certificate()
    stack.wait_healthy("cert-sync", timeout=10)
    stack.wait_healthy("hysteria", timeout=10)


def test_panel_headers_are_present(stack: StackHarness) -> None:
    response = stack.https_get("/login")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
```

- [ ] **Step 2: Run and confirm harness scripts are missing**

Run: `uv run pytest tests/compose/test_stack_health.py -q -m integration`

Expected: FAIL because `StackHarness` cannot start the absent override.

- [ ] **Step 3: Implement temporary CA and deterministic cleanup**

Generate an ephemeral CA and IP SAN certificate with OpenSSL into a `mktemp -d` directory, never the repository. Override only the gateway certificate issuer for the test. Register trap cleanup, use a unique Compose project name, wait on explicit health status and collect sanitized logs on failure. Hysteria2 readiness checks its UDP process and certificate health file timestamp.

- [ ] **Step 4: Run the full local five-service stack**

Run: `bash tests/compose/stack-up.sh && uv run pytest tests/compose/test_stack_health.py -q -m integration; test_status=$?; bash tests/compose/stack-down.sh; exit $test_status`

Expected: PASS and no remaining containers or temporary certificate directory.

- [ ] **Step 5: Commit the local integration harness**

```bash
git add tests/compose
git commit -m "test: verify first-start service dependencies"
```

### Task 6: Certificate Rotation Without Hysteria2 Restart

**Files:**
- Create: `tests/compose/test_certificate_rotation.py`
- Modify: `runtime/internal/certsync/export_test.go`

**Interfaces:**
- Consumes: running local stack from Task 5.
- Produces evidence that a new TLS handshake uses the new certificate while the Hysteria2 container ID remains unchanged.

- [ ] **Step 1: Write a failing rotation test**

```python
def test_rotation_changes_leaf_without_container_restart(stack: StackHarness) -> None:
    before_id = stack.container_id("hysteria")
    before_fingerprint = stack.hysteria_leaf_fingerprint()
    stack.install_rotated_test_certificate()
    stack.wait_for_new_export(before_fingerprint, timeout=10)
    after_fingerprint = stack.hysteria_leaf_fingerprint()
    assert after_fingerprint != before_fingerprint
    assert stack.container_id("hysteria") == before_id
```

- [ ] **Step 2: Run and confirm rotation is not yet observed**

Run: `uv run pytest tests/compose/test_certificate_rotation.py -q -m integration`

Expected: FAIL because the exporter or Hysteria2 reload behavior is incomplete.

- [ ] **Step 3: Add exporter freshness and runtime polling behavior**

Ensure `cert-sync` polls every 60 seconds in production and every 1 second in tests, updates `health.json` only after both PEM files are durable, and reports degraded health when less than 30 minutes remain. Configure Hysteria2 with file paths, not embedded PEM. Pinned Hysteria2 uses its local certificate loader on every new TLS handshake, so the test must observe the rotated leaf without a process or container restart.

- [ ] **Step 4: Run rotation and exporter race suites**

Run: `cd runtime && go test -race ./internal/certsync && cd .. && uv run pytest tests/compose/test_certificate_rotation.py -q -m integration`

Expected: PASS with unchanged Hysteria2 container ID under the validated baseline.

- [ ] **Step 5: Commit certificate rotation behavior**

```bash
git add runtime/internal/certsync tests/compose/test_certificate_rotation.py
git commit -m "test: prove live certificate rotation"
```

### Task 7: Edge Security and Port Exposure Gate

**Files:**
- Create: `tests/compose/test_runtime_security.py`
- Create: `tests/compose/scan_ports.sh`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces CI job `compose-security`.
- Produces: `scan_ports.sh HOST -> machine-readable allowed-port comparison`.

- [ ] **Step 1: Write failing runtime inspection tests**

```python
def test_runtime_mounts_match_policy(stack: StackHarness) -> None:
    for service in stack.services:
        inspection = stack.inspect(service)
        assert inspection["HostConfig"]["Privileged"] is False
        assert inspection["HostConfig"]["ReadonlyRootfs"] is True
        assert inspection["HostConfig"]["CapAdd"] in (None, [])
    assert stack.inspect("cert-sync")["HostConfig"]["NetworkMode"] == "none"
```

- [ ] **Step 2: Run and record any policy mismatch**

Run: `uv run pytest tests/compose/test_runtime_security.py -q -m integration`

Expected: FAIL until all Compose runtime settings match the policy.

- [ ] **Step 3: Correct Compose and implement explicit port scan**

Use `nmap -Pn -n` from a second test container or host namespace. Compare listeners with 80/tcp, 443/tcp, 443/udp and 9443/tcp plus the pre-existing SSH port supplied to the script. Do not treat filtered cloud ports as proof of a local listener. CI validates container configuration; public exposure is repeated on a real VPS in Plan 05.

- [ ] **Step 4: Run the complete edge gate**

Run: `make check && uv run pytest tests/compose -q -m integration && bash tests/compose/scan_ports.sh 127.0.0.1`

Expected: PASS with no internal API port published.

- [ ] **Step 5: Commit edge security checks**

```bash
git add deploy/compose.yaml tests/compose .github/workflows/ci.yml
git commit -m "test: enforce edge isolation and ports"
```

## Plan 03 Checkpoint

Run:

```bash
bash tools/lock_images.sh --check
make check
uv run pytest tests/compose -q -m integration
docker compose -f deploy/compose.yaml config --quiet
git status --short
```

Expected outcome: five healthy isolated services, a trusted IP certificate path, no broad container privileges and only the documented host ports.
