# EzOpenPN Implementation Plan Index

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and release a one-command, self-hosted protected-connection server with an understandable Russian administration panel and two independently usable transports.

**Architecture:** The work is divided into five plans with explicit interfaces. The control plane owns durable state and the web UI, transport adapters own runtime reconciliation, the edge layer owns containers and certificates, the operations layer owns installation and recovery, and the release layer owns documentation and evidence gates.

**Tech Stack:** Python 3.12, FastAPI 0.141.1, SQLAlchemy 2.0.52, Alembic 1.19.1, SQLite, PyNaCl 1.6.2, Argon2, Jinja2, vanilla JavaScript, Go 1.26, Xray 26.3.27, Hysteria2 2.12.2, Caddy 2.11.4, Docker Engine, Compose v2, Bash and Bats.

**Spec:** `docs/superpowers/specs/2026-08-31-ezopenpn-design.md`

## Global Constraints

- The first recommendation in README and the installer is a separate clean VPS.
- Supported hosts are Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Debian 12 and Debian 13 on amd64.
- The host must have a directly assigned public IPv4, at least 1 GiB RAM and at least 4 GiB free disk.
- Host ports are exactly 80/tcp, 443/tcp, 443/udp and 9443/tcp; SSH is left untouched.
- VLESS + Reality over XHTTP and Hysteria2 with Salamander are both issued for every profile.
- Issued XHTTP links use `packet-up`; ordinary client multiplexing is not enabled.
- No user-owned domain is required; Caddy obtains a trusted short-lived certificate for the public IPv4.
- No container receives `privileged`, host networking, Docker Socket or `NET_ADMIN`.
- The panel has exactly one local administrator in the first release.
- Profile credentials are encrypted with XChaCha20-Poly1305 and looked up with HMAC-SHA-256.
- Administrator passwords use Argon2id with 64 MiB memory, 3 passes, parallelism 2, a 16-byte salt and a 32-byte hash.
- Sessions expire after 12 hours of inactivity and after 7 days total.
- SQLite is the source of truth; Xray runtime users are reconciled from it.
- A profile is recommended per device, but repeated import is not technically blocked.
- Commerce, tariffs, invitation rewards, messaging integrations, quotas, expiry dates and external telemetry are out of scope.
- The repository-wide content guard rejects the two prohibited historical network labels, legacy identifiers, secrets, U+2013 and U+2014.
- The repository begins with clean history and remains private until history, security, license, terminology and release checks pass.
- A handshake is not release evidence; both transports must pass external throughput tests from at least two different network types.
- Every task follows red, green, refactor and ends in a focused commit.

---

## Plan Set and Dependency Order

1. `2026-08-31-01-foundation-control-plane.md`
   - Produces the Python package, content guard, durable models, cryptography, administrator lifecycle, session security, profile domain service and a locally usable panel.
2. `2026-08-31-02-transport-runtime.md`
   - Consumes the profile service and produces link generation, Xray gRPC integration, Hysteria2 auth and kick integration, runtime reconciliation and the narrow Xray supervisor.
3. `2026-08-31-03-edge-compose.md`
   - Consumes the control and runtime images and produces hardened Compose, Caddy IP certificate handling, certificate export and all local container health tests.
4. `2026-08-31-04-installer-operations.md`
   - Consumes the release bundle and produces preflight, one-command installation, firewall handling, status, doctor, backup, restore, update, reinstall, uninstall and purge.
5. `2026-08-31-05-release-documentation.md`
   - Consumes the working stack and produces beginner documentation, CI, supply-chain evidence, VM tests, external network evidence and the signed first release.

Each plan must be completed in order. A later plan may add tests against earlier interfaces, but it must not silently rename those interfaces. Any necessary interface change is made first in the owning plan with its tests and then propagated as a separate commit.

## Spec Coverage Map

| Spec sections | Owning implementation tasks |
|---|---|
| 1 to 3: purpose, main flow, language and clean history | Plan 01 Tasks 1 and 11; Plan 05 Tasks 1 and 9 |
| 4 and 5: supported host and preflight | Plan 04 Task 2; Plan 05 Task 6 |
| 6 and 7: services, networks, ports and privileges | Plan 02 Tasks 3 to 8; Plan 03 Tasks 1 to 7 |
| 8: durable data and secrets | Plan 01 Tasks 2 to 6; Plan 04 Task 8 |
| 9: profile lifecycle and subscription | Plan 02 Tasks 1, 6 and 7 |
| 10 and 11: panel and administrator security | Plan 01 Tasks 5, 8 and 9; Plan 05 Task 7 |
| 12 and 13: service commands, idempotency and rollback | Plan 04 Tasks 1 and 6 to 10 |
| 14: observability and privacy | Plan 04 Task 7; Plan 05 Task 3 |
| 15: images and supply chain | Plan 03 Task 1; Plan 05 Tasks 2 to 5 |
| 16 and 17: tests and first-release criteria | Plan 03 Tasks 5 to 7; Plan 05 Tasks 3 to 9 |
| 18: excluded features | Global constraints and Plan 05 documentation contracts |
| 19: release stages | This dependency order and Plan 05 |
| 20: operational risks | Plan 02 Task 7; Plan 03 Tasks 6 and 7; Plan 04 Tasks 2 and 9; Plan 05 Task 8 |
| 21: primary sources | Preserved in the approved spec and third-party notices |

## Repository File Map

```text
EzOpenPN/
├── .github/
│   ├── dependabot.yml
│   └── workflows/
│       ├── ci.yml
│       ├── images.yml
│       ├── release.yml
│       └── vm-matrix.yml
├── control/
│   ├── Dockerfile
│   ├── alembic.ini
│   ├── migrations/
│   ├── src/ezopenpn/
│   │   ├── cli.py
│   │   ├── config.py
│   │   ├── db.py
│   │   ├── models.py
│   │   ├── security/
│   │   ├── profiles/
│   │   ├── integrations/
│   │   └── web/
│   └── tests/
├── runtime/
│   ├── Dockerfile.xray
│   ├── Dockerfile.cert-sync
│   ├── go.mod
│   ├── go.sum
│   ├── cmd/
│   │   ├── xray-supervisor/
│   │   └── cert-sync/
│   └── internal/
├── proto/xray/
├── deploy/
│   ├── compose.yaml
│   ├── caddy/Caddyfile
│   ├── xray/config.json.tmpl
│   ├── hysteria/config.yaml.tmpl
│   └── masquerade/index.html
├── installer/
│   ├── install.sh
│   ├── lib/
│   ├── bin/ezopenpn
│   └── systemd/ezopenpn.service
├── tests/
│   ├── compose/
│   ├── shell/
│   ├── vm/
│   └── release/
├── tools/
│   ├── content_guard.py
│   ├── lock_images.sh
│   ├── toolchain.toml
│   ├── toolchain.lock
│   └── build_release.sh
├── docs/
│   ├── getting-started.md
│   ├── profiles.md
│   ├── recovery.md
│   ├── security.md
│   ├── troubleshooting.md
│   ├── compatibility.md
│   └── superpowers/
├── pyproject.toml
├── uv.lock
├── Makefile
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE
```

## Stable Interfaces Across Plans

```python
class XrayClient(Protocol):
    def add_user(self, runtime_id: str, user_id: UUID) -> None: ...
    def remove_user(self, runtime_id: str) -> None: ...
    def list_users(self) -> set[str]: ...
    def wait_ready(self, timeout_seconds: float) -> None: ...

class HysteriaClient(Protocol):
    def kick(self, runtime_id: str) -> None: ...

class XraySupervisorClient(Protocol):
    def restart(self) -> None: ...

class ProfileCoordinator:
    def create(self, name: str) -> ProfileResult: ...
    def disable(self, profile_id: UUID) -> ProfileResult: ...
    def enable(self, profile_id: UUID) -> ProfileResult: ...
    def delete(self, profile_id: UUID) -> None: ...
    def reconcile(self) -> ReconcileResult: ...
```

```text
GET  /health/live
GET  /health/ready
POST /internal/hysteria/auth
GET  /login
POST /login
POST /logout
GET  /
POST /profiles
POST /profiles/{profile_id}/disable
POST /profiles/{profile_id}/enable
POST /profiles/{profile_id}/delete
GET  /profiles/{profile_id}
GET  /s/{subscription_token}
```

The internal auth route returns exactly `{"ok": true, "id": "<runtime_id>"}` or `{"ok": false, "id": ""}` with HTTP 200. Public errors never include exception text, credentials, UUID values, tokens or full links.

## Version Policy

The first compatibility baseline is:

```text
Python        3.12
uv            0.12.7
FastAPI       0.141.1
SQLAlchemy    2.0.52
Alembic       1.19.1
Argon2 CFFI   25.1.0
PyNaCl        1.6.2
Jinja2        3.1.6
HTTPX         0.28.1
Segno         1.6.6
Uvicorn       0.52.4
gRPC Python   1.83.1
gRPC tools    1.83.1
Protobuf      7.36.0
Python forms  0.0.32
pytest        9.1.1
pytest-cov    7.1.0
pytest-asyncio 1.4.0
respx         0.23.1
Ruff          0.16.5
mypy          2.3.1
Bandit        1.9.4
pip-audit     2.10.1
Xray          26.3.27
Hysteria2     2.12.2
Caddy         2.11.4
```

Python packages are resolved into `uv.lock`. Container tags are never used alone in production; `deploy/images.lock` records repository, human-readable version and immutable digest. An update changes one upstream at a time and reruns its integration and external compatibility gates.

## Commit and Review Policy

- A task starts from a clean worktree.
- The named failing test is run before implementation and its failure is recorded in the task notes.
- The smallest implementation is added, followed by the named focused test and the relevant suite.
- `make check` is mandatory before each plan checkpoint.
- Generated files are reproducible and have a checked generation command.
- No commit contains release credentials, server addresses from prior systems or generated profile material.
- The private GitHub remote is created only after the first local gate is green.
- Publication is a final release action, never an automatic side effect of CI.

## Completion Evidence

The plan set is complete only when the repository contains all of the following evidence:

```text
unit and integration test reports
clean-host install results for all four supported distributions
browser login and profile lifecycle recording
certificate issue and renewal exercise
backup, restore, update, reinstall and rollback exercise
external connection and throughput results for both transports
revocation during active transfer
port exposure scan
content, secret, dependency, image and configuration scans
signed release manifest, SBOM and provenance
```

The evidence records versions, timestamps and pass or fail status, but never contain profile credentials, full links, administrator data or destination browsing history.
