# EzOpenPN Installer and Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a safe one-command clean-host installation and a single `ezopenpn` command for diagnosis, password reset, backup, restore, update, reinstall, uninstall and purge.

**Architecture:** A small streamed bootstrap verifies a versioned release bundle, then hands control to a local Bash installer library. Every mutating operation uses explicit paths, checkpoints, an operation lock, a verified backup and health-based rollback.

**Tech Stack:** Bash 5, curl, OpenSSL, systemd, Docker Engine, Compose v2, Bats, Python control CLI and GitHub release attestations.

**Spec:** `docs/superpowers/specs/2026-08-31-ezopenpn-design.md`

## Global Constraints

- Apply every constraint in `docs/superpowers/plans/2026-08-31-ezopenpn-implementation-index.md`.
- Show the clean dedicated VPS recommendation before any install command or mutation.
- Read interactive values from `/dev/tty`; never place passwords in arguments, environment values, shell tracing or logs.
- Abort before package or firewall changes when a preflight requirement fails.
- Never change the SSH port, SSH configuration or firewall default policy.
- Never operate recursively on `/`, a home directory, the workspace root or an unresolved variable.
- Persistent paths are exactly `/etc/ezopenpn`, `/var/lib/ezopenpn`, `/var/backups/ezopenpn` and `/usr/local/bin/ezopenpn`.
- `reinstall` preserves the database, master key, runtime secrets and profile links.
- `uninstall` preserves persistent data; only an explicitly confirmed `purge` removes it.
- Every release download is verified before execution.

---

### Task 1: Safe Shell Framework and Operation Lock

**Files:**
- Create: `installer/lib/common.sh`
- Create: `installer/lib/lock.sh`
- Create: `installer/lib/state.sh`
- Create: `tests/shell/test_common.bats`
- Create: `tests/shell/test_lock.bats`
- Create: `tests/shell/helpers/load.bash`

**Interfaces:**
- Produces: `die CODE MESSAGE`, `info MESSAGE`, `warn MESSAGE`
- Produces: `require_root`, `require_tty`, `require_absolute_safe_path PATH`
- Produces: `acquire_operation_lock NAME`, `release_operation_lock`
- Produces checkpoint file `/var/lib/ezopenpn/operations/current.json`.

- [ ] **Step 1: Write failing path and lock tests**

```bash
@test "safe path rejects root and unresolved text" {
  run require_absolute_safe_path "/"
  [ "$status" -ne 0 ]
  run require_absolute_safe_path '${MISSING_VALUE}'
  [ "$status" -ne 0 ]
}

@test "second mutating command cannot acquire the lock" {
  acquire_operation_lock install
  run bash -c 'source installer/lib/lock.sh; acquire_operation_lock update'
  [ "$status" -eq 73 ]
}
```

- [ ] **Step 2: Run and confirm helper files are missing**

Run: `bats tests/shell/test_common.bats tests/shell/test_lock.bats`

Expected: FAIL on missing sourced files.

- [ ] **Step 3: Implement quiet, deterministic helpers**

Set `umask 077`, `set -Eeuo pipefail`, disable xtrace on entry, use `flock` on `/run/lock/ezopenpn.lock`, and register cleanup traps. Write checkpoints through a sibling temporary file, fsync with Python or `sync -f`, then rename. Diagnostics have stable codes such as `E_PREFLIGHT_PORT`, `E_RELEASE_VERIFY` and `E_HEALTH_TIMEOUT`; they never interpolate command output that could contain a credential.

- [ ] **Step 4: Run Bats and ShellCheck**

Run: `bats tests/shell/test_common.bats tests/shell/test_lock.bats && shellcheck installer/lib/common.sh installer/lib/lock.sh installer/lib/state.sh`

Expected: PASS.

- [ ] **Step 5: Commit the operations framework**

```bash
git add installer/lib tests/shell
git commit -m "feat: add safe host operation framework"
```

### Task 2: Read-Only Clean-Host Preflight

**Files:**
- Create: `installer/lib/preflight.sh`
- Create: `tests/shell/test_preflight.bats`
- Create: `tests/shell/fixtures/os-release/ubuntu-22.04`
- Create: `tests/shell/fixtures/os-release/ubuntu-24.04`
- Create: `tests/shell/fixtures/os-release/debian-12`
- Create: `tests/shell/fixtures/os-release/debian-13`

**Interfaces:**
- Produces: `run_preflight -> JSON report on stdout, exit 0 or stable diagnostic code`
- Produces: `detect_public_ipv4 -> IPv4 text`
- Consumes no persistent write path.

- [ ] **Step 1: Write failing supported-host and conflict tests**

```bash
@test "unsupported architecture fails before mutation" {
  export TEST_UNAME_M="aarch64"
  run run_preflight
  [ "$status" -eq 20 ]
  [[ "$output" == *"E_PREFLIGHT_ARCH"* ]]
  [ ! -e "$TEST_ROOT/etc/ezopenpn" ]
}

@test "occupied tcp port reports owning process" {
  export TEST_SS_OUTPUT='LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=123,fd=7))'
  run run_preflight
  [ "$status" -eq 24 ]
  [[ "$output" == *"443/tcp"* ]]
  [[ "$output" == *"caddy"* ]]
}
```

- [ ] **Step 2: Run and confirm preflight is missing**

Run: `bats tests/shell/test_preflight.bats`

Expected: FAIL on missing `run_preflight`.

- [ ] **Step 3: Implement every spec precondition without mutation**

Parse `/etc/os-release`, require `x86_64`, systemd, root or sudo, 1 GiB MemTotal, 4 GiB free on `/var`, synchronized time from `timedatectl`, working DNS and HTTPS, and direct public IPv4 assignment. Resolve public IP through `https://checkip.amazonaws.com` and `https://api.ipify.org`; require equal valid results and require the address in `ip -4 addr`. Check TCP and UDP listeners for 80, 443 and 9443, list foreign Docker containers, inspect active UFW or firewalld, and reject unsupported raw firewall policy. Check access to GitHub, Docker registry, Let’s Encrypt directory and every configured Reality target candidate.

When EzOpenPN checkpoints already exist, return maintenance mode rather than treating its own listeners and containers as conflicts.

- [ ] **Step 4: Run all fixture variants and ShellCheck**

Run: `bats tests/shell/test_preflight.bats && shellcheck installer/lib/preflight.sh`

Expected: all four supported fixtures pass and conflict cases fail before any fixture mutation.

- [ ] **Step 5: Commit preflight checks**

```bash
git add installer/lib/preflight.sh tests/shell/test_preflight.bats tests/shell/fixtures/os-release
git commit -m "feat: validate clean supported hosts"
```

### Task 3: Verified Release Bootstrap

**Files:**
- Create: `installer/install.sh`
- Create: `installer/lib/release.sh`
- Create: `tests/shell/test_release_verify.bats`
- Create: `tests/shell/fixtures/fulcio-root.pem`

**Interfaces:**
- Public entry: `curl -fsSL https://github.com/A1exZabr/EzOpenPN/releases/latest/download/install.sh | sudo bash`
- Produces: verified bundle directory passed to `installer-main.sh`.
- Accepts for tests only: `EZOPENPN_RELEASE_BASE_URL` and `EZOPENPN_EXPECTED_VERSION`.

- [ ] **Step 1: Write failing tamper and identity tests**

```bash
@test "modified bundle is rejected before execution" {
  prepare_signed_fixture
  printf 'tamper' >> "$FIXTURE_SERVER/ezopenpn-bundle.tar.gz"
  run bootstrap_release
  [ "$status" -eq 31 ]
  [[ "$output" == *"E_RELEASE_VERIFY"* ]]
  [ ! -e "$TEST_ROOT/executed" ]
}

@test "wrong workflow identity is rejected" {
  prepare_fixture_with_wrong_identity
  run bootstrap_release
  [ "$status" -eq 31 ]
}
```

- [ ] **Step 2: Run and confirm bootstrap is missing**

Run: `bats tests/shell/test_release_verify.bats`

Expected: FAIL because `install.sh` and release verification do not exist.

- [ ] **Step 3: Implement release identity verification**

The streamed script prints the clean-host recommendation, creates `mktemp -d`, registers cleanup, resolves the immutable latest tag through GitHub redirects, downloads the bundle, checksum file, Sigstore signature and certificate, then verifies all of the following:

```text
bundle checksum matches SHA256SUMS
certificate chains to the pinned Fulcio root
OIDC issuer is https://token.actions.githubusercontent.com
certificate identity is the release workflow in A1exZabr/EzOpenPN at the exact tag
Rekor inclusion proof is valid
bundle manifest version equals the resolved tag
```

Use a pinned cosign binary whose version and amd64 checksum are generated into the release copy of `install.sh`. Run the verified bundle installer with `sudo --preserve-env` only for the two documented test overrides; production preserves no environment. The trust boundary of the initial streamed script is GitHub HTTPS and is stated in security documentation.

- [ ] **Step 4: Run positive, tampered and unavailable-network tests**

Run: `bats tests/shell/test_release_verify.bats && shellcheck installer/install.sh installer/lib/release.sh`

Expected: valid fixture executes once; tampered, wrong-identity and incomplete downloads never execute.

- [ ] **Step 5: Commit verified bootstrap**

```bash
git add installer/install.sh installer/lib/release.sh tests/shell/test_release_verify.bats tests/shell/fixtures/fulcio-root.pem
git commit -m "feat: verify release bundle before install"
```

### Task 4: Docker Engine and Firewall Preparation

**Files:**
- Create: `installer/lib/docker.sh`
- Create: `installer/lib/firewall.sh`
- Create: `tests/shell/test_docker_install.bats`
- Create: `tests/shell/test_firewall.bats`

**Interfaces:**
- Produces: `ensure_docker_engine`
- Produces: `apply_firewall_rules`, `rollback_firewall_rules`
- Firewall rule set: 80/tcp, 443/tcp, 443/udp and 9443/tcp only.

- [ ] **Step 1: Write failing repository and rollback tests**

```bash
@test "docker install uses official repository for detected distribution" {
  export TEST_OS_ID="debian"
  export TEST_OS_CODENAME="bookworm"
  run ensure_docker_engine
  [ "$status" -eq 0 ]
  grep -q "download.docker.com/linux/debian" "$TEST_APT_SOURCE"
}

@test "firewall rollback removes only rules created by this operation" {
  apply_firewall_rules
  rollback_firewall_rules
  assert_foreign_rule_unchanged
  assert_no_managed_rules
}
```

- [ ] **Step 2: Run and confirm helpers are missing**

Run: `bats tests/shell/test_docker_install.bats tests/shell/test_firewall.bats`

Expected: FAIL on missing functions.

- [ ] **Step 3: Implement official installation and scoped firewall changes**

If a compatible Docker Engine and Compose v2 already exist, keep them. Otherwise add the official apt keyring and repository for the detected supported distribution, install `docker-ce`, CLI, containerd, buildx and Compose plugin, enable Docker and verify `docker info`. Record every installed package and created apt file in the checkpoint.

For active UFW, add comment-tagged allow rules. For active firewalld, add permanent and runtime ports in a dedicated service definition. Back up status before changes and rollback only operation-owned rules. Never enable an inactive firewall, change defaults or alter SSH allowances. Print the exact provider firewall list because provider APIs are out of scope.

- [ ] **Step 4: Run mocked install, firewall and rollback tests**

Run: `bats tests/shell/test_docker_install.bats tests/shell/test_firewall.bats && shellcheck installer/lib/docker.sh installer/lib/firewall.sh`

Expected: PASS across installed, absent and interrupted cases.

- [ ] **Step 5: Commit host preparation**

```bash
git add installer/lib/docker.sh installer/lib/firewall.sh tests/shell
git commit -m "feat: prepare Docker and required ports"
```

### Task 5: Secret Generation, Runtime Target Selection and Layout

**Files:**
- Create: `installer/lib/configure.sh`
- Create: `installer/lib/credentials.sh`
- Create: `installer/targets.txt`
- Create: `tests/shell/test_configure.bats`
- Create: `tests/shell/test_credentials.bats`

**Interfaces:**
- Produces exact persistent directory layout from the spec.
- Produces root-readable secret files and rendered non-secret configuration.
- Produces selected Reality target, X25519 pair, short ID and XHTTP path.

- [ ] **Step 1: Write failing idempotency and credential-channel tests**

```bash
@test "rerun preserves existing master key" {
  configure_layout
  first_hash="$(sha256sum "$TEST_ROOT/var/lib/ezopenpn/secrets/master.key")"
  configure_layout
  second_hash="$(sha256sum "$TEST_ROOT/var/lib/ezopenpn/secrets/master.key")"
  [ "$first_hash" = "$second_hash" ]
}

@test "password never appears in child arguments or environment" {
  export TEST_TTY_INPUT=$'owner\nstrong console passphrase\nstrong console passphrase\n'
  collect_admin_credentials
  assert_process_snapshot_excludes "strong console passphrase"
  assert_environment_snapshot_excludes "strong console passphrase"
}
```

- [ ] **Step 2: Run and confirm configure helpers are missing**

Run: `bats tests/shell/test_configure.bats tests/shell/test_credentials.bats`

Expected: FAIL on missing functions.

- [ ] **Step 3: Implement root-owned layout and runtime generation**

Create only the four explicit persistent roots, with service-owned subdirectories and numeric ownership from the Compose plan. Generate separate 32-byte values for the master key, Hysteria2 stats API and Salamander, use atomic exclusive creation and preserve existing files. Read login and password twice from `/dev/tty`, disable terminal echo, require 12 characters and reject exact equality with login; keep the password only in a shell variable until it is sent over a dedicated pipe to the control CLI, then unset it.

Use the pinned Xray image to run `xray tls ping` against each line in `installer/targets.txt`. Accept only TLS 1.3 candidates with successful SNI handshake, record one target and server name, then run `xray x25519`. Generate a 16-hex-character short ID, a random URL-safe path and randomized bounded fallback limits. Validate rendered configuration before activation. The target list is neutral and contains no historical host from the predecessor system.

- [ ] **Step 4: Run idempotency, permissions and redaction tests**

Run: `bats tests/shell/test_configure.bats tests/shell/test_credentials.bats && shellcheck installer/lib/configure.sh installer/lib/credentials.sh`

Expected: PASS; a second run changes no existing credential checksum.

- [ ] **Step 5: Commit installation configuration**

```bash
git add installer/lib/configure.sh installer/lib/credentials.sh installer/targets.txt tests/shell
git commit -m "feat: generate isolated server configuration"
```

### Task 6: One-Command Installation and Systemd Ownership

**Files:**
- Create: `installer/installer-main.sh`
- Create: `installer/lib/install.sh`
- Create: `installer/systemd/ezopenpn.service`
- Create: `tests/shell/test_install_flow.bats`

**Interfaces:**
- Produces an installed stack and `/usr/local/bin/ezopenpn`.
- Produces final output: panel URL, login, reset command, status command and provider firewall ports.
- Produces advanced downloaded-script options: `--advanced-lab-certificate PATH --advanced-lab-key PATH`; the streamed command never enables them.

- [ ] **Step 1: Write a failing ordered installation test**

```bash
@test "install reaches healthy only after certificate and admin creation" {
  run installer_main
  [ "$status" -eq 0 ]
  assert_event_order \
    preflight bundle_verified docker_ready firewall_ready layout_ready \
    gateway_started certificate_ready control_migrated admin_created \
    runtimes_ready external_checks_passed install_complete
}

@test "failed health check rolls back firewall and services" {
  export TEST_FAIL_HEALTH="xray"
  run installer_main
  [ "$status" -ne 0 ]
  assert_no_running_managed_services
  assert_no_managed_firewall_rules
}

@test "laboratory certificate requires both explicit files" {
  run installer_main --advanced-lab-certificate "$TEST_CERT"
  [ "$status" -eq 2 ]
  assert_no_host_mutation
}
```

- [ ] **Step 2: Run and confirm main installer is missing**

Run: `bats tests/shell/test_install_flow.bats`

Expected: FAIL because `installer_main` does not exist.

- [ ] **Step 3: Implement checkpointed install order**

Run preflight, verify bundle, prepare Docker and firewall, install release files under `/etc/ezopenpn/releases/VERSION`, switch a `current` symlink atomically, generate config, start gateway first, wait for a trusted certificate, start control, migrate, send the password on stdin to `init-admin`, start Xray and Hysteria2, reconcile, and run local plus public health checks. Install a oneshot systemd unit that calls Compose from the fixed current path and remains active after exit. A failure invokes the checkpoint rollback in reverse order.

The advanced laboratory pair is accepted only when both absolute regular files are supplied to a downloaded local installer, their key matches, the certificate IP SAN matches the server and the user types `LAB` on `/dev/tty`. It never generates an untrusted certificate, never changes the production default, and prints that browsers and clients may reject the result.

Do not declare success until the panel certificate verifies against the system trust store and both runtime management healthchecks pass. UDP public reachability remains a provider checklist item until the external client test.

- [ ] **Step 4: Run success, interruption and resume tests**

Run: `bats tests/shell/test_install_flow.bats && shellcheck installer/installer-main.sh installer/lib/install.sh`

Expected: PASS for a clean install, rollback failure and resume from each recorded checkpoint.

- [ ] **Step 5: Commit one-command installation**

```bash
git add installer/installer-main.sh installer/lib/install.sh installer/systemd tests/shell/test_install_flow.bats
git commit -m "feat: install complete stack in one command"
```

### Task 7: Status, Doctor, Logs and Password Reset Commands

**Files:**
- Create: `installer/bin/ezopenpn`
- Create: `installer/lib/diagnostics.sh`
- Create: `installer/lib/admin.sh`
- Create: `tests/shell/test_cli_dispatch.bats`
- Create: `tests/shell/test_diagnostics.bats`
- Create: `tests/shell/test_admin_reset.bats`

**Interfaces:**
- Produces: `ezopenpn status`, `doctor`, `logs [service]`, `admin reset-password`.
- Exit 0 means healthy, 1 degraded, 2 invalid invocation and 3 unavailable installation.

- [ ] **Step 1: Write failing dispatch and password tests**

```bash
@test "unknown service log request is rejected" {
  run ezopenpn logs host
  [ "$status" -eq 2 ]
  [[ "$output" == *"control, xray, hysteria, gateway, cert-sync"* ]]
}

@test "password reset passes secret on stdin and revokes sessions" {
  export TEST_TTY_INPUT=$'new strong passphrase\nnew strong passphrase\n'
  run ezopenpn admin reset-password
  [ "$status" -eq 0 ]
  assert_control_stdin_equals $'new strong passphrase\n'
  assert_sessions_revoked
  assert_profiles_unchanged
}
```

- [ ] **Step 2: Run and confirm CLI is missing**

Run: `bats tests/shell/test_cli_dispatch.bats tests/shell/test_diagnostics.bats tests/shell/test_admin_reset.bats`

Expected: FAIL because `installer/bin/ezopenpn` does not exist.

- [ ] **Step 3: Implement allowlisted dispatch and redacted diagnostics**

Use a case statement with no dynamic command execution. `status` reports installed version, container health, certificate expiry, runtime readiness and active profile count. `doctor` repeats preflight network checks, validates file permissions, Compose policy, database integrity, certificate match, Xray reconciliation and public panel HTTPS. `logs` accepts only the five service names and passes `--since` and `--tail` numeric options after validation. Reset reads twice from the controlling terminal and invokes the control CLI with `--password-stdin`.

- [ ] **Step 4: Run CLI, diagnostics and redaction tests**

Run: `bats tests/shell/test_cli_dispatch.bats tests/shell/test_diagnostics.bats tests/shell/test_admin_reset.bats && shellcheck installer/bin/ezopenpn installer/lib/diagnostics.sh installer/lib/admin.sh`

Expected: PASS; fixture secrets never appear in output.

- [ ] **Step 5: Commit daily operations CLI**

```bash
git add installer/bin/ezopenpn installer/lib/diagnostics.sh installer/lib/admin.sh tests/shell
git commit -m "feat: add diagnosis and password recovery commands"
```

### Task 8: Verified Backup and Restore

**Files:**
- Modify: `control/src/ezopenpn/cli.py`
- Create: `control/src/ezopenpn/backup.py`
- Create: `control/tests/integration/test_backup.py`
- Create: `installer/lib/backup.sh`
- Create: `tests/shell/test_backup_restore.bats`

**Interfaces:**
- Produces control commands: `backup-database --output PATH`, `verify-database --path PATH`.
- Produces host commands: `ezopenpn backup`, `ezopenpn restore ARCHIVE`.
- Archive contains manifest, online SQLite snapshot, configuration, secrets and Caddy state.

- [ ] **Step 1: Write failing online snapshot and restore tests**

```python
def test_online_backup_is_consistent_during_write(backup_fixture: BackupFixture) -> None:
    backup_fixture.start_concurrent_audit_writes()
    result = create_online_backup(backup_fixture.engine, backup_fixture.output)
    assert verify_database(result.database_path).ok is True
    assert result.quick_check == "ok"
```

```bash
@test "restore rejects archive with changed member" {
  archive="$(make_valid_backup)"
  alter_archive_member "$archive" manifest.json
  run ezopenpn restore "$archive"
  [ "$status" -ne 0 ]
  assert_running_state_unchanged
}
```

- [ ] **Step 2: Run and confirm backup functions are missing**

Run: `uv run pytest control/tests/integration/test_backup.py -q && bats tests/shell/test_backup_restore.bats`

Expected: FAIL on missing backup implementations.

- [ ] **Step 3: Implement SQLite Online Backup and staged restore**

Use Python `sqlite3.Connection.backup`, run `PRAGMA quick_check`, record schema version and SHA-256. The host creates a root-only staging directory under `/var/backups/ezopenpn`, copies only the explicit approved paths, writes a sorted per-file checksum manifest, creates a gzip tar without absolute names and chmods archive and checksum `0600`.

Restore validates archive path, type, ownership, no symlinks, no absolute members, no `..`, all checksums and supported schema before stopping services. It creates a fresh backup of current state, extracts to sibling staging directories, validates, then swaps explicit directories and starts health checks. Any failure restores the pre-restore backup.

- [ ] **Step 4: Run concurrent backup, malicious archive and round-trip tests**

Run: `uv run pytest control/tests/integration/test_backup.py -q && bats tests/shell/test_backup_restore.bats`

Expected: PASS with profile IDs and encrypted values unchanged after round trip.

- [ ] **Step 5: Commit backup and restore**

```bash
git add control/src/ezopenpn/backup.py control/src/ezopenpn/cli.py control/tests/integration/test_backup.py installer/lib/backup.sh tests/shell/test_backup_restore.bats
git commit -m "feat: back up and restore persistent state"
```

### Task 9: Update, Reinstall and Automatic Rollback

**Files:**
- Create: `installer/lib/upgrade.sh`
- Create: `tests/shell/test_upgrade.bats`
- Create: `tests/shell/test_reinstall.bats`

**Interfaces:**
- Produces: `ezopenpn update`, `ezopenpn reinstall`.
- `update` selects latest stable version; `reinstall` selects the currently installed version.

- [ ] **Step 1: Write failing preservation and rollback tests**

```bash
@test "reinstall preserves profile and master key hashes" {
  before_profiles="$(profile_material_hashes)"
  before_master="$(master_key_hash)"
  run ezopenpn reinstall
  [ "$status" -eq 0 ]
  [ "$(profile_material_hashes)" = "$before_profiles" ]
  [ "$(master_key_hash)" = "$before_master" ]
}

@test "failed new image restores old release and database" {
  export TEST_NEW_CONTROL_HEALTH="fail"
  old_version="$(installed_version)"
  old_database="$(database_hash)"
  run ezopenpn update
  [ "$status" -ne 0 ]
  [ "$(installed_version)" = "$old_version" ]
  [ "$(database_hash)" = "$old_database" ]
  assert_stack_healthy
}
```

- [ ] **Step 2: Run and confirm upgrade helper is missing**

Run: `bats tests/shell/test_upgrade.bats tests/shell/test_reinstall.bats`

Expected: FAIL on missing commands.

- [ ] **Step 3: Implement the shared safe upgrade transaction**

Acquire the operation lock, run preflight in maintenance mode, download and verify the selected release, reject unsupported downgrade, create and verify a backup, pull exact digests, render and validate config, stop only managed services, switch the current release symlink, migrate, start and run health checks. On failure, stop the attempted version, restore the verified backup, restore the previous symlink and image lock, then start and verify the old version. Keep the failed diagnostic bundle without secrets.

Migration files in a stable release must include a tested downgrade to the previous stable schema. The release workflow rejects a migration lacking that test.

- [ ] **Step 4: Run upgrade, reinstall, interruption and rollback matrix**

Run: `bats tests/shell/test_upgrade.bats tests/shell/test_reinstall.bats && shellcheck installer/lib/upgrade.sh`

Expected: PASS; only a fully healthy new release becomes current.

- [ ] **Step 5: Commit lifecycle upgrades**

```bash
git add installer/lib/upgrade.sh tests/shell/test_upgrade.bats tests/shell/test_reinstall.bats
git commit -m "feat: update and reinstall with rollback"
```

### Task 10: Uninstall, Explicit Purge and VM Idempotency

**Files:**
- Create: `installer/lib/remove.sh`
- Create: `tests/shell/test_remove.bats`
- Create: `tests/shell/test_vm_idempotency.bats`
- Create: `tests/vm/run-install-twice.sh`
- Create: `tests/vm/assert-preserved.sh`

**Interfaces:**
- Produces: `ezopenpn uninstall`, `ezopenpn purge`.
- `purge` confirmation requires exact product name and a second `DELETE` token from `/dev/tty`.

- [ ] **Step 1: Write failing preservation and confirmation tests**

```bash
@test "uninstall leaves all persistent directories" {
  run ezopenpn uninstall
  [ "$status" -eq 0 ]
  [ -d "$TEST_ROOT/etc/ezopenpn" ]
  [ -d "$TEST_ROOT/var/lib/ezopenpn" ]
  [ -d "$TEST_ROOT/var/backups/ezopenpn" ]
}

@test "purge with wrong confirmation removes nothing" {
  export TEST_TTY_INPUT=$'EzOpenPn\nDELETE\n'
  run ezopenpn purge
  [ "$status" -ne 0 ]
  assert_persistent_paths_exist
}
```

- [ ] **Step 2: Run and confirm remove helper is missing**

Run: `bats tests/shell/test_remove.bats`

Expected: FAIL on missing commands.

- [ ] **Step 3: Implement recoverable uninstall and explicit deletion**

Uninstall stops and removes only the managed Compose project, disables the systemd unit, removes managed firewall rules and leaves config, state, secrets, backups and release files. Print the exact reinstall command. Purge first creates and verifies the path built by `final_archive="/var/backups/ezopenpn-final-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"`, which is outside the directory being removed, then reads both confirmations, resolves and compares each deletion target to the fixed allowlist, removes the three persistent roots and CLI, and reports the retained final archive path. Never use a recursive command with a variable that has not passed `require_absolute_safe_path` and exact allowlist equality.

The VM script accepts an SSH target through `EZOPENPN_TEST_HOST`, installs twice and asserts identical master key, profile link, database profile rows and public URL after the second run. Its command sequencing is tested here with a mock SSH executable; Plan 05 supplies the disposable real VM target.

- [ ] **Step 4: Run removal tests and a disposable VM idempotency pass**

Run: `bats tests/shell/test_remove.bats tests/shell/test_vm_idempotency.bats && shellcheck installer/lib/remove.sh tests/vm/run-install-twice.sh tests/vm/assert-preserved.sh`

Expected: PASS; uninstall is recoverable, wrong purge confirmation is a no-op, and the mocked two-install sequence verifies identity preservation.

- [ ] **Step 5: Commit removal and idempotency behavior**

```bash
git add installer/lib/remove.sh tests/shell/test_remove.bats tests/shell/test_vm_idempotency.bats tests/vm
git commit -m "feat: add recoverable removal and idempotency"
```

## Plan 04 Checkpoint

Run:

```bash
bats tests/shell
shellcheck installer/install.sh installer/installer-main.sh installer/bin/ezopenpn installer/lib/*.sh
make check
git status --short
```

Expected outcome: one verified command installs on a clean supported host, every recovery command has a tested failure path, and no operation loses profile material without an exact destructive confirmation.
