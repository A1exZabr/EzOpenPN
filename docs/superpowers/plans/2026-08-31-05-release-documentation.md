# EzOpenPN Release and Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the tested stack into an understandable beginner release with complete documentation, reproducible artifacts, security evidence and real external transport validation.

**Architecture:** CI provides deterministic code, image and VM gates; GitHub Actions builds signed release artifacts and attestations; a separate release checklist requires browser, clean-host, client and external network evidence before the private repository is made public.

**Tech Stack:** GitHub Actions, GHCR, Sigstore Cosign, Syft, Trivy, gitleaks, CodeQL, QEMU, Playwright, pytest and Markdown.

**Spec:** `docs/superpowers/specs/2026-08-31-ezopenpn-design.md`

## Global Constraints

- Apply every constraint in `docs/superpowers/plans/2026-08-31-ezopenpn-implementation-index.md`.
- Beginner documentation starts with the clean dedicated VPS recommendation.
- Public copy avoids prohibited historical labels and avoids U+2013 and U+2014.
- Documentation never embeds a real administrator value, profile credential, full link, private key or production server address.
- A release is not ready from CI alone; external throughput and active-revocation evidence are mandatory.
- GitHub Actions and third-party tools are pinned to immutable commits or checksums.
- The repository stays private until the final history and artifact audit passes.
- Publication and release are separate steps; neither is triggered by an ordinary push.

---

### Task 1: Beginner README and Operational Documentation

**Files:**
- Create: `README.md`
- Create: `docs/getting-started.md`
- Create: `docs/profiles.md`
- Create: `docs/recovery.md`
- Create: `docs/troubleshooting.md`
- Create: `docs/security.md`
- Create: `docs/compatibility.md`
- Create: `docs/architecture.md`
- Modify: `control/src/ezopenpn/web/templates/dashboard.html`
- Modify: `control/src/ezopenpn/web/templates/profile.html`
- Create: `tests/docs/test_docs.py`

**Interfaces:**
- Produces one canonical install command and one canonical password-reset command.
- Produces matching four-step profile instructions in documentation and panel.

- [ ] **Step 1: Write failing documentation contract tests**

```python
def test_readme_starts_with_clean_server_recommendation() -> None:
    paragraphs = meaningful_paragraphs(Path("README.md").read_text(encoding="utf-8"))
    assert "отдельный чистый VPS" in paragraphs[0]


def test_install_and_reset_commands_have_one_canonical_value() -> None:
    documents = load_public_documents()
    assert unique_matches(documents, INSTALL_COMMAND_PATTERN) == {
        "curl -fsSL https://github.com/A1exZabr/EzOpenPN/releases/latest/download/install.sh | sudo bash"
    }
    assert unique_matches(documents, RESET_COMMAND_PATTERN) == {"sudo ezopenpn admin reset-password"}
```

- [ ] **Step 2: Run and confirm public docs are missing**

Run: `uv run pytest tests/docs/test_docs.py -q`

Expected: FAIL because README and documentation files do not exist.

- [ ] **Step 3: Write task-oriented Russian documentation**

README order is: clean VPS recommendation, supported systems, four required ports, one command, expected final output, create first profile, password recovery, update and support links. Getting started explains how to rent a server without recommending a specific provider, connect over SSH, open cloud firewall rules and recognize success. Profiles explains one profile per device, combined link, QR, separate transport fallback and how to disable. Recovery documents status, doctor, logs, reset, backup, restore, reinstall and rollback. Troubleshooting maps every stable diagnostic code to safe checks and documents the downloaded-installer-only laboratory certificate options in a clearly separated advanced section. Security describes trust boundaries, local data, no telemetry and release verification. Compatibility contains only actually tested client and version rows.

Panel instructions use exactly four numbered steps: create profile, install a compatible client, scan or paste, switch transport if the first route is unstable. Keep protocol details in a closed disclosure element.

- [ ] **Step 4: Run copy, link and content checks**

Run: `uv run pytest tests/docs/test_docs.py -q && uv run python tools/content_guard.py README.md docs control/src/ezopenpn/web && lychee --offline README.md docs/*.md`

Expected: PASS with no broken relative links or copy drift.

- [ ] **Step 5: Commit beginner documentation**

```bash
git add README.md docs control/src/ezopenpn/web/templates tests/docs
git commit -m "docs: add beginner setup and recovery guide"
```

### Task 2: License and Third-Party Notices

**Files:**
- Create: `LICENSE`
- Create: `THIRD_PARTY_NOTICES.md`
- Create: `CONTRIBUTING.md`
- Create: `SECURITY.md`
- Create: `tests/release/test_licenses.py`

**Interfaces:**
- Produces MIT licensing for original EzOpenPN files.
- Preserves upstream file-level licenses and notices for Xray schema, binaries, Hysteria2, Caddy, Python and Go dependencies.

- [ ] **Step 1: Write failing license coverage tests**

```python
def test_original_project_license_is_neutral_mit() -> None:
    license_text = Path("LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in license_text
    assert "EzOpenPN contributors" in license_text


def test_every_distributed_upstream_has_notice(image_lock: ImageLock) -> None:
    notices = Path("THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    for image in image_lock.images.values():
        assert image.repository in notices
```

- [ ] **Step 2: Run and confirm license files are missing**

Run: `uv run pytest tests/release/test_licenses.py -q`

Expected: FAIL because licensing files do not exist.

- [ ] **Step 3: Add accurate licenses and reporting process**

Use the standard MIT text with `EzOpenPN contributors`. Mark the reduced Xray schema files and generated derivatives under MPL-2.0 at file level, and include the MPL text beside them. Record upstream repository, pinned version, license and distribution form for every image and copied asset. CONTRIBUTING requires content guard, focused tests, no generated secrets and evidence for transport changes. SECURITY provides a private GitHub reporting path without personal contact details.

- [ ] **Step 4: Run license and content scans**

Run: `uv run pytest tests/release/test_licenses.py -q && reuse lint && uv run python tools/content_guard.py .`

Expected: PASS with no unlicensed copied file.

- [ ] **Step 5: Commit licensing and contribution policy**

```bash
git add LICENSE THIRD_PARTY_NOTICES.md CONTRIBUTING.md SECURITY.md proto/xray tests/release/test_licenses.py
git commit -m "docs: add licensing and security policies"
```

### Task 3: Complete CI and Security Gates

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/dependabot.yml`
- Create: `.github/workflows/codeql.yml`
- Create: `.gitleaks.toml`
- Create: `tests/security/test_secret_redaction.py`
- Create: `tests/security/test_compose_security.py`
- Create: `tools/toolchain.toml`
- Create: `tools/toolchain.lock`
- Create: `tools/lock_toolchain.sh`
- Create: `tools/run_security_checks.sh`

**Interfaces:**
- Produces required jobs: content, Python, Go, shell, Compose, CodeQL, dependency audit, secret scan and image scan.

- [ ] **Step 1: Write failing local security runner tests**

```python
def test_security_runner_invokes_every_required_gate(script_text: str) -> None:
    for command in ("bandit", "pip-audit", "gitleaks", "trivy", "govulncheck"):
        assert command in script_text


def test_fixture_secrets_are_redacted(caplog: LogCaptureFixture) -> None:
    emit_all_safe_errors("fixture-profile-secret", "fixture-session-token")
    assert "fixture-profile-secret" not in caplog.text
    assert "fixture-session-token" not in caplog.text
```

- [ ] **Step 2: Run and record absent gates**

Run: `uv run pytest tests/security -q`

Expected: FAIL because the security runner and fixtures are absent.

- [ ] **Step 3: Implement pinned CI with least privilege**

Set workflow permissions to read-only by default and grant only job-specific package or security-event scopes. Pin actions to full commit SHA. Lock Bats, ShellCheck, actionlint, lychee, REUSE, gitleaks, Trivy, Syft, Cosign and govulncheck by version, amd64 checksum and official source in `toolchain.lock`; `lock_toolchain.sh --check` verifies drift. Run content guard before generated or dependency work, then Ruff, mypy, pytest coverage, Go race tests, Bats, ShellCheck, Compose policy, gitleaks history scan, Bandit, pip-audit, govulncheck and Trivy. Upload only sanitized test reports. Dependabot opens grouped weekly updates but no update merges automatically. Configure these successful jobs as required checks on private `main` after the first remote run.

- [ ] **Step 4: Run the same gate locally**

Run: `bash tools/lock_toolchain.sh --check && bash tools/run_security_checks.sh && make check`

Expected: PASS with zero critical or high findings and no secret diagnostic.

- [ ] **Step 5: Commit CI security**

```bash
git add .github .gitleaks.toml tests/security tools/toolchain.toml tools/toolchain.lock tools/lock_toolchain.sh tools/run_security_checks.sh
git commit -m "ci: enforce code and supply security gates"
```

### Task 4: Signed Container Build, SBOM and Digest Manifest

**Files:**
- Create: `.github/workflows/images.yml`
- Create: `tools/verify_image_attestations.sh`
- Create: `tests/release/test_image_manifest.py`
- Create: `tests/release/fixtures/images.release.json`

**Interfaces:**
- Produces GHCR images: `ezopenpn-control`, `ezopenpn-xray`, `ezopenpn-cert-sync`.
- Produces per-image digest, SPDX SBOM and GitHub provenance attestation.

- [ ] **Step 1: Write failing manifest tests**

```python
def test_release_image_manifest_has_attested_digest(release_manifest: ReleaseManifest) -> None:
    for image in release_manifest.images:
        assert image.reference.startswith("ghcr.io/a1exzabr/ezopenpn-")
        assert image.digest.startswith("sha256:")
        assert image.sbom_sha256
        assert image.provenance_subject == f"{image.reference}@{image.digest}"
```

- [ ] **Step 2: Run and confirm image workflow is absent**

Run: `uv run pytest tests/release/test_image_manifest.py -q`

Expected: FAIL because no release manifest fixture can be built.

- [ ] **Step 3: Implement build-once and keyless signing**

Build only linux/amd64 from the exact source commit, push by content digest, generate SPDX JSON with Syft, attach GitHub artifact attestations, sign with Cosign keyless OIDC and write `images.release.json`. Verify the workflow identity and repository in a separate job before exposing outputs to the bundle job. Do not push `latest` until release publication succeeds.

- [ ] **Step 4: Run workflow lint and local manifest validation**

Run: `actionlint .github/workflows/images.yml && uv run pytest tests/release/test_image_manifest.py -q && bash tools/verify_image_attestations.sh --fixture tests/release/fixtures/images.release.json`

Expected: PASS.

- [ ] **Step 5: Commit signed image pipeline**

```bash
git add .github/workflows/images.yml tools/verify_image_attestations.sh tests/release
git commit -m "ci: build attested immutable images"
```

### Task 5: Reproducible Release Bundle and Manual Release Workflow

**Files:**
- Create: `tools/build_release.sh`
- Create: `tools/verify_release.sh`
- Create: `.github/workflows/release.yml`
- Create: `tests/release/test_bundle.py`
- Create: `tests/release/test_reproducible_bundle.py`

**Interfaces:**
- Produces assets: `install.sh`, `ezopenpn-bundle.tar.gz`, `SHA256SUMS`, signature, certificate, SBOM and provenance.
- Release workflow accepts only a tag matching `vMAJOR.MINOR.PATCH` and a completed evidence artifact.

- [ ] **Step 1: Write failing bundle content and reproducibility tests**

```python
def test_bundle_contains_only_allowlisted_roots(bundle_members: set[str]) -> None:
    assert bundle_members <= {"deploy", "installer", "manifest.json", "LICENSE", "THIRD_PARTY_NOTICES.md"}
    assert "manifest.json" in bundle_members


def test_two_builds_are_byte_identical(tmp_path: Path) -> None:
    first = build_release(tmp_path / "one", source_date_epoch=1_800_000_000)
    second = build_release(tmp_path / "two", source_date_epoch=1_800_000_000)
    assert sha256(first.bundle) == sha256(second.bundle)
```

- [ ] **Step 2: Run and confirm release builder is missing**

Run: `uv run pytest tests/release/test_bundle.py tests/release/test_reproducible_bundle.py -q`

Expected: FAIL on missing build script.

- [ ] **Step 3: Implement deterministic assets and protected dispatch**

Use sorted tar members, numeric owner 0, fixed mode map, gzip with no filename and `SOURCE_DATE_EPOCH` from the tag commit. Manifest includes application version, source commit, schema bounds, exact image digests and per-file checksums. Generate a release-specific `install.sh` containing the pinned Cosign version and checksum. Sign checksum and bundle with GitHub OIDC, attach SBOM and provenance, then have an independent job download and verify every asset.

The workflow uses `workflow_dispatch` with a tag input, verifies the tag is signed and points at the tested commit, checks the evidence artifact, creates a draft release, runs remote verification, and only then marks the release latest.

- [ ] **Step 4: Run local reproducibility and workflow tests**

Run: `uv run pytest tests/release/test_bundle.py tests/release/test_reproducible_bundle.py -q && bash tools/build_release.sh --version v0.1.0 --output dist/one && bash tools/verify_release.sh dist/one && actionlint .github/workflows/release.yml`

Expected: PASS and repeated bundles have the same SHA-256.

- [ ] **Step 5: Commit release construction**

```bash
git add tools/build_release.sh tools/verify_release.sh .github/workflows/release.yml tests/release
git commit -m "ci: build verified release assets"
```

### Task 6: Four-System Disposable VM Matrix

**Files:**
- Create: `tests/vm/matrix.toml`
- Create: `tools/lock_vm_images.sh`
- Create: `tests/vm/runner.py`
- Create: `tests/vm/cloud-init.yaml`
- Create: `tests/vm/test_clean_install.py`
- Create: `.github/workflows/vm-matrix.yml`

**Interfaces:**
- Produces matrix names: `ubuntu-22.04`, `ubuntu-24.04`, `debian-12`, `debian-13`.
- Produces sanitized per-VM result JSON with install, rerun, reset, backup, restore, reinstall and uninstall status.

- [ ] **Step 1: Write failing matrix completeness tests**

```python
def test_vm_matrix_is_complete(matrix: VmMatrix) -> None:
    assert set(matrix.images) == {"ubuntu-22.04", "ubuntu-24.04", "debian-12", "debian-13"}
    for image in matrix.images.values():
        assert image.url.startswith("https://")
        assert len(image.sha256) == 64


def test_vm_result_requires_recovery_operations(result: VmResult) -> None:
    assert result.steps == {
        "install": "pass", "rerun": "pass", "reset": "pass",
        "backup_restore": "pass", "reinstall": "pass", "uninstall": "pass",
    }
```

- [ ] **Step 2: Run and confirm matrix tools are missing**

Run: `uv run pytest tests/vm/test_clean_install.py -q`

Expected: FAIL because the VM matrix does not exist.

- [ ] **Step 3: Implement locked cloud images and SSH harness**

Resolve official cloud-image checksum manifests into `matrix.toml`. Start each image with QEMU/KVM, a temporary qcow overlay and cloud-init, expose only a random host SSH port, copy the locally built release bundle, and run installation with a test TTY. Record preflight, install, second install, profile creation, password reset, backup/restore, reinstall and uninstall. Destroy overlay, seed image and SSH keys in a trap. CI runs one system per matrix job and uploads sanitized JSON.

These NAT VMs validate host behavior but not public ACME or external transport performance; those are separate release gates.

- [ ] **Step 4: Run one local VM and validate workflow**

Run: `bash tools/lock_vm_images.sh --check && uv run pytest tests/vm/test_clean_install.py -q && uv run python tests/vm/runner.py --system ubuntu-24.04 --bundle dist/one/ezopenpn-bundle.tar.gz && actionlint .github/workflows/vm-matrix.yml`

Expected: PASS and the VM is removed afterward.

- [ ] **Step 5: Commit the VM matrix**

```bash
git add tests/vm tools/lock_vm_images.sh .github/workflows/vm-matrix.yml
git commit -m "test: verify supported clean host matrix"
```

### Task 7: Browser, Accessibility and Profile Instruction Evidence

**Files:**
- Create: `tests/browser/playwright.config.ts`
- Create: `tests/browser/panel.spec.ts`
- Create: `tests/browser/package.json`
- Create: `tests/browser/package-lock.json`
- Create: `tests/browser/a11y.spec.ts`
- Create: `docs/images/panel-login.png`
- Create: `docs/images/profile-card.png`

**Interfaces:**
- Produces deterministic screenshots from fixture data only.
- Produces browser evidence for login, create, copy, disable, enable, delete and reset reminder.

- [ ] **Step 1: Write failing browser flows**

```typescript
test("administrator creates and disables a profile", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Логин").fill("owner");
  await page.getByLabel("Пароль").fill("fixture passphrase");
  await page.getByRole("button", { name: "Войти" }).click();
  await page.getByRole("button", { name: "Создать профиль" }).click();
  await page.getByLabel("Название").fill("Телефон");
  await page.getByRole("button", { name: "Создать" }).click();
  await expect(page.getByText("Активен")).toBeVisible();
  await page.getByRole("button", { name: "Отключить" }).click();
  await expect(page.getByText("Отключён")).toBeVisible();
});
```

- [ ] **Step 2: Run and confirm browser project is missing**

Run: `npm --prefix tests/browser test`

Expected: FAIL because package and tests do not exist.

- [ ] **Step 3: Implement Playwright fixtures and accessible interaction**

Run the local test stack with deterministic non-production values. Cover invalid login, CSRF rejection, session timeout, profile lifecycle, clipboard fallback, QR presence, four-step help and permanent reset reminder. Run axe rules with zero serious or critical findings, keyboard-only navigation and mobile viewport. Mask all credential and link regions before screenshots.

- [ ] **Step 4: Run browser and visual evidence tests**

Run: `npm --prefix tests/browser ci && npm --prefix tests/browser test && uv run python tools/content_guard.py docs/images`

Expected: PASS and screenshots contain no usable connection material.

- [ ] **Step 5: Commit browser evidence**

```bash
git add tests/browser docs/images
git commit -m "test: verify beginner panel workflow"
```

### Task 8: External Client, Throughput and Revocation Release Gate

**Files:**
- Create: `tests/release/record_network_result.py`
- Create: `tests/release/validate_evidence.py`
- Create: `tests/release/test_evidence.py`
- Create: `docs/releases/release-checklist.md`
- Create: `docs/releases/network-result.schema.json`
- Create: `docs/releases/client-result.schema.json`
- Create after real trials: `docs/releases/evidence/fixed.json`
- Create after real trials: `docs/releases/evidence/mobile.json`
- Create after real trials: `docs/releases/evidence/clients.json`

**Interfaces:**
- Produces sanitized canonical evidence JSON per network and client; the signed release tag covers committed evidence.
- Requires network types `fixed` and `mobile` from the intended usage region.
- Requires both transports on every network result.

- [ ] **Step 1: Write failing evidence validation tests**

```python
def test_release_rejects_handshake_only_result() -> None:
    result = network_result(bytes_transferred=0, median_mbps=0.0, handshake=True)
    assert validate_network_result(result).code == "throughput_missing"


def test_release_requires_both_network_types(valid_results: list[NetworkResult]) -> None:
    fixed_only = [item for item in valid_results if item.network_type == "fixed"]
    assert validate_release_evidence(fixed_only, []).code == "network_matrix_incomplete"
```

- [ ] **Step 2: Run and confirm evidence tools are missing**

Run: `uv run pytest tests/release/test_evidence.py -q`

Expected: FAIL because evidence validation is absent.

- [ ] **Step 3: Implement measurable release criteria and sanitization**

For each transport and network type, require three trials, correct external server address, at least 100 MiB transferred per trial, median at least 2 Mbit/s and no stall over 10 seconds. During a fourth active transfer, disable the profile and require transfer termination plus failed reconnect within 10 seconds; verify another active VLESS profile reconnects automatically. Record UTC time, application version, client name and version, network type, bytes, duration, median, revocation time and pass status. Reject source IP, profile ID, UUID, token, full link, SSID, provider account and browsing destination fields.

Client evidence separately requires current stable Hiddify Next on Android, Happ on iOS and v2rayN on Windows to import the combined link and connect through both transports. A client supporting only one is documented but cannot satisfy the full matrix.

- [ ] **Step 4: Run schema tests, then perform and validate real trials**

Run: `uv run pytest tests/release/test_evidence.py -q && uv run python tests/release/validate_evidence.py docs/releases/evidence`

Expected: unit tests pass first; final evidence validation remains nonzero until all real signed result files have been collected, then exits 0.

- [ ] **Step 5: Commit only sanitized evidence and checklist**

```bash
git add tests/release docs/releases
git commit -m "test: record external transport release evidence"
```

### Task 9: History Audit, Private Remote and Public Release

**Files:**
- Create: `tools/history_guard.py`
- Create: `tools/publication_audit.sh`
- Create: `docs/releases/publication-report.md`
- Create: `tests/release/test_history_guard.py`

**Interfaces:**
- Produces: `publication_audit.sh -> report and exit 0 only when publication is safe`.
- Produces GitHub repository `A1exZabr/EzOpenPN`, initially private and not a fork.

- [ ] **Step 1: Write failing historical-blob tests**

```python
def test_guard_finds_prohibited_content_in_unreachable_current_tree(tmp_git_repo: Path) -> None:
    commit_bad_blob(tmp_git_repo)
    commit_clean_replacement(tmp_git_repo)
    result = scan_git_history(tmp_git_repo)
    assert result.ok is False
    assert result.findings[0].kind == "prohibited_content"
```

- [ ] **Step 2: Run and confirm history audit tools are missing**

Run: `uv run pytest tests/release/test_history_guard.py -q`

Expected: FAIL on missing `history_guard`.

- [ ] **Step 3: Implement full-object and GitHub metadata audit**

Enumerate every commit, tag and blob reachable from all refs with `git rev-list --objects --all` and `git cat-file --batch`, scan text through the same codepoint and hashed rules as the working-tree guard, and run gitleaks across history. Verify no source remote or fork metadata links to the predecessor, all commits belong to the new root history, all third-party licenses are present, all release assets verify and all evidence gates are complete.

Verify the private repository created in Plan 01 still has the neutral description, `isFork=false`, `visibility=PRIVATE`, main history identical to local and required checks enabled. After the complete publication audit, create the signed `v0.1.0` tag, run the manual release workflow, download and verify the private draft assets with authenticated tooling, and publish the release. Change repository visibility to public only after those checks, then run the exact README command on a new clean VPS and repeat the remote publication audit. Never force-push or rewrite a published tag.

- [ ] **Step 4: Run the final local and remote audit**

Run: `bash tools/publication_audit.sh && gh api repos/A1exZabr/EzOpenPN --jq '{visibility,isFork:.fork,defaultBranch:.default_branch}' && release_dir="$(mktemp -d)" && gh release download v0.1.0 --repo A1exZabr/EzOpenPN --dir "$release_dir" && bash tools/verify_release.sh "$release_dir"`

Expected before publication: private, not a fork, main default, audit pass. Expected after publication: public release installs successfully on a new clean VPS and every evidence link resolves.

- [ ] **Step 5: Commit the publication report and push final state**

```bash
git add tools/history_guard.py tools/publication_audit.sh docs/releases/publication-report.md tests/release/test_history_guard.py
git commit -m "release: document clean publication audit"
git push origin main --follow-tags
```

## Plan 05 Checkpoint

Run:

```bash
make check
bash tools/run_security_checks.sh
uv run pytest tests/docs tests/release tests/security -q
npm --prefix tests/browser test
bash tools/publication_audit.sh
gh run list --repo A1exZabr/EzOpenPN --limit 20
git status --short
```

Expected outcome: a public, non-fork repository with neutral history, a signed first release, one-command clean-host installation, beginner documentation and evidence that both transports work and revoke access in real external networks.
