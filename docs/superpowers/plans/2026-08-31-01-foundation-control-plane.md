# EzOpenPN Foundation and Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a tested Python control plane with clean-repository gates, durable encrypted state, one administrator, secure sessions and a locally usable Russian profile panel.

**Architecture:** A synchronous SQLAlchemy service owns SQLite transactions and is injected into thin FastAPI routes. Security primitives, profile persistence and web concerns live in separate modules; transport operations are represented by typed protocols and use fakes until Plan 02 provides real adapters.

**Tech Stack:** Python 3.12, uv, FastAPI 0.141.1, SQLAlchemy 2.0.52, Alembic 1.19.1, Pydantic Settings 2.15.0, PyNaCl 1.6.2, Argon2 CFFI 25.1.0, Jinja2 3.1.6, Segno 1.6.6, pytest 9.1.1, Ruff 0.16.5 and mypy 2.3.1.

**Spec:** `docs/superpowers/specs/2026-08-31-ezopenpn-design.md`

## Global Constraints

- Apply every constraint in `docs/superpowers/plans/2026-08-31-ezopenpn-implementation-index.md`.
- Keep Python on 3.12 and commit `uv.lock`.
- Keep routes thin; transactions and state transitions belong to services.
- Never pass administrator passwords through arguments, environment values or logs.
- Never log decrypted profile values, UUID credentials, opaque tokens or complete links.
- Public Russian copy must pass `tools/content_guard.py`.
- Every state-changing browser request requires both an authenticated server-side session and a valid CSRF token.
- Tests use temporary directories and temporary SQLite databases only.

---

### Task 1: Repository Skeleton and Content Guard

**Files:**
- Create: `.editorconfig`
- Create: `.gitignore`
- Create: `pyproject.toml`
- Create: `Makefile`
- Create: `control/src/ezopenpn/__init__.py`
- Create: `tools/content_guard.py`
- Create: `control/tests/unit/test_content_guard.py`

**Interfaces:**
- Produces: `python tools/content_guard.py [root] -> exit 0 or 1`
- Produces: `make unit`, `make lint`, `make content-check`, `make check`

- [ ] **Step 1: Write failing guard tests**

```python
from pathlib import Path

from tools.content_guard import scan_tree


def test_guard_rejects_constructed_historical_label(tmp_path: Path) -> None:
    value = "".join(chr(code) for code in (118, 112, 110))
    (tmp_path / "bad.txt").write_text(value, encoding="utf-8")
    assert scan_tree(tmp_path) == ["bad.txt: prohibited content"]


def test_guard_rejects_long_dash(tmp_path: Path) -> None:
    (tmp_path / "bad.md").write_text(chr(0x2014), encoding="utf-8")
    assert scan_tree(tmp_path) == ["bad.md: prohibited typography"]


def test_guard_accepts_neutral_copy(tmp_path: Path) -> None:
    (tmp_path / "ok.md").write_text("Защищённое подключение", encoding="utf-8")
    assert scan_tree(tmp_path) == []
```

- [ ] **Step 2: Run the focused tests and confirm the import failure**

Run: `uv run pytest control/tests/unit/test_content_guard.py -q`

Expected: FAIL because `tools.content_guard` does not exist.

- [ ] **Step 3: Implement the scanner and project configuration**

Use these runtime-built labels and hashed legacy fragments so no forbidden literal is committed:

```python
PROHIBITED_CODEPOINTS = (
    (118, 112, 110),
    (1074, 1087, 1085),
)

LEGACY_HASHES = {
    7: {
        "9df9fbcc062eaeb4878c8e4070a910a3177af66901b7c026c792d5dbeed9b565",
        "bbace7c72de0ee8e3b0d4af9b1f88b79d7ac154e56dcca5f65855b37a48e07e5",
        "2be96eabe47efd9af4bdf5dc85c2264c1e5b3fc0d3b44e561953e6ebb7455745",
        "040ffd5925d40e11c67b7238a7fc9957850b8b9a46e9729fab88c24d6a98aff2",
    },
    8: {
        "4771e5a54bc39fe9ec290bdbf2a9c6fb6fe31d9a654c818690609d3c8e7bc735",
        "3f40462915a3e6026a4d790127b95ded4d870f6ab18d9af2fcbc454168255237",
        "44574c4ba2ea74ad4bf1e184133cdbf4e7390a3690beff6a7364511a70ec208e",
    },
    12: {"1e5c936639f3bcfd9720cb13071246e94999dfeeb3c8f1f82e9b01cdce3ae0c5"},
    20: {"0d98bc50af694fee7ba0dfd2f06dab35fcaa371202785b9bc004f914d9474dc2"},
}
```

`scan_tree()` must scan relative paths and UTF-8 text, skip `.git`, skip files containing a NUL byte, casefold before hashed-window checks, sort diagnostics and reject private-key PEM markers and common assignment patterns for passwords or tokens. Configure `pyproject.toml` with the exact dependency versions from the index, the `control/src` package root, pytest path, Ruff rules `E,F,I,B,SIM,UP`, and strict mypy for `ezopenpn`.

- [ ] **Step 4: Run the guard, unit test and static configuration checks**

Run: `uv lock && uv sync --all-groups && uv run pytest control/tests/unit/test_content_guard.py -q && uv run python tools/content_guard.py . && uv run ruff check .`

Expected: all commands exit 0 and `uv.lock` is created.

- [ ] **Step 5: Commit the repository foundation**

```bash
git add .editorconfig .gitignore pyproject.toml uv.lock Makefile tools control
git commit -m "build: add control plane foundation"
```

### Task 2: Typed Configuration and Secret File Loading

**Files:**
- Create: `control/src/ezopenpn/config.py`
- Create: `control/tests/unit/test_config.py`

**Interfaces:**
- Produces: `Settings.load(config_path: Path) -> Settings`
- Produces: `SecretFiles.load(master_key_path: Path, hysteria_api_path: Path, hysteria_obfs_path: Path) -> SecretFiles`

- [ ] **Step 1: Write failing configuration tests**

```python
def test_settings_require_absolute_paths(tmp_path: Path) -> None:
    config = tmp_path / "control.toml"
    config.write_text('[app]\npublic_ip="203.0.113.10"\ndatabase_path="relative.db"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="database_path must be absolute"):
        Settings.load(config)


def test_secret_loader_rejects_open_permissions(tmp_path: Path) -> None:
    key = tmp_path / "master.key"
    key.write_bytes(bytes(range(32)))
    key.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        SecretFiles.load(key, key, key)
```

- [ ] **Step 2: Run and confirm the missing module failure**

Run: `uv run pytest control/tests/unit/test_config.py -q`

Expected: FAIL because `ezopenpn.config` does not exist.

- [ ] **Step 3: Implement immutable settings**

Define frozen Pydantic models for app, database, paths, proxy trust, Xray, Hysteria2 and session settings. Read non-secret values from one TOML file. Read the 32-byte master key, Hysteria2 API secret and Salamander secret from separate files, require regular files, reject symlinks, require mode `0600`, reject wrong lengths and never include secret bytes in `repr`.

```python
class Settings(BaseModel):
    model_config = ConfigDict(frozen=True)
    public_ip: IPvAnyAddress
    database_path: Path
    xray_grpc_target: str = "xray:10085"
    xray_inbound_tag: str = "protected-entry"
    hysteria_stats_url: AnyHttpUrl = "http://hysteria:9999"
    supervisor_socket: Path = Path("/run/ezopenpn-xray/control.sock")
    trusted_proxy_hosts: frozenset[str] = frozenset({"gateway"})
```

- [ ] **Step 4: Run focused and lint tests**

Run: `uv run pytest control/tests/unit/test_config.py -q && uv run ruff check control/src/ezopenpn/config.py control/tests/unit/test_config.py && uv run mypy control/src/ezopenpn/config.py`

Expected: PASS.

- [ ] **Step 5: Commit configuration loading**

```bash
git add control/src/ezopenpn/config.py control/tests/unit/test_config.py
git commit -m "feat: add typed control configuration"
```

### Task 3: SQLite Models and Initial Migration

**Files:**
- Create: `control/src/ezopenpn/db.py`
- Create: `control/src/ezopenpn/models.py`
- Create: `control/alembic.ini`
- Create: `control/migrations/env.py`
- Create: `control/migrations/script.py.mako`
- Create: `control/migrations/versions/0001_initial.py`
- Create: `control/tests/integration/test_migrations.py`

**Interfaces:**
- Produces: `create_engine_for(path: Path) -> Engine`
- Produces: `session_scope(engine: Engine) -> Iterator[Session]`
- Produces: `upgrade_database(path: Path) -> None`
- Produces models: `Admin`, `AdminSession`, `LoginThrottle`, `Profile`, `ProfileLookup`, `SystemState`, `AuditEvent`

- [ ] **Step 1: Write a failing migration round-trip test**

```python
def test_initial_migration_creates_expected_tables(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    upgrade_database(database)
    inspector = inspect(create_engine(f"sqlite:///{database}"))
    assert set(inspector.get_table_names()) == {
        "admins", "admin_sessions", "login_throttles", "profiles",
        "profile_lookups", "system_state", "audit_events", "alembic_version",
    }
```

- [ ] **Step 2: Run and confirm the migration helper is absent**

Run: `uv run pytest control/tests/integration/test_migrations.py -q`

Expected: FAIL on the missing migration module.

- [ ] **Step 3: Implement models, pragmas and migration**

Use string UUID primary keys, UTC-aware timestamp conversion at repository boundaries and a `ProfileState` enum with `pending`, `active`, `disabled` and `error`. Store the wrapped per-profile data key and encrypted values as separate BLOB columns. Add unique constraints for administrator login, profile runtime ID and lookup digest. Configure every SQLite connection with foreign keys, WAL, `busy_timeout=5000`, `synchronous=FULL` and `secure_delete=ON`.

```python
@event.listens_for(Engine, "connect")
def set_sqlite_pragmas(connection: DBAPIConnection, _: object) -> None:
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA synchronous=FULL")
    cursor.close()
```

- [ ] **Step 4: Run migration, model and full unit suites**

Run: `uv run pytest control/tests/integration/test_migrations.py control/tests/unit -q`

Expected: PASS, including upgrade from an empty database and downgrade back to empty.

- [ ] **Step 5: Commit durable storage**

```bash
git add control/alembic.ini control/migrations control/src/ezopenpn/db.py control/src/ezopenpn/models.py control/tests/integration/test_migrations.py
git commit -m "feat: add durable control database"
```

### Task 4: Passwords, Secret Encryption and Lookup Digests

**Files:**
- Create: `control/src/ezopenpn/security/__init__.py`
- Create: `control/src/ezopenpn/security/passwords.py`
- Create: `control/src/ezopenpn/security/secrets.py`
- Create: `control/tests/unit/security/test_passwords.py`
- Create: `control/tests/unit/security/test_secrets.py`

**Interfaces:**
- Produces: `PasswordHasher.hash(password: str) -> str`
- Produces: `PasswordHasher.verify(encoded: str, password: str) -> PasswordCheck`, including `needs_rehash`
- Produces: `SecretCipher.encrypt_profile_value(key: bytes, value: bytes, context: bytes) -> bytes`
- Produces: `SecretCipher.decrypt_profile_value(key: bytes, blob: bytes, context: bytes) -> bytes`
- Produces: `SecretCipher.lookup_digest(value: bytes) -> bytes`
- Produces: `SecretCipher.new_profile_key() -> bytes`, `wrap_profile_key(profile_id: UUID, key: bytes) -> bytes`, `unwrap_profile_key(profile_id: UUID, wrapped: bytes) -> bytes`

- [ ] **Step 1: Write failing primitive tests**

```python
def test_cipher_uses_distinct_nonces() -> None:
    cipher = SecretCipher(bytes(range(32)))
    profile_key = cipher.new_profile_key()
    first = cipher.encrypt_profile_value(profile_key, b"same", b"profile:one")
    second = cipher.encrypt_profile_value(profile_key, b"same", b"profile:one")
    assert first != second
    assert cipher.decrypt_profile_value(profile_key, first, b"profile:one") == b"same"


def test_password_parameters_are_embedded() -> None:
    encoded = PasswordHasher().hash("correct horse battery staple")
    assert "m=65536,t=3,p=2" in encoded
```

- [ ] **Step 2: Run and confirm missing security modules**

Run: `uv run pytest control/tests/unit/security -q`

Expected: FAIL on missing imports.

- [ ] **Step 3: Implement key separation and constant-time checks**

Derive independent 32-byte wrapping and lookup keys using HMAC-SHA-256 labels `ezopenpn/wrap/v1` and `ezopenpn/lookup/v1`. Generate one random 32-byte data key per profile, wrap it with the master-derived key, and encrypt every profile field with that data key. Use `nacl.secret.Aead` with a fresh 24-byte nonce and context as additional authenticated data. Prefix ciphertext with a one-byte format version. Use `hmac.compare_digest` for lookup verification. Deleting the wrapped per-profile key provides cryptographic erasure of remaining ciphertext pages. Configure `argon2.PasswordHasher` with `time_cost=3`, `memory_cost=65536`, `parallelism=2`, `salt_len=16`, `hash_len=32` and Argon2id. Return `needs_rehash` from successful verification and replace the stored hash in the same login transaction when parameters have increased.

- [ ] **Step 4: Run primitive tests and deliberately break context binding once**

Run: `uv run pytest control/tests/unit/security -q`

Expected: PASS. Temporarily change the decrypt context in the test and confirm `CryptoError`, then restore the passing test before commit.

- [ ] **Step 5: Commit security primitives**

```bash
git add control/src/ezopenpn/security control/tests/unit/security
git commit -m "feat: protect passwords and profile secrets"
```

### Task 5: Administrator, Sessions, CSRF and Login Throttling

**Files:**
- Create: `control/src/ezopenpn/security/admin.py`
- Create: `control/src/ezopenpn/security/sessions.py`
- Create: `control/src/ezopenpn/security/throttle.py`
- Create: `control/tests/unit/security/test_admin.py`
- Create: `control/tests/integration/test_sessions.py`

**Interfaces:**
- Produces: `AdminService.create_initial(login: str, password: str) -> Admin`
- Produces: `AdminService.reset_password(password: str) -> None`
- Produces: `SessionService.create(admin_id: UUID, now: datetime) -> SessionGrant`
- Produces: `SessionService.authenticate(raw_token: str, now: datetime) -> SessionIdentity | None`
- Produces: `LoginThrottle.register_failure(ip: str, login: str, now: datetime) -> timedelta`

- [ ] **Step 1: Write failing session and reset tests**

```python
def test_password_reset_revokes_existing_session(services: ServiceFixture) -> None:
    admin = services.admin.create_initial("owner", "first strong password")
    grant = services.sessions.create(admin.id, services.now)
    services.admin.reset_password("second strong password")
    assert services.sessions.authenticate(grant.raw_token, services.now) is None


def test_session_has_idle_and_absolute_expiry(services: ServiceFixture) -> None:
    admin = services.admin.create_initial("owner", "first strong password")
    grant = services.sessions.create(admin.id, services.now)
    assert services.sessions.authenticate(grant.raw_token, services.now + timedelta(hours=12, seconds=1)) is None
```

- [ ] **Step 2: Run and confirm missing services**

Run: `uv run pytest control/tests/unit/security/test_admin.py control/tests/integration/test_sessions.py -q`

Expected: FAIL on missing service classes.

- [ ] **Step 3: Implement one-admin invariants and opaque sessions**

Store only HMAC digests of 32-byte session tokens and CSRF tokens. Rotate the cookie token on login. Record a session version copied from the administrator row and reject mismatches. Use a 12-hour idle deadline and 7-day absolute deadline. Normalize login with Unicode NFKC and casefold. Throttle by independent HMAC digests of client IP and normalized login, with delays of 1, 2, 4, 8, 16 and 30 seconds and a 15-minute decay window.

- [ ] **Step 4: Run tests including constant response behavior**

Run: `uv run pytest control/tests/unit/security control/tests/integration/test_sessions.py -q`

Expected: PASS; unknown login and bad password return the same result type and public message.

- [ ] **Step 5: Commit administrator security**

```bash
git add control/src/ezopenpn/security control/tests/unit/security control/tests/integration/test_sessions.py
git commit -m "feat: add secure administrator sessions"
```

### Task 6: Profile Repository and State Machine

**Files:**
- Create: `control/src/ezopenpn/profiles/__init__.py`
- Create: `control/src/ezopenpn/profiles/types.py`
- Create: `control/src/ezopenpn/profiles/repository.py`
- Create: `control/src/ezopenpn/profiles/service.py`
- Create: `control/tests/unit/profiles/test_repository.py`
- Create: `control/tests/unit/profiles/test_service.py`

**Interfaces:**
- Produces: `ProfileRepository.insert_pending(material: NewProfileMaterial) -> ProfileRecord`
- Produces: `ProfileRepository.find_by_subscription_token(token: str) -> ProfileRecord | None`
- Produces: `ProfileService.create(name: str) -> ProfileResult`
- Produces: `ProfileService.disable_local(profile_id: UUID) -> ProfileResult`
- Consumes later: `ProfileCoordinator` from the index replaces the local fake runtime.

- [ ] **Step 1: Write failing state-machine tests**

```python
def test_profile_creation_encrypts_all_credentials(profile_service: ProfileService) -> None:
    result = profile_service.create("Телефон")
    stored = profile_service.repository.get(result.profile_id)
    assert stored.state is ProfileState.PENDING
    assert profile_service.fixture_plain_secret not in stored.hysteria_secret_ciphertext
    assert stored.wrapped_profile_key
    assert stored.subscription_lookup_digest != result.subscription_token.encode()


def test_invalid_transition_is_rejected(profile_service: ProfileService) -> None:
    created = profile_service.create("Ноутбук")
    profile_service.repository.set_state(created.profile_id, ProfileState.ERROR)
    profile_service.repository.set_state(created.profile_id, ProfileState.DISABLED)
    with pytest.raises(InvalidProfileTransition):
        profile_service.repository.set_state(created.profile_id, ProfileState.PENDING)
```

- [ ] **Step 2: Run and confirm profile modules are missing**

Run: `uv run pytest control/tests/unit/profiles -q`

Expected: FAIL on missing imports.

- [ ] **Step 3: Implement generated material and legal transitions**

Define `ProfileResult` in `profiles/types.py` with profile ID, name, state, runtime ID and optional link bundle; its `repr` redacts the bundle. Generate a UUID credential, 32 random bytes for Hysteria2 auth, 32 random bytes for the subscription token, one per-profile data key and a separate random runtime ID formatted as `p_` plus 26 lowercase Base32 characters. Store only the wrapped data key. Validate names after trimming: 1 to 64 Unicode characters, no control characters. Encrypt each value with the data key and context containing the profile ID and field name. Inject the random-byte provider in tests so `fixture_plain_secret` is deterministic. Define legal transitions `pending -> active|error`, `error -> pending|disabled`, `active -> disabled|error`, and `disabled -> active|error`.

- [ ] **Step 4: Run profile tests and database suite**

Run: `uv run pytest control/tests/unit/profiles control/tests/integration/test_migrations.py -q`

Expected: PASS.

- [ ] **Step 5: Commit profile persistence**

```bash
git add control/src/ezopenpn/profiles control/tests/unit/profiles
git commit -m "feat: add encrypted profile state"
```

### Task 7: Control CLI for Initial Administrator and Password Reset

**Files:**
- Create: `control/src/ezopenpn/cli.py`
- Create: `control/tests/integration/test_cli.py`

**Interfaces:**
- Produces: `python -m ezopenpn.cli init-admin --login LOGIN --password-stdin`
- Produces: `python -m ezopenpn.cli reset-password --password-stdin`
- Produces: `python -m ezopenpn.cli migrate`

- [ ] **Step 1: Write failing CLI tests**

```python
def test_init_admin_reads_password_only_from_stdin(cli: CliFixture) -> None:
    result = cli.run(["init-admin", "--login", "owner", "--password-stdin"], input="strong passphrase\n")
    assert result.returncode == 0
    assert "strong passphrase" not in result.stdout
    assert "strong passphrase" not in result.stderr


def test_second_initial_admin_is_rejected(cli: CliFixture) -> None:
    assert cli.run(["init-admin", "--login", "owner", "--password-stdin"], input="first passphrase\n").returncode == 0
    result = cli.run(["init-admin", "--login", "other", "--password-stdin"], input="second passphrase\n")
    assert result.returncode == 4
```

- [ ] **Step 2: Run and confirm the module is absent**

Run: `uv run pytest control/tests/integration/test_cli.py -q`

Expected: FAIL because `ezopenpn.cli` does not exist.

- [ ] **Step 3: Implement argparse commands and exit codes**

Read exactly one newline-terminated password from stdin only when `--password-stdin` is present. Reject a terminal on stdin in that mode so automation cannot hang. Use exit codes 0 success, 2 invalid input, 3 unavailable database, 4 state conflict and 5 migration failure. Output neutral success text without login or database paths.

- [ ] **Step 4: Run CLI tests and a real temporary migration**

Run: `uv run pytest control/tests/integration/test_cli.py -q`

Expected: tests pass, including a migration command against a test-created absolute temporary path.

- [ ] **Step 5: Commit the control CLI**

```bash
git add control/src/ezopenpn/cli.py control/tests/integration/test_cli.py
git commit -m "feat: add administrator control commands"
```

### Task 8: FastAPI Application, Proxy Trust and Authentication Routes

**Files:**
- Create: `control/src/ezopenpn/web/__init__.py`
- Create: `control/src/ezopenpn/web/app.py`
- Create: `control/src/ezopenpn/web/dependencies.py`
- Create: `control/src/ezopenpn/web/middleware.py`
- Create: `control/src/ezopenpn/web/routes/auth.py`
- Create: `control/src/ezopenpn/web/routes/health.py`
- Create: `control/src/ezopenpn/web/templates/base.html`
- Create: `control/src/ezopenpn/web/templates/login.html`
- Create: `control/src/ezopenpn/web/static/app.css`
- Create: `control/tests/integration/web/test_auth.py`
- Create: `control/tests/integration/web/test_proxy_headers.py`

**Interfaces:**
- Produces: `create_app(settings: Settings, services: Services) -> FastAPI`
- Produces routes: `/health/live`, `/health/ready`, `/login`, `/logout`
- Produces cookie: `ezop_session`, Secure, HttpOnly, SameSite Strict, Path `/`

- [ ] **Step 1: Write failing browser-route tests**

```python
def test_login_rotates_session_and_sets_secure_cookie(web_client: TestClient) -> None:
    csrf = extract_csrf(web_client.get("/login").text)
    response = web_client.post("/login", data={"login": "owner", "password": "correct passphrase", "csrf": csrf}, follow_redirects=False)
    assert response.status_code == 303
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie


def test_untrusted_forwarded_address_is_ignored(web_client: TestClient) -> None:
    response = web_client.get("/health/live", headers={"x-forwarded-for": "198.51.100.7"})
    assert response.headers["x-observed-client"] != "198.51.100.7"
```

The second response header exists only under the test setting and is never enabled in production.

- [ ] **Step 2: Run and confirm missing web modules**

Run: `uv run pytest control/tests/integration/web/test_auth.py control/tests/integration/web/test_proxy_headers.py -q`

Expected: FAIL on missing `create_app`.

- [ ] **Step 3: Implement the application and middleware**

Disable `/docs`, `/redoc` and OpenAPI in production. Trust forwarded headers only when the direct peer is the configured gateway. Add request IDs, safe exception mapping, CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, and `frame-ancestors 'none'`. Use identical status and copy for unknown login and bad password. For login, issue a short-lived pre-auth nonce in an HttpOnly SameSite Strict cookie and place its HMAC-bound form token in the page; consume it once on POST. Require session CSRF on logout and every later mutation.

- [ ] **Step 4: Run route tests and inspect headers**

Run: `uv run pytest control/tests/integration/web -q && uv run python tools/content_guard.py control/src/ezopenpn/web`

Expected: PASS and no content diagnostics.

- [ ] **Step 5: Commit authenticated web entry**

```bash
git add control/src/ezopenpn/web control/tests/integration/web
git commit -m "feat: add secure panel authentication"
```

### Task 9: Profile Panel with Injected Runtime Coordinator

**Files:**
- Create: `control/src/ezopenpn/profiles/runtime.py`
- Create: `control/src/ezopenpn/web/routes/profiles.py`
- Create: `control/src/ezopenpn/web/templates/dashboard.html`
- Create: `control/src/ezopenpn/web/templates/profile.html`
- Create: `control/src/ezopenpn/web/static/app.js`
- Create: `control/tests/integration/web/test_profiles.py`

**Interfaces:**
- Produces the profile routes defined in the index.
- Produces: `RuntimeCoordinator` protocol with the exact `ProfileCoordinator` method signatures from the index.
- Consumes in this plan: `FakeRuntimeCoordinator`; Plan 02 supplies `ProfileCoordinator`.

- [ ] **Step 1: Write failing authenticated lifecycle tests**

```python
def test_create_profile_redirects_to_card(authenticated_client: TestClient) -> None:
    csrf = dashboard_csrf(authenticated_client)
    response = authenticated_client.post("/profiles", data={"name": "Телефон", "csrf": csrf}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/profiles/")


def test_mutation_without_csrf_is_rejected(authenticated_client: TestClient, profile_id: str) -> None:
    response = authenticated_client.post(f"/profiles/{profile_id}/disable")
    assert response.status_code == 403
```

- [ ] **Step 2: Run and confirm missing profile routes**

Run: `uv run pytest control/tests/integration/web/test_profiles.py -q`

Expected: FAIL with 404 for `/profiles`.

- [ ] **Step 3: Implement thin routes and beginner copy**

Dashboard cards show `Активен`, `Отключён` or `Нужна проверка`, a create form and the permanent recovery reminder `sudo ezopenpn admin reset-password`. The profile page reserves fields for the combined link and both transport links but displays `Подключение готовится` while the fake runtime has no material. JavaScript only copies already rendered values and does not make security decisions.

- [ ] **Step 4: Run route, accessibility smoke and content tests**

Run: `uv run pytest control/tests/integration/web/test_profiles.py -q && uv run python tools/content_guard.py control/src/ezopenpn/web`

Expected: PASS; all controls have labels, focus styles and keyboard operation.

- [ ] **Step 5: Commit the local profile panel**

```bash
git add control/src/ezopenpn/profiles/runtime.py control/src/ezopenpn/web control/tests/integration/web/test_profiles.py
git commit -m "feat: add profile management panel"
```

### Task 10: Control Image and Foundation CI Gate

**Files:**
- Create: `control/Dockerfile`
- Create: `control/docker-entrypoint.sh`
- Create: `.github/workflows/ci.yml`
- Create: `tests/compose/control-smoke.sh`

**Interfaces:**
- Produces image entrypoint: migrations, then `uvicorn ezopenpn.web.app:create_runtime_app --factory`
- Produces CI jobs: `content`, `python`, `control-image`

- [ ] **Step 1: Write a failing image smoke script**

```bash
#!/usr/bin/env bash
set -euo pipefail
image_name="ezopenpn-control:test"
docker build -f control/Dockerfile -t "$image_name" .
test "$(docker image inspect "$image_name" --format '{{.Config.User}}')" = "10001:10001"
docker run --rm "$image_name" python -m ezopenpn.cli --help >/dev/null
```

- [ ] **Step 2: Run and confirm the Dockerfile is missing**

Run: `bash tests/compose/control-smoke.sh`

Expected: FAIL because `control/Dockerfile` does not exist.

- [ ] **Step 3: Implement a locked, non-root multi-stage image**

Use `python:3.12.11-slim-bookworm` as the local development base; Plan 03 replaces every production build input with its locked amd64 digest. Install from `uv.lock` with `uv sync --frozen --no-dev`, copy only the virtual environment and application into the runtime stage, create UID and GID 10001, set read-only-compatible paths, add a Python healthcheck and use `tini` as PID 1. The entrypoint runs migrations once and then uses `exec`.

CI runs the content guard first, then Ruff, mypy, pytest with branch coverage, migration tests and the image smoke test. GitHub Actions are pinned to commit SHA values.

- [ ] **Step 4: Run the complete foundation gate**

Run: `make check && bash tests/compose/control-smoke.sh && git diff --check`

Expected: all checks pass and `git status --short` lists only intended files.

- [ ] **Step 5: Commit the foundation delivery**

```bash
git add control/Dockerfile control/docker-entrypoint.sh .github/workflows/ci.yml tests/compose/control-smoke.sh
git commit -m "build: package and verify control service"
```

### Task 11: Private Non-Fork GitHub Repository

**Files:**
- Create: `docs/development/repository-policy.md`

**Interfaces:**
- Produces remote: `origin -> https://github.com/A1exZabr/EzOpenPN.git`
- Produces GitHub metadata: private visibility, `main` default branch, `isFork=false`, neutral description.

- [ ] **Step 1: Record the expected repository invariants**

Document that the repository is created from the current root commit, never as a fork, carries no predecessor remote, remains private through development and becomes public only after Plan 05 passes.

- [ ] **Step 2: Verify the target name and local history before mutation**

Run: `test "$(git rev-list --max-parents=0 HEAD | wc -l | tr -d ' ')" = 1 && test -z "$(git remote)" && ! gh api repos/A1exZabr/EzOpenPN >/dev/null 2>&1`

Expected: one local root, no remote, and GitHub returns not found.

- [ ] **Step 3: Commit the repository policy**

```bash
git add docs/development/repository-policy.md
git commit -m "docs: define clean repository policy"
```

- [ ] **Step 4: Create privately and push without importing other history**

Run: `gh repo create A1exZabr/EzOpenPN --private --source=. --remote=origin --push --description "Самостоятельный сервер защищённых подключений"`

Expected: creation succeeds and pushes `main`.

- [ ] **Step 5: Verify remote metadata and exact branch identity**

Run: `gh api repos/A1exZabr/EzOpenPN --jq '{visibility,isFork:.fork,defaultBranch:.default_branch}' && test "$(git rev-parse HEAD)" = "$(git ls-remote origin refs/heads/main | cut -f1)"`

Expected: `PRIVATE`, false, `main`, and identical local and remote commit IDs.

## Plan 01 Checkpoint

Run:

```bash
make check
bash tests/compose/control-smoke.sh
gh api repos/A1exZabr/EzOpenPN --jq '{visibility,isFork:.fork,defaultBranch:.default_branch}'
git log --oneline --decorate -10
git status --short
```

Expected outcome: a clean worktree, a non-root control image, a local login flow, encrypted profile persistence and a panel whose runtime boundary can be replaced by Plan 02 without route changes.
