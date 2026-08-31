from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "tests/vm/matrix.toml"
CLOUD_INIT_PATH = ROOT / "tests/vm/cloud-init.yaml"
ASSERTION_PATH = ROOT / "tests/vm/assert-preserved.sh"
EXPECTED_SYSTEMS = {
    "ubuntu-22.04",
    "ubuntu-24.04",
    "debian-12",
    "debian-13",
}
EXPECTED_STEPS = {
    "install": "pass",
    "rerun": "pass",
    "reset": "pass",
    "backup_restore": "pass",
    "reinstall": "pass",
    "uninstall": "pass",
}
LIMITATIONS = [
    "public_certificate_not_tested",
    "external_transport_performance_not_tested",
]
LAB_ADDRESS = "203.0.113.10"
REMOTE_ROOT = "/tmp/ezopenpn-vm"
SSH_USER = "eztest"
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ImageLock:
    name: str
    url: str
    filename: str
    sha256: str
    manifest_algorithm: str
    manifest_checksum: str


class VmRunError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_matrix(path: Path = MATRIX_PATH) -> dict[str, ImageLock]:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    images = document.get("images")
    if document.get("schema") != 1 or not isinstance(images, dict):
        raise ValueError("invalid VM image matrix")
    if set(images) != EXPECTED_SYSTEMS:
        raise ValueError("incomplete VM image matrix")
    loaded: dict[str, ImageLock] = {}
    for name, raw in images.items():
        if not isinstance(raw, dict):
            raise ValueError(f"invalid VM image: {name}")
        image = ImageLock(
            name=name,
            url=str(raw.get("url", "")),
            filename=str(raw.get("filename", "")),
            sha256=str(raw.get("sha256", "")),
            manifest_algorithm=str(raw.get("manifest_algorithm", "")),
            manifest_checksum=str(raw.get("manifest_checksum", "")),
        )
        checksum_length = 64 if image.manifest_algorithm == "sha256" else 128
        if (
            not image.url.startswith("https://")
            or not image.url.endswith(image.filename)
            or SHA256.fullmatch(image.sha256) is None
            or image.manifest_algorithm not in {"sha256", "sha512"}
            or re.fullmatch(
                rf"[0-9a-f]{{{checksum_length}}}", image.manifest_checksum
            )
            is None
        ):
            raise ValueError(f"invalid VM image lock: {name}")
        loaded[name] = image
    return loaded


def validate_result(result: dict[str, Any]) -> dict[str, Any]:
    expected_keys = {
        "schema",
        "system",
        "image_sha256",
        "started_at",
        "finished_at",
        "steps",
        "limitations",
    }
    if set(result) != expected_keys or result.get("schema") != 1:
        raise ValueError("invalid VM result schema")
    if result.get("system") not in EXPECTED_SYSTEMS:
        raise ValueError("invalid VM result system")
    if SHA256.fullmatch(str(result.get("image_sha256", ""))) is None:
        raise ValueError("invalid VM result image")
    if not all(
        isinstance(result.get(name), str) and TIMESTAMP.fullmatch(result[name])
        for name in ("started_at", "finished_at")
    ):
        raise ValueError("invalid VM result time")
    if result.get("steps") != EXPECTED_STEPS:
        raise ValueError("VM result does not prove every operation")
    if result.get("limitations") != LIMITATIONS:
        raise ValueError("VM result limitations are incomplete")
    return result


def _digest(path: Path, algorithm: str) -> str:
    value = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _regular_file(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)


def _run(
    command: list[str],
    *,
    label: str,
    input_text: str | None = None,
    timeout: int = 300,
    secrets_to_redact: tuple[str, ...] = (),
    print_output: bool = True,
) -> str:
    try:
        completed = subprocess.run(
            command,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VmRunError(f"{label} could not complete") from error
    output = completed.stdout or ""
    for value in secrets_to_redact:
        if value:
            output = output.replace(value, "[redacted]")
    if print_output and output.strip():
        print(output.rstrip())
    if completed.returncode != 0:
        tail = "\n".join(output.splitlines()[-40:])
        raise VmRunError(f"{label} failed with exit {completed.returncode}\n{tail}")
    return output.strip()


def _require_commands(names: tuple[str, ...]) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise VmRunError(f"required commands are unavailable: {', '.join(missing)}")


def _download_image(image: ImageLock, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True, mode=0o755)
    if cache.is_symlink() or not cache.is_dir():
        raise VmRunError("image cache is unsafe")
    destination = cache / f"{image.name}-{image.sha256}.qcow2"
    if _regular_file(destination) and _digest(destination, "sha256") == image.sha256:
        if _digest(destination, image.manifest_algorithm) != image.manifest_checksum:
            raise VmRunError("cached image disagrees with its upstream checksum")
        return destination
    if destination.exists() or destination.is_symlink():
        raise VmRunError("cached image path is occupied by invalid data")
    temporary = cache / f".{destination.name}.{os.getpid()}.partial"
    if temporary.exists() or temporary.is_symlink():
        raise VmRunError("partial image path already exists")
    try:
        _run(
            [
                "curl",
                "--proto",
                "=https",
                "--tlsv1.2",
                "-fsSL",
                "--retry",
                "3",
                "--connect-timeout",
                "15",
                "--max-time",
                "1200",
                "-o",
                str(temporary),
                image.url,
            ],
            label="cloud image download",
            timeout=1250,
        )
        if _digest(temporary, "sha256") != image.sha256:
            raise VmRunError("downloaded image checksum does not match the lock")
        if _digest(temporary, image.manifest_algorithm) != image.manifest_checksum:
            raise VmRunError("downloaded image checksum does not match upstream")
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _ssh_base(key: Path, port: int, *, tty: bool = False) -> list[str]:
    command = [
        "ssh",
        "-i",
        str(key),
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
    ]
    if tty:
        command.append("-tt")
    command.append(f"{SSH_USER}@127.0.0.1")
    return command


def _ssh(
    key: Path,
    port: int,
    remote_command: str,
    *,
    label: str,
    tty: bool = False,
    input_text: str | None = None,
    timeout: int = 300,
    secrets_to_redact: tuple[str, ...] = (),
    print_output: bool = True,
) -> str:
    return _run(
        [*_ssh_base(key, port, tty=tty), remote_command],
        label=label,
        input_text=input_text,
        timeout=timeout,
        secrets_to_redact=secrets_to_redact,
        print_output=print_output,
    )


def _copy_to_guest(key: Path, port: int, source: Path, destination: str) -> None:
    _run(
        [
            "scp",
            "-q",
            "-i",
            str(key),
            "-P",
            str(port),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            str(source),
            f"{SSH_USER}@127.0.0.1:{destination}",
        ],
        label=f"copy {source.name}",
        timeout=180,
    )


def _collect_failure_diagnostics(
    key: Path,
    port: int,
    secrets_to_redact: tuple[str, ...],
) -> None:
    inspect_format = (
        "{{.Name}} status={{.State.Status}} "
        "health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} "
        "exit={{.State.ExitCode}} error={{json .State.Error}}"
    )
    command = """set +e
printf '%s\\n' '[vm] failure diagnostics'
if command -v docker >/dev/null 2>&1; then
  sudo docker ps -a \
    --filter label=com.docker.compose.project=ezopenpn \
    --format 'table {{.Names}}\\t{{.Status}}\\t{{.Image}}'
  for container in $(sudo docker ps -aq \
    --filter label=com.docker.compose.project=ezopenpn); do
    sudo docker inspect --format __INSPECT_FORMAT__ "$container"
  done
fi
if command -v ezopenpn >/dev/null 2>&1; then
  for service in control xray hysteria gateway cert-sync; do
    printf '\\n[vm] sanitized %s logs\\n' "$service"
    sudo ezopenpn logs "$service" --since 3600 --tail 120
  done
fi
exit 0""".replace("__INSPECT_FORMAT__", shlex.quote(inspect_format))
    _ssh(
        key,
        port,
        command,
        label="collect failure diagnostics",
        timeout=90,
        secrets_to_redact=secrets_to_redact,
        print_output=True,
    )


def _wait_for_ssh(process: subprocess.Popen[bytes], key: Path, port: int) -> None:
    deadline = time.monotonic() + 420
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise VmRunError("guest stopped before SSH became ready")
        completed = subprocess.run(
            [*_ssh_base(key, port), "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        if completed.returncode == 0:
            return
        time.sleep(5)
    raise VmRunError("guest SSH did not become ready")


def _prepare_registry_auth(key: Path, port: int, token: str, user: str) -> None:
    if not token:
        return
    encoded = base64.b64encode(f"{user}:{token}".encode()).decode("ascii")
    script = (
        "import json,os,pathlib,sys;"
        "root=pathlib.Path('/root/.docker');root.mkdir(mode=0o700,exist_ok=True);"
        "path=root/'config.json';"
        "fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);"
        "stream=os.fdopen(fd,'w');"
        "json.dump({'auths':{'ghcr.io':{'auth':sys.stdin.read()}}},stream);"
        "stream.write('\\n');stream.close()"
    )
    _ssh(
        key,
        port,
        f"sudo python3 -c {shlex.quote(script)}",
        label="prepare registry authentication",
        input_text=encoded,
        secrets_to_redact=(token, encoded),
        print_output=False,
    )


def _install_command() -> str:
    values = {
        "HOME": "/root",
        "TEST_PUBLIC_IP_A": LAB_ADDRESS,
        "TEST_PUBLIC_IP_B": LAB_ADDRESS,
        "TEST_IP_ADDR_OUTPUT": f"2: lo inet {LAB_ADDRESS}/32 scope global lo",
        "EZOPENPN_BUNDLE_ROOT": f"{REMOTE_ROOT}/release",
    }
    environment = " ".join(
        f"{name}={shlex.quote(value)}" for name, value in values.items()
    )
    return (
        f"sudo -H env {environment} bash {REMOTE_ROOT}/release/installer/installer-main.sh "
        f"--advanced-lab-certificate {REMOTE_ROOT}/lab.crt "
        f"--advanced-lab-key {REMOTE_ROOT}/lab.key"
    )


def _maintenance_environment() -> str:
    values = {
        "HOME": "/root",
        "TEST_PUBLIC_IP_A": LAB_ADDRESS,
        "TEST_PUBLIC_IP_B": LAB_ADDRESS,
        "TEST_IP_ADDR_OUTPUT": f"2: lo inet {LAB_ADDRESS}/32 scope global lo",
        "TEST_UPGRADE_BUNDLE_ROOT": f"{REMOTE_ROOT}/release",
    }
    return " ".join(f"{name}={shlex.quote(value)}" for name, value in values.items())


def _run_operations(
    key: Path,
    port: int,
    bundle: Path,
    registry_token: str,
    registry_user: str,
) -> None:
    initial_password = secrets.token_urlsafe(24)
    reset_password = secrets.token_urlsafe(24)
    redactions = (initial_password, reset_password, registry_token)
    _ssh(
        key,
        port,
        f"mkdir -m 0700 -p {REMOTE_ROOT}",
        label="prepare guest workspace",
    )
    _copy_to_guest(key, port, bundle, f"{REMOTE_ROOT}/bundle.tar.gz")
    _copy_to_guest(key, port, ASSERTION_PATH, f"{REMOTE_ROOT}/assert-preserved.sh")
    prepare = (
        f"set -eu; mkdir -m 0700 {REMOTE_ROOT}/release; "
        f"tar -xzf {REMOTE_ROOT}/bundle.tar.gz -C {REMOTE_ROOT}/release; "
        f"chmod 0700 {REMOTE_ROOT}/assert-preserved.sh; "
        f"openssl req -x509 -newkey rsa:2048 -nodes -days 1 "
        f"-subj /CN={LAB_ADDRESS} -addext subjectAltName=IP:{LAB_ADDRESS} "
        f"-keyout {REMOTE_ROOT}/lab.key -out {REMOTE_ROOT}/lab.crt >/dev/null 2>&1; "
        f"sudo ip address add {LAB_ADDRESS}/32 dev lo"
    )
    _ssh(key, port, prepare, label="prepare laboratory address and certificate")
    _prepare_registry_auth(key, port, registry_token, registry_user)

    install_command = _install_command()
    _ssh(
        key,
        port,
        install_command,
        label="install",
        tty=True,
        input_text=f"LAB\nowner\n{initial_password}\n{initial_password}\n",
        timeout=1800,
        secrets_to_redact=redactions,
    )
    print("[vm] install: pass", flush=True)

    _ssh(
        key,
        port,
        f"sudo bash {REMOTE_ROOT}/assert-preserved.sh capture",
        label="capture identity before rerun",
        secrets_to_redact=redactions,
    )
    _ssh(
        key,
        port,
        install_command,
        label="rerun",
        tty=True,
        input_text="LAB\n",
        timeout=1800,
        secrets_to_redact=redactions,
    )
    _ssh(
        key,
        port,
        f"sudo bash {REMOTE_ROOT}/assert-preserved.sh verify",
        label="verify identity after rerun",
        secrets_to_redact=redactions,
    )
    print("[vm] rerun: pass", flush=True)

    _ssh(
        key,
        port,
        "sudo ezopenpn admin reset-password",
        label="reset administrator password",
        tty=True,
        input_text=f"{reset_password}\n{reset_password}\n",
        timeout=300,
        secrets_to_redact=redactions,
    )
    print("[vm] reset: pass", flush=True)

    _ssh(
        key,
        port,
        f"sudo bash {REMOTE_ROOT}/assert-preserved.sh capture",
        label="capture identity before restore",
        secrets_to_redact=redactions,
    )
    _ssh(
        key,
        port,
        "sudo ezopenpn backup",
        label="create backup",
        timeout=600,
        secrets_to_redact=redactions,
    )
    archive = _ssh(
        key,
        port,
        "sudo find /var/backups/ezopenpn -maxdepth 1 -type f -name 'ezopenpn-*.tar.gz' "
        "-printf '%T@ %p\\n' | sort -nr | head -n 1 | cut -d' ' -f2-",
        label="locate backup",
        print_output=False,
    )
    if not archive.startswith("/var/backups/ezopenpn/ezopenpn-") or "\n" in archive:
        raise VmRunError("backup command did not produce a safe archive path")
    _ssh(
        key,
        port,
        f"sudo ezopenpn restore {shlex.quote(archive)}",
        label="restore backup",
        timeout=900,
        secrets_to_redact=redactions,
    )
    _ssh(
        key,
        port,
        f"sudo bash {REMOTE_ROOT}/assert-preserved.sh verify",
        label="verify identity after restore",
        secrets_to_redact=redactions,
    )
    print("[vm] backup_restore: pass", flush=True)

    _ssh(
        key,
        port,
        f"sudo bash {REMOTE_ROOT}/assert-preserved.sh capture",
        label="capture identity before reinstall",
        secrets_to_redact=redactions,
    )
    _ssh(
        key,
        port,
        f"sudo -H env {_maintenance_environment()} ezopenpn reinstall",
        label="reinstall",
        timeout=1800,
        secrets_to_redact=redactions,
    )
    _ssh(
        key,
        port,
        f"sudo bash {REMOTE_ROOT}/assert-preserved.sh verify",
        label="verify identity after reinstall",
        secrets_to_redact=redactions,
    )
    print("[vm] reinstall: pass", flush=True)

    _ssh(
        key,
        port,
        "sudo ezopenpn uninstall && "
        "test -d /etc/ezopenpn && test -d /var/lib/ezopenpn && "
        "test -d /var/backups/ezopenpn && "
        "test -z \"$(sudo docker ps -q --filter label=com.docker.compose.project=ezopenpn)\"",
        label="uninstall",
        timeout=600,
        secrets_to_redact=redactions,
    )
    print("[vm] uninstall: pass", flush=True)


def _write_result(path: Path, result: dict[str, Any]) -> None:
    validate_result(result)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise VmRunError("result path already exists")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def run_system(system: str, bundle: Path, output: Path, cache: Path) -> None:
    _require_commands(
        (
            "cloud-localds",
            "curl",
            "qemu-img",
            "qemu-system-x86_64",
            "scp",
            "ssh",
            "ssh-keygen",
        )
    )
    if sys.platform != "linux" or not Path("/dev/kvm").exists():
        raise VmRunError("KVM acceleration is required")
    if not _regular_file(bundle):
        raise VmRunError("release bundle must be a regular file")
    image = load_matrix()[system]
    started_at = _utc_now()
    base = _download_image(image, cache)
    with tempfile.TemporaryDirectory(prefix=f"ezopenpn-{system}.") as raw_work:
        work = Path(raw_work)
        private_key = work / "id_ed25519"
        _run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
            label="generate disposable SSH key",
        )
        public_key = private_key.with_suffix(".pub").read_text(encoding="ascii").strip()
        user_data = CLOUD_INIT_PATH.read_text(encoding="utf-8").replace(
            "@@SSH_PUBLIC_KEY@@", public_key
        )
        if "@@" in user_data:
            raise VmRunError("cloud-init template contains an unresolved marker")
        (work / "user-data").write_text(user_data, encoding="utf-8")
        (work / "meta-data").write_text(
            f"instance-id: ezopenpn-{secrets.token_hex(12)}\nlocal-hostname: ez-test\n",
            encoding="ascii",
        )
        seed = work / "seed.img"
        _run(
            ["cloud-localds", str(seed), str(work / "user-data"), str(work / "meta-data")],
            label="create cloud-init seed",
        )
        information = json.loads(
            _run(
                ["qemu-img", "info", "--output=json", str(base)],
                label="inspect cloud image",
                print_output=False,
            )
        )
        if information.get("format") != "qcow2" or information.get("backing-filename"):
            raise VmRunError("cloud image is not a standalone qcow2 disk")
        overlay = work / "overlay.qcow2"
        _run(
            [
                "qemu-img",
                "create",
                "-q",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(base),
                str(overlay),
                "24G",
            ],
            label="create disposable overlay",
        )
        port = _reserve_port()
        console = (work / "console.log").open("wb")
        command = [
            "qemu-system-x86_64",
            "-machine",
            "q35,accel=kvm",
            "-cpu",
            "host",
            "-smp",
            "2",
            "-m",
            "2048",
            "-drive",
            f"file={overlay},if=virtio,format=qcow2,cache=unsafe",
            "-drive",
            f"file={seed},if=virtio,format=raw,readonly=on",
            "-netdev",
            f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-display",
            "none",
            "-serial",
            "stdio",
            "-monitor",
            "none",
            "-no-reboot",
        ]
        process = subprocess.Popen(command, stdout=console, stderr=subprocess.STDOUT)
        try:
            _wait_for_ssh(process, private_key, port)
            _ssh(
                private_key,
                port,
                "sudo cloud-init status --wait",
                label="wait for cloud-init",
                timeout=600,
            )
            registry_token = os.environ.get("EZOPENPN_VM_REGISTRY_TOKEN", "")
            registry_user = os.environ.get("EZOPENPN_VM_REGISTRY_USER", "github-actions")
            _run_operations(
                private_key,
                port,
                bundle,
                registry_token,
                registry_user,
            )
        except BaseException:
            try:
                _collect_failure_diagnostics(
                    private_key,
                    port,
                    (registry_token,),
                )
            except VmRunError as diagnostic_error:
                print(
                    f"[vm] failure diagnostics unavailable: {diagnostic_error}",
                    file=sys.stderr,
                )
            console.flush()
            try:
                lines = (work / "console.log").read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if lines:
                    print("[vm] console tail:", file=sys.stderr)
                    print("\n".join(lines[-80:]), file=sys.stderr)
            except OSError:
                pass
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            console.close()
    _write_result(
        output,
        {
            "schema": 1,
            "system": system,
            "image_sha256": image.sha256,
            "started_at": started_at,
            "finished_at": _utc_now(),
            "steps": EXPECTED_STEPS,
            "limitations": LIMITATIONS,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a disposable clean-system check")
    parser.add_argument("--system", choices=sorted(EXPECTED_SYSTEMS))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--cache",
        type=Path,
        default=Path(os.environ.get("EZOPENPN_VM_CACHE", "/tmp/ezopenpn-vm-cache")),
    )
    parser.add_argument("--validate-result", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.validate_result is not None:
            document = json.loads(arguments.validate_result.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("VM result must be an object")
            validate_result(document)
            print("VM result is valid.")
            return 0
        if arguments.system is None or arguments.bundle is None or arguments.output is None:
            parser.error("--system, --bundle and --output are required")
        run_system(
            arguments.system,
            arguments.bundle.resolve(strict=True),
            arguments.output.resolve(),
            arguments.cache.resolve(),
        )
    except (OSError, ValueError, VmRunError, json.JSONDecodeError) as error:
        print(f"VM check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
