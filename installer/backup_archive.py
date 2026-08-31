#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO

FORMAT_VERSION = 1
SUPPORTED_SCHEMA_VERSIONS = frozenset({"0001_initial"})
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024
MAX_TOTAL_SIZE = 4 * 1024 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_MANIFEST_SIZE = 1024 * 1024

FIXED_SOURCES = (
    ("database/ezopenpn.sqlite3", "snapshot"),
    ("configuration/control.toml", "etc/ezopenpn/control.toml"),
    ("configuration/Caddyfile", "etc/ezopenpn/Caddyfile"),
    ("configuration/compose.yaml", "etc/ezopenpn/compose.yaml"),
    ("configuration/stack.env", "etc/ezopenpn/stack.env"),
    ("state/install.json", "var/lib/ezopenpn/install.json"),
    ("secrets/master.key", "var/lib/ezopenpn/secrets/master.key"),
    ("secrets/hysteria-api.key", "var/lib/ezopenpn/secrets/hysteria-api.key"),
    ("secrets/hysteria-obfs.key", "var/lib/ezopenpn/secrets/hysteria-obfs.key"),
    ("runtime/xray/config.json", "var/lib/ezopenpn/runtime/xray/config.json"),
    ("runtime/hysteria/config.yaml", "var/lib/ezopenpn/runtime/hysteria/config.yaml"),
)
TREE_SOURCES = (
    ("runtime/material", "var/lib/ezopenpn/runtime/material"),
    ("caddy", "var/lib/ezopenpn/caddy"),
)


class ArchiveError(ValueError):
    pass


def _sha256_stream(stream: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(chunk)
        if size > MAX_FILE_SIZE:
            raise ArchiveError("file exceeds size limit")
        digest.update(chunk)
    return digest.hexdigest(), size


def _sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return _sha256_stream(stream)[0]


def _regular_status(path: Path) -> os.stat_result:
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise ArchiveError(f"regular file required: {path.name}")
    if status.st_size > MAX_FILE_SIZE:
        raise ArchiveError(f"file exceeds size limit: {path.name}")
    return status


def _safe_copy(source: Path, destination: Path) -> tuple[str, int]:
    _regular_status(source)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    source_descriptor = os.open(source, flags)
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    destination_descriptor = os.open(destination, destination_flags, 0o600)
    try:
        opened = os.fstat(source_descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ArchiveError("source changed during copy")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_SIZE:
                raise ArchiveError("file exceeds size limit")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                view = view[written:]
        os.fsync(destination_descriptor)
        return digest.hexdigest(), size
    finally:
        os.close(source_descriptor)
        os.close(destination_descriptor)


def _tree_files(source: Path) -> list[tuple[PurePosixPath, Path]]:
    status = source.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise ArchiveError(f"directory required: {source.name}")
    found: list[tuple[PurePosixPath, Path]] = []
    for current, directory_names, file_names in os.walk(source, followlinks=False):
        current_path = Path(current)
        for name in sorted(directory_names):
            child = current_path / name
            child_status = child.lstat()
            if stat.S_ISLNK(child_status.st_mode) or not stat.S_ISDIR(child_status.st_mode):
                raise ArchiveError(f"unsafe directory member: {name}")
        for name in sorted(file_names):
            child = current_path / name
            _regular_status(child)
            found.append((PurePosixPath(child.relative_to(source).as_posix()), child))
    return found


def _database_metadata(path: Path) -> tuple[str, str]:
    _regular_status(path)
    try:
        with sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True) as connection:
            quick = connection.execute("PRAGMA quick_check").fetchall()
            foreign = connection.execute("PRAGMA foreign_key_check").fetchone()
            schema_rows = connection.execute(
                "SELECT version_num FROM alembic_version"
            ).fetchall()
    except sqlite3.DatabaseError as error:
        raise ArchiveError("database is unreadable") from error
    if quick != [("ok",)] or foreign is not None:
        raise ArchiveError("database integrity check failed")
    if (
        len(schema_rows) != 1
        or len(schema_rows[0]) != 1
        or not isinstance(schema_rows[0][0], str)
    ):
        raise ArchiveError("database schema marker is invalid")
    schema = schema_rows[0][0]
    if schema not in SUPPORTED_SCHEMA_VERSIONS:
        raise ArchiveError("database schema is unsupported")
    return "ok", schema


def _load_install_state(path: Path) -> tuple[str, str]:
    _regular_status(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArchiveError("installation state is invalid") from error
    if not isinstance(value, dict):
        raise ArchiveError("installation state is invalid")
    version = value.get("version")
    public_ipv4 = value.get("public_ipv4")
    if not isinstance(version, str) or not version.startswith("v"):
        raise ArchiveError("installation version is invalid")
    if not isinstance(public_ipv4, str) or not public_ipv4:
        raise ArchiveError("installation address is invalid")
    return version, public_ipv4


def _manifest_bytes(value: dict[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _add_tar_file(archive: tarfile.TarFile, name: str, path: Path, timestamp: int) -> None:
    status = _regular_status(path)
    info = tarfile.TarInfo(name)
    info.size = status.st_size
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = timestamp
    with path.open("rb") as stream:
        archive.addfile(info, stream)


def _write_checksum(archive: Path) -> None:
    checksum = archive.with_name(archive.name + ".sha256")
    descriptor = os.open(
        checksum,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        value = f"{_sha256_file(archive)}  {archive.name}\n".encode()
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_archive(root: Path, snapshot: Path, staging: Path, archive: Path) -> None:
    root = root.absolute()
    staging = staging.absolute()
    archive = archive.absolute()
    stage_status = staging.lstat()
    archive_parent_status = archive.parent.lstat()
    if (
        stat.S_ISLNK(stage_status.st_mode)
        or not stat.S_ISDIR(stage_status.st_mode)
        or stage_status.st_uid != os.geteuid()
        or stat.S_IMODE(stage_status.st_mode) != 0o700
    ):
        raise ArchiveError("staging directory is unsafe")
    if (
        stat.S_ISLNK(archive_parent_status.st_mode)
        or not stat.S_ISDIR(archive_parent_status.st_mode)
        or archive_parent_status.st_uid != os.geteuid()
        or stat.S_IMODE(archive_parent_status.st_mode) & 0o022 != 0
    ):
        raise ArchiveError("archive destination is unsafe")
    payload = staging / "payload"
    payload.mkdir(mode=0o700)
    records: list[dict[str, object]] = []
    total_size = 0

    for archive_name, source_name in FIXED_SOURCES:
        source = snapshot if source_name == "snapshot" else root / source_name
        digest, size = _safe_copy(source, payload / archive_name)
        total_size += size
        records.append({"path": archive_name, "sha256": digest, "size": size})

    for archive_prefix, source_name in TREE_SOURCES:
        source_root = root / source_name
        (payload / archive_prefix).mkdir(parents=True, exist_ok=True, mode=0o700)
        for relative, source in _tree_files(source_root):
            archive_name = str(PurePosixPath(archive_prefix) / relative)
            digest, size = _safe_copy(source, payload / archive_name)
            total_size += size
            records.append({"path": archive_name, "sha256": digest, "size": size})

    if total_size > MAX_TOTAL_SIZE or len(records) > MAX_MEMBERS - 1:
        raise ArchiveError("backup payload exceeds limits")
    records.sort(key=lambda item: str(item["path"]))
    quick_check, schema_version = _database_metadata(
        payload / "database/ezopenpn.sqlite3"
    )
    version, public_ipv4 = _load_install_state(payload / "state/install.json")
    created_at = datetime.now(timezone.utc).replace(microsecond=0)  # noqa: UP017
    manifest: dict[str, object] = {
        "application": "EzOpenPN",
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "files": records,
        "format": FORMAT_VERSION,
        "public_ipv4": public_ipv4,
        "quick_check": quick_check,
        "schema_version": schema_version,
        "version": version,
    }
    manifest_path = staging / "manifest.json"
    manifest_path.write_bytes(_manifest_bytes(manifest))
    os.chmod(manifest_path, 0o600)

    descriptor = os.open(
        archive,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    timestamp = int(created_at.timestamp())
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as raw:  # noqa: SIM117
            descriptor = -1
            with (
                gzip.GzipFile(fileobj=raw, mode="wb", mtime=timestamp) as compressed,
                tarfile.open(fileobj=compressed, mode="w|") as tar,
            ):
                _add_tar_file(tar, "manifest.json", manifest_path, timestamp)
                for record in records:
                    name = str(record["path"])
                    _add_tar_file(tar, f"payload/{name}", payload / name, timestamp)
            raw.flush()
            os.fsync(raw.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.chmod(archive, 0o600)
    try:
        _write_checksum(archive)
    except BaseException:
        archive.unlink(missing_ok=True)
        raise


def _validate_archive_file(path: Path, expected_owner: int) -> None:
    status = _regular_status(path)
    if status.st_uid != expected_owner or stat.S_IMODE(status.st_mode) != 0o600:
        raise ArchiveError("archive owner or mode is invalid")
    checksum = path.with_name(path.name + ".sha256")
    checksum_status = _regular_status(checksum)
    if (
        checksum_status.st_uid != expected_owner
        or stat.S_IMODE(checksum_status.st_mode) != 0o600
        or checksum_status.st_size > 1024
    ):
        raise ArchiveError("archive checksum owner or mode is invalid")
    try:
        value = checksum.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise ArchiveError("archive checksum is unreadable") from error
    expected = f"{_sha256_file(path)}  {path.name}\n"
    if value != expected:
        raise ArchiveError("archive checksum does not match")


def _validated_member_name(name: str) -> PurePosixPath:
    if not name or len(name) > 512 or "\\" in name or name.startswith("/"):
        raise ArchiveError("archive member name is invalid")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveError("archive member escapes its root")
    return path


def _parse_manifest(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_MANIFEST_SIZE:
        raise ArchiveError("manifest exceeds size limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArchiveError("manifest is invalid") from error
    if not isinstance(value, dict) or set(value) != {
        "application",
        "created_at",
        "files",
        "format",
        "public_ipv4",
        "quick_check",
        "schema_version",
        "version",
    }:
        raise ArchiveError("manifest fields are invalid")
    if (
        value["application"] != "EzOpenPN"
        or value["format"] != FORMAT_VERSION
        or value["quick_check"] != "ok"
        or value["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS
        or not isinstance(value["version"], str)
        or not isinstance(value["public_ipv4"], str)
        or not isinstance(value["created_at"], str)
        or not isinstance(value["files"], list)
    ):
        raise ArchiveError("manifest values are invalid")
    return value


def _allowed_payload_path(path: PurePosixPath) -> bool:
    value = path.as_posix()
    fixed = {name for name, _ in FIXED_SOURCES}
    return value in fixed or any(
        value.startswith(f"{prefix}/") for prefix, _ in TREE_SOURCES
    )


def _manifest_records(manifest: dict[str, object]) -> dict[str, tuple[str, int]]:
    raw_records = manifest["files"]
    if not isinstance(raw_records, list) or len(raw_records) > MAX_MEMBERS - 1:
        raise ArchiveError("manifest file list is invalid")
    records: dict[str, tuple[str, int]] = {}
    ordered: list[str] = []
    for raw in raw_records:
        if not isinstance(raw, dict) or set(raw) != {"path", "sha256", "size"}:
            raise ArchiveError("manifest file record is invalid")
        path_value = raw["path"]
        digest = raw["sha256"]
        size = raw["size"]
        if (
            not isinstance(path_value, str)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_FILE_SIZE
        ):
            raise ArchiveError("manifest file metadata is invalid")
        path = _validated_member_name(path_value)
        if not _allowed_payload_path(path) or path_value in records:
            raise ArchiveError("manifest contains an unexpected file")
        records[path_value] = (digest, size)
        ordered.append(path_value)
    if ordered != sorted(ordered):
        raise ArchiveError("manifest file list is not sorted")
    required = {name for name, _ in FIXED_SOURCES}
    if not required.issubset(records):
        raise ArchiveError("manifest is missing a required file")
    return records


def _safe_extract_member(
    source: BinaryIO, destination: Path, expected_digest: str, expected_size: int
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > expected_size or size > MAX_FILE_SIZE:
                raise ArchiveError("archive member size does not match")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if size != expected_size or digest.hexdigest() != expected_digest:
        raise ArchiveError("archive member checksum does not match")


def validate_and_extract(
    archive: Path,
    staging: Path,
    current_state: Path,
    expected_owner: int,
) -> dict[str, object]:
    archive = archive.absolute()
    staging = staging.absolute()
    _validate_archive_file(archive, expected_owner)
    stage_status = staging.lstat()
    if stat.S_ISLNK(stage_status.st_mode) or not stat.S_ISDIR(stage_status.st_mode):
        raise ArchiveError("staging directory is unsafe")
    if any(staging.iterdir()):
        raise ArchiveError("staging directory must be empty")

    with tarfile.open(archive, "r:gz") as tar:
        members: list[tarfile.TarInfo] = []
        names: set[str] = set()
        total_size = 0
        for member in tar:
            if len(members) >= MAX_MEMBERS:
                raise ArchiveError("archive member count is invalid")
            _validated_member_name(member.name)
            if member.name in names or not member.isfile():
                raise ArchiveError("archive contains an unsafe member")
            if member.size < 0 or member.size > MAX_FILE_SIZE:
                raise ArchiveError("archive member exceeds size limit")
            total_size += member.size
            if total_size > MAX_TOTAL_SIZE:
                raise ArchiveError("archive exceeds total size limit")
            names.add(member.name)
            members.append(member)
        if not members:
            raise ArchiveError("archive member count is invalid")
        try:
            manifest_member = tar.getmember("manifest.json")
        except KeyError as error:
            raise ArchiveError("archive manifest is missing") from error
        manifest_stream = tar.extractfile(manifest_member)
        if manifest_stream is None:
            raise ArchiveError("archive manifest is unreadable")
        manifest = _parse_manifest(manifest_stream.read(MAX_MANIFEST_SIZE + 1))
        records = _manifest_records(manifest)
        expected_names = {"manifest.json", *(f"payload/{name}" for name in records)}
        if names != expected_names:
            raise ArchiveError("archive members do not match the manifest")
        for name, (digest, size) in records.items():
            member = tar.getmember(f"payload/{name}")
            stream = tar.extractfile(member)
            if stream is None:
                raise ArchiveError("archive member is unreadable")
            _safe_extract_member(stream, staging / "payload" / name, digest, size)
        for archive_prefix, _ in TREE_SOURCES:
            (staging / "payload" / archive_prefix).mkdir(
                parents=True, exist_ok=True, mode=0o700
            )

    manifest_path = staging / "manifest.json"
    manifest_path.write_bytes(_manifest_bytes(manifest))
    os.chmod(manifest_path, 0o600)
    quick, schema = _database_metadata(staging / "payload/database/ezopenpn.sqlite3")
    if quick != manifest["quick_check"] or schema != manifest["schema_version"]:
        raise ArchiveError("database metadata does not match the manifest")
    archive_version, archive_ip = _load_install_state(
        staging / "payload/state/install.json"
    )
    current_version, current_ip = _load_install_state(current_state)
    if (
        archive_version != manifest["version"]
        or archive_ip != manifest["public_ipv4"]
        or archive_version != current_version
        or archive_ip != current_ip
    ):
        raise ArchiveError("archive belongs to a different installation")
    return manifest


def _apply_owner(path: Path, uid: int, gid: int) -> None:
    if os.geteuid() == 0:
        os.chown(path, uid, gid, follow_symlinks=False)


def _install_file(source: Path, destination: Path, mode: int, uid: int, gid: int) -> None:
    _regular_status(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        f".{destination.name}.restore-{os.getpid()}-{os.urandom(4).hex()}"
    )
    try:
        _safe_copy(source, temporary)
        os.chmod(temporary, mode)
        _apply_owner(temporary, uid, gid)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _copy_tree(source: Path, destination: Path, uid: int, gid: int) -> None:
    source_status = source.lstat()
    if stat.S_ISLNK(source_status.st_mode) or not stat.S_ISDIR(source_status.st_mode):
        raise ArchiveError("restore tree is invalid")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.restore-", dir=destination.parent)
    )
    old = destination.with_name(
        f".{destination.name}.previous-{os.getpid()}-{os.urandom(4).hex()}"
    )
    moved_old = False
    try:
        for relative, item in _tree_files(source):
            target = temporary / relative.as_posix()
            _safe_copy(item, target)
        for current, directories, files in os.walk(temporary):
            current_path = Path(current)
            os.chmod(current_path, 0o700)
            _apply_owner(current_path, uid, gid)
            for name in files:
                child = current_path / name
                os.chmod(child, 0o600)
                _apply_owner(child, uid, gid)
            for name in directories:
                child = current_path / name
                os.chmod(child, 0o700)
                _apply_owner(child, uid, gid)
        if destination.exists():
            if destination.is_symlink() or not destination.is_dir():
                raise ArchiveError("restore destination is unsafe")
            os.replace(destination, old)
            moved_old = True
        os.replace(temporary, destination)
        if moved_old:
            shutil.rmtree(old)
    except BaseException:
        if moved_old and not destination.exists() and old.exists():
            os.replace(old, destination)
        raise
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
        if old.exists():
            shutil.rmtree(old)


def apply_payload(root: Path, staging: Path) -> None:
    root = root.absolute()
    payload = staging.absolute() / "payload"
    manifest = _parse_manifest((staging / "manifest.json").read_bytes())
    records = _manifest_records(manifest)
    for name, (digest, size) in records.items():
        path = payload / name
        status = _regular_status(path)
        if status.st_size != size or _sha256_file(path) != digest:
            raise ArchiveError("staged payload changed before restore")

    fixed_destinations = (
        (
            "database/ezopenpn.sqlite3",
            "var/lib/ezopenpn/control/ezopenpn.sqlite3",
            0o600,
            10001,
            10001,
        ),
        ("configuration/control.toml", "etc/ezopenpn/control.toml", 0o640, 0, 10001),
        ("configuration/Caddyfile", "etc/ezopenpn/Caddyfile", 0o640, 0, 11003),
        ("configuration/compose.yaml", "etc/ezopenpn/compose.yaml", 0o640, 0, 0),
        ("configuration/stack.env", "etc/ezopenpn/stack.env", 0o640, 0, 0),
        ("secrets/master.key", "var/lib/ezopenpn/secrets/master.key", 0o600, 10001, 10001),
        (
            "secrets/hysteria-api.key",
            "var/lib/ezopenpn/secrets/hysteria-api.key",
            0o600,
            10001,
            10001,
        ),
        (
            "secrets/hysteria-obfs.key",
            "var/lib/ezopenpn/secrets/hysteria-obfs.key",
            0o600,
            10001,
            10001,
        ),
        (
            "runtime/xray/config.json",
            "var/lib/ezopenpn/runtime/xray/config.json",
            0o600,
            10002,
            11001,
        ),
        (
            "runtime/hysteria/config.yaml",
            "var/lib/ezopenpn/runtime/hysteria/config.yaml",
            0o600,
            10003,
            11003,
        ),
    )
    database = root / "var/lib/ezopenpn/control/ezopenpn.sqlite3"
    database.with_name(database.name + "-wal").unlink(missing_ok=True)
    database.with_name(database.name + "-shm").unlink(missing_ok=True)
    for source_name, destination_name, mode, uid, gid in fixed_destinations:
        _install_file(payload / source_name, root / destination_name, mode, uid, gid)
    _copy_tree(
        payload / "runtime/material",
        root / "var/lib/ezopenpn/runtime/material",
        0,
        0,
    )
    _copy_tree(payload / "caddy", root / "var/lib/ezopenpn/caddy", 10004, 11003)


def cleanup_staging(path: Path, parent: Path) -> None:
    path = path.absolute()
    parent = parent.absolute()
    if path.parent != parent or not path.name.startswith(".stage."):
        raise ArchiveError("cleanup path is outside the staging root")
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise ArchiveError("cleanup path is unsafe")
    shutil.rmtree(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--root", type=Path, required=True)
    create.add_argument("--snapshot", type=Path, required=True)
    create.add_argument("--staging", type=Path, required=True)
    create.add_argument("--archive", type=Path, required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--archive", type=Path, required=True)
    validate.add_argument("--staging", type=Path, required=True)
    validate.add_argument("--current-state", type=Path, required=True)
    validate.add_argument("--expected-owner", type=int, required=True)
    apply_command = commands.add_parser("apply")
    apply_command.add_argument("--root", type=Path, required=True)
    apply_command.add_argument("--staging", type=Path, required=True)
    cleanup = commands.add_parser("cleanup")
    cleanup.add_argument("--path", type=Path, required=True)
    cleanup.add_argument("--parent", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "create":
            create_archive(
                arguments.root,
                arguments.snapshot,
                arguments.staging,
                arguments.archive,
            )
        elif arguments.command == "validate":
            manifest = validate_and_extract(
                arguments.archive,
                arguments.staging,
                arguments.current_state,
                arguments.expected_owner,
            )
            print(_manifest_bytes(manifest).decode(), end="")
        elif arguments.command == "apply":
            apply_payload(arguments.root, arguments.staging)
        elif arguments.command == "cleanup":
            cleanup_staging(arguments.path, arguments.parent)
        else:
            return 2
    except (ArchiveError, OSError, tarfile.TarError, json.JSONDecodeError):
        print("Операция с резервной копией отклонена.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
