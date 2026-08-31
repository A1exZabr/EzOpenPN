#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

mode="${1:-}"
case "$mode" in
  capture | verify) ;;
  *) exit 2 ;;
esac

compose=(
  docker compose
  --env-file /etc/ezopenpn/stack.env
  -f /etc/ezopenpn/compose.yaml
  --project-name ezopenpn
)

if [[ "$mode" == capture ]]; then
  "${compose[@]}" exec -T control python - <<'PY'
from ezopenpn.models import ProfileState
from ezopenpn.web.app import create_runtime_app

application = create_runtime_app()
services = application.state.services
active = [
    record for record in services.profiles.list() if record.state is ProfileState.ACTIVE
]
if not active:
    created = services.runtime.create("Проверка повторной установки")
    if created.state is not ProfileState.ACTIVE:
        raise SystemExit(1)
PY
fi

profile_identity="$("${compose[@]}" exec -T control python - <<'PY'
import hashlib
import json
import sqlite3

from ezopenpn.config import SecretFiles, Settings
from ezopenpn.db import create_engine_for
from ezopenpn.models import ProfileState
from ezopenpn.profiles.links import ProfileLinkService, TransportLinkConfig, encode_url_secret
from ezopenpn.profiles.repository import ProfileRepository
from ezopenpn.security.secrets import SecretCipher

settings = Settings.load(__import__("pathlib").Path("/etc/ezopenpn/control.toml"))
secrets = SecretFiles.load(
    settings.paths.master_key_path,
    settings.paths.hysteria_api_path,
    settings.paths.hysteria_obfs_path,
)
cipher = SecretCipher(secrets.master_key)
engine = create_engine_for(settings.database_path)
repository = ProfileRepository(engine, cipher)
links = ProfileLinkService(
    repository,
    cipher,
    TransportLinkConfig(
        host=settings.public_ip,
        reality_public_key=settings.xray.reality_public_key,
        reality_server_name=settings.xray.reality_server_name,
        reality_short_id=settings.xray.reality_short_id,
        xhttp_path=settings.xray.xhttp_path,
        hysteria_obfs_password=encode_url_secret(secrets.hysteria_obfs_secret),
    ),
)
active = [record for record in repository.list() if record.state is ProfileState.ACTIVE]
if not active:
    raise SystemExit(1)
bundles = []
for record in active:
    bundle = links.bundle_for_record(record)
    bundles.append(
        [str(record.profile_id), bundle.combined_url, bundle.vless_link, bundle.hysteria_link]
    )
with sqlite3.connect(settings.database_path) as connection:
    cursor = connection.execute("SELECT * FROM profiles ORDER BY id")
    columns = [item[0] for item in cursor.description]
    rows = []
    for raw in cursor.fetchall():
        values = [
            {"bytes": value.hex()} if isinstance(value, bytes) else value for value in raw
        ]
        rows.append(dict(zip(columns, values)))
engine.dispose()

def digest(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    return hashlib.sha256(payload).hexdigest()

print(
    json.dumps(
        {
            "profile_links_sha256": digest(sorted(bundles)),
            "profile_rows_sha256": digest(rows),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
PY
)"

baseline=/var/lib/ezopenpn/operations/vm-idempotency-baseline.json
python3 - \
  "$mode" "$baseline" /var/lib/ezopenpn/secrets/master.key \
  /var/lib/ezopenpn/install.json "$profile_identity" <<'PY'
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

mode = sys.argv[1]
baseline = Path(sys.argv[2])
master = Path(sys.argv[3])
state = Path(sys.argv[4])
profile_identity = json.loads(sys.argv[5])
install_state = json.loads(state.read_text(encoding="utf-8"))
identity = {
    **profile_identity,
    "master_sha256": hashlib.sha256(master.read_bytes()).hexdigest(),
    "panel_url": f"https://{install_state['public_ipv4']}:9443",
}
if mode == "capture":
    temporary = baseline.with_name(baseline.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(identity, stream, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, baseline)
    finally:
        temporary.unlink(missing_ok=True)
else:
    expected = baseline.read_bytes()
    actual = (json.dumps(identity, separators=(",", ":"), sort_keys=True) + "\n").encode()
    if not hmac.compare_digest(expected, actual):
        raise SystemExit(1)
    baseline.unlink()
PY
