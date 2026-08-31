# Deployment layout for maintainers

The installer renders this directory into `/etc/ezopenpn` and creates every bind source before Compose starts. Compose is intentionally unable to create missing host paths.

Host ownership and modes:

| Path | Owner | Mode | Purpose |
| --- | --- | --- | --- |
| `/etc/ezopenpn/control.toml` | `root:10001` | `0640` | Non-secret control settings |
| `/etc/ezopenpn/Caddyfile` | `root:10004` | `0640` | Gateway policy |
| `/var/lib/ezopenpn/control` | `10001:10001` | `0700` | SQLite data |
| `/var/lib/ezopenpn/secrets/*.key` | `10001:10001` | `0600` | Exact 32-byte secret files |
| `/var/lib/ezopenpn/runtime/xray/config.json` | `10002:11001` | `0600` | Runtime configuration |
| `/var/lib/ezopenpn/runtime/xray-run` | `10002:11001` | `0750` | Narrow supervisor socket |
| `/var/lib/ezopenpn/runtime/hysteria/config.yaml` | `10003:11003` | `0600` | Runtime configuration |
| `/var/lib/ezopenpn/caddy` | `10004:11003` | `0700` | ACME account and certificate storage |
| `/var/lib/ezopenpn/runtime/hysteria-certs` | `10004:11003` | `0750` | Atomic certificate export |

The gateway and certificate exporter deliberately share UID 10004. The exporter sees the gateway storage read-only and has no network. Hysteria2 receives only the exported directory read-only through group 11003.

Only the four documented bindings appear on the host. The control listener, Xray management listener and Hysteria2 statistics listener remain on the internal bridge.
