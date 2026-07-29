# LinkLake v2

[中文](README.md) | English

LinkLake is a cross-platform secure tunnel platform implemented from scratch in Rust, with independent core, server, client, and management-plane components.

The current release completes TCP productionization. UDP, HTTP/HTTPS host routing, and P2P are not implemented yet.

## Production TCP capabilities

- TLS control channel, Argon2 client tokens, and exact policy authorization
- Reconnects with exponential backoff and jitter
- Per-policy, global, and pending-pair connection limits
- Aggregate bidirectional bandwidth limit per policy
- Immediate listener and active-connection shutdown on policy disable/delete
- Traffic, failure, rejection, timeout, reconnect, and authentication metrics
- SQLite persistence, audit, online backup, and integrity-checked restore
- Bilingual Web UI, password login, secure cookies, and five-second refresh
- Native Windows services and Linux systemd units
- Hourly server/client log rotation with 168 files retained by default

## Run locally

```powershell
$env:LINKLAKE_ENROLLMENT_TOKEN = "choose-a-long-random-token"
$env:LINKLAKE_ADMIN_USERNAME = "admin"
$env:LINKLAKE_ADMIN_PASSWORD = "choose-a-password-with-at-least-12-characters"
$env:LINKLAKE_DATA_DIR = "C:\LinkLake\data"
cargo run -p linklake-server
```

Open `http://127.0.0.1:32100`. The administrator password is only used during initial setup; SQLite stores its Argon2 hash.

For loopback development only, `LINKLAKE_ALLOW_INSECURE_DEFAULT_ADMIN=1` creates `admin / 123456` and forces an immediate password change. Public binds reject this option and require TLS for both management and control listeners.

## Enroll and run a client

```powershell
cargo run -p linklake-client -- enroll `
  --server http://127.0.0.1:32100 `
  --token $env:LINKLAKE_ENROLLMENT_TOKEN `
  --name dev-machine
```

The client token is shown once. Create an exactly matching TCP policy in the Web UI, then run:

```powershell
cargo run -p linklake-client -- agent `
  --control 127.0.0.1:32101 `
  --client-id <client-id> `
  --token <client-token> `
  --public-port 32001 `
  --target 127.0.0.1:8080 `
  --name development-tcp
```

For multiple tunnels, use [examples/linklake-client.toml](examples/linklake-client.toml):

```powershell
cargo run -p linklake-client -- run --config .\linklake-client.toml
```

Remote control connections also require `control_ca_cert` and `control_server_name`. Public TCP ports currently use `32000-32999`.

## Management and metrics

- Public health endpoint: `GET /api/v1/health`
- Authenticated metrics endpoint: `GET /api/v1/metrics`
- The Web UI configures connection and aggregate bandwidth limits
- `LINKLAKE_MANAGEMENT_TOKEN` is an optional automation Bearer token, not a Web login credential

Set logs with `LINKLAKE_LOG_DIR`. The server defaults to `LINKLAKE_DATA_DIR/logs`; the client writes to the console when unset, while service installers configure a rotating log directory.

## Database backup and restore

Online backup:

```powershell
linklake-server backup --data-dir C:\LinkLake\data --output D:\Backups\linklake.sqlite3
```

Stop the service before restoring:

```powershell
linklake-server restore --data-dir C:\LinkLake\data --input D:\Backups\linklake.sqlite3
```

Restore validates SQLite integrity and preserves the old database as `linklake.sqlite3.pre-restore-<timestamp>`.

## Production installation

Windows release package:

- `windows/install-server.ps1` installs and starts `LinkLakeServer`
- `windows/install-client.ps1` installs and starts `LinkLakeClient`
- `windows/uninstall.ps1` removes services while preserving programs and data

Linux release package:

```sh
sudo ./systemd/install-linux.sh server
sudo ./systemd/install-linux.sh client
```

The installer enables but does not start services with placeholder configuration. Edit `/etc/linklake/server.env` or `/etc/linklake/client.toml`, then run `systemctl start`.

## Build and verify

The repository pins Rust `1.88.0` through `rust-toolchain.toml` and dependencies through `Cargo.lock`. Install the toolchain with rustup; CI uses the same version on Windows and Linux.

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\tcp-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-windows-package.ps1
```

On Linux:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
bash scripts/package-linux.sh
bash scripts/verify-linux-package.sh
```

The E2E suite covers real binary echo traffic, bandwidth limits, connection limits, reconnects, policy lifecycle, pairing timeout, and metrics.

Packaging scripts honor `SOURCE_DATE_EPOCH`. With the same timestamp, source, toolchain, target platform, and locked dependencies, archive ordering, timestamps, and release metadata remain stable. Windows produces a ZIP plus SHA-256; Linux produces a tar.gz plus SHA-256.

`.github/workflows/ci.yml` runs formatting, Clippy, unit tests, script syntax checks, and Windows TCP E2E for pushes and pull requests. `.github/workflows/release.yml` builds both platform packages when manually dispatched and creates or updates a GitHub Release for `v*` tags.

## Roadmap

1. HTTP/HTTPS host routing and certificate automation
2. UDP tunnels
3. Flutter management client
4. Multi-node and P2P operation with explicit relay fallback

The project owner will select a license after all planned functionality is complete.
