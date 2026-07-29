# LinkLake v2

[中文](README.md) | English

LinkLake is a cross-platform secure tunnel platform implemented from scratch in Rust, with independent core, server, client, and management-plane components.

LinkLake's code implementation, automated tests, and project documentation were produced by OpenAI GPT-5.6; the project owner is responsible for requirements, infrastructure authorization, and final acceptance.

The current release completes TCP productionization and the first stage of HTTP host routing. Automated HTTPS certificates, UDP, and P2P are not implemented yet.

## Production TCP capabilities

- TLS control channel, Argon2 client tokens, and exact policy authorization
- Application-level heartbeats, half-open connection detection, and client TLS session reuse
- Reconnects with exponential backoff and jitter
- Per-policy, global, and pending-pair connection limits
- Aggregate bidirectional bandwidth limit per policy
- Immediate listener and active-connection shutdown on policy disable/delete
- Traffic, failure, rejection, timeout, reconnect, and authentication metrics
- SQLite persistence, audit, online backup, and integrity-checked restore
- Bilingual Web UI, password login, secure cookies, and five-second refresh
- Native Windows services and Linux systemd units
- Hourly server/client log rotation with 168 files retained by default

## HTTP host routing

- Routes requests by Host to a selected client and its local HTTP service
- Persists HTTP route policies in SQLite with create, enable, disable, delete, and online-state management
- Configures a maximum concurrent connection count per route and records requests, failures, traffic, and pairing timeouts
- Provides bilingual HTTP route management in the Web UI
- The first stage handles HTTP only; HTTPS termination and automated certificate issuance and renewal remain planned

Before using a route, point its DNS record to the LinkLake server and ensure the public HTTP entry point can reach the server's configured HTTP listener.

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

The client token is shown once. For a TCP tunnel, create an exactly matching policy in the Web UI, then run:

```powershell
cargo run -p linklake-client -- agent `
  --control 127.0.0.1:32101 `
  --client-id <client-id> `
  --token <client-token> `
  --public-port 32001 `
  --target 127.0.0.1:8080 `
  --name development-tcp
```

For multiple TCP tunnels and HTTP host routes, use [examples/linklake-client.toml](examples/linklake-client.toml). HTTP routes use `[[http_routes]]`; `hostname` must exactly match the hostname created in the Web UI:

```powershell
cargo run -p linklake-client -- run --config .\linklake-client.toml
```

Remote control connections also require `control_ca_cert` and `control_server_name`. Public TCP ports currently use `32000-32999`.

## Management and metrics

- Public health endpoint: `GET /api/v1/health`
- Authenticated metrics endpoint: `GET /api/v1/metrics`
- TCP policies: `GET/POST /api/v1/tcp-tunnels`
- HTTP routes: `GET/POST /api/v1/http-routes`
- Enable or disable an HTTP route: `POST /api/v1/http-routes/:id/enabled`
- Delete an HTTP route: `DELETE /api/v1/http-routes/:id`
- The Web UI configures TCP aggregate bandwidth limits and TCP/HTTP connection limits
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\http-e2e.ps1
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

The TCP E2E suite covers real binary echo traffic, bandwidth limits, connection limits, reconnects, policy lifecycle, pairing timeout, and metrics. The HTTP E2E suite covers Host routing, request and response transfer, connection limits, client reconnects, policy lifecycle, and metrics.

Packaging scripts honor `SOURCE_DATE_EPOCH`. With the same timestamp, source, toolchain, target platform, and locked dependencies, archive ordering, timestamps, and release metadata remain stable. Windows produces a ZIP plus SHA-256; Linux produces a tar.gz plus SHA-256.

`.github/workflows/ci.yml` runs formatting, Clippy, unit tests, script syntax checks, and Windows TCP/HTTP E2E for pushes and pull requests. `.github/workflows/release.yml` builds both platform packages when manually dispatched and creates or updates a GitHub Release for `v*` tags.

## Roadmap

1. HTTP host routing: first stage complete
2. HTTPS termination and certificate automation
3. UDP tunnels
4. Flutter management client
5. Multi-node and P2P operation with explicit relay fallback

The project owner will select a license after all planned functionality is complete.
