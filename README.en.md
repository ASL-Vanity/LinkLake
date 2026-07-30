# LinkLake v2

[中文](README.md) | English

LinkLake is a cross-platform secure tunnel platform implemented from scratch in Rust, with independent core, server, client, and management-plane components.

LinkLake's code implementation, automated tests, and project documentation were produced by OpenAI GPT-5.6; the project owner is responsible for requirements, infrastructure authorization, and final acceptance.

The current release completes TCP and UDP productionization, HTTP host routing, and the first stage of native HTTPS with ACME certificate automation. P2P is not implemented yet.

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

## Production UDP capabilities

The current UDP implementation includes:

- Persistent UDP policies with create, enable, disable, delete, exact client authorization, and online state
- Public UDP-to-local UDP session mapping with datagrams carried over a QUIC relay data channel
- Per-policy session limits, idle session expiration, a global session limit, and aggregate bandwidth limits
- Datagram fragmentation/reassembly protection and counters for oversized, malformed, rate-limited, and session-limited drops
- QUIC Retry address validation, one-time short-lived tickets, attachment timeouts, and global/per-source pending and active attachment limits
- Per-source active-session caps, source/policy/global new-session rate limits, and a shared client queue-memory budget
- Bidirectional packet and byte counters, reassembly/session timeouts, and transport errors
- Bilingual Web UI management and multi-policy `[[udp_tunnels]]` client configuration

TCP and UDP have separate operating-system port namespaces, so TCP `32001` and UDP `32001` may coexist. A UDP public port can belong to only one UDP policy. The current UDP public port range is `32000-32999`.

The UDP relay is disabled by default. Setting `LINKLAKE_UDP_RELAY_BIND` enables it and also requires an externally reachable `LINKLAKE_UDP_RELAY_ENDPOINT` plus `LINKLAKE_UDP_RELAY_SERVER_NAME` matching the control-channel certificate. UDP has completed automated local acceptance and end-to-end acceptance across an independent public test host, a Linux server, and a Windows client.

The first UDP release listens for public service traffic on IPv4 only (`0.0.0.0`). Whether the QUIC relay also serves IPv6 depends on the bind address in `LINKLAKE_UDP_RELAY_BIND`. The client creates its local-target socket in the target address family, so the local target can be IPv4 or IPv6. Expose only the relay and policy UDP ports that are needed, and retain cloud-firewall or upstream DDoS protection.

UDP and QUIC DATAGRAM are both best-effort transports; LinkLake does not turn UDP into a reliable byte stream. Automated local tests cover datagrams up to `65507` bytes, but Internet MTU, IP fragmentation, carrier networks, proxies, and firewalls can discard larger original UDP datagrams. When the application controls packet size, `1200` bytes or less is a conservative Internet-facing default; add application-level retries, sequence numbers, or loss tolerance when required.

## HTTP/HTTPS host routing

- Routes requests by HTTP Host and TLS SNI to a selected client and its local HTTP service
- Persists HTTP/HTTPS route policies in SQLite with create, enable, disable, delete, and online-state management
- Configures a maximum concurrent connection count per route and records requests, failures, traffic, and pairing timeouts
- Terminates TLS natively, selects certificates by exact SNI, and rejects missing or unknown SNI and SNI/Host mismatches
- Supports Let's Encrypt production, staging, and custom ACME directories with HTTP-01 issuance and automatic renewal
- Provides bilingual ACME settings, per-route TLS controls, immediate issue/renew actions, certificate status, and errors in the Web UI
- Can return a `308` HTTP-to-HTTPS redirect after the certificate is active; the HTTP-01 challenge path always remains reachable over plain HTTP
- The first stage supports HTTP/1.1 and WebSocket/WSS; wildcard certificates that require DNS-01 are not supported

Before using a route, point its DNS record to the LinkLake server. HTTP-01 requires public port 80 to reach `LINKLAKE_HTTP_BIND` with the original Host, while public port 443 must deliver the TLS stream unchanged to `LINKLAKE_HTTPS_BIND` so LinkLake can select the certificate by SNI and terminate TLS.

If an upstream Nginx instance already terminates business TLS on port 443, LinkLake-managed certificates are not used. Let LinkLake bind port 443 directly, or use Nginx `stream` SNI routing for TCP pass-through; the management UI can remain on a separate management TLS entry point. Port 80 may use a regular reverse proxy, but it must preserve Host and must not intercept `/.well-known/acme-challenge/`.

## Run locally

```powershell
$env:LINKLAKE_ENROLLMENT_TOKEN = "choose-a-long-random-token"
$env:LINKLAKE_ADMIN_USERNAME = "admin"
$env:LINKLAKE_ADMIN_PASSWORD = "choose-a-password-with-at-least-12-characters"
$env:LINKLAKE_DATA_DIR = "C:\LinkLake\data"
$env:LINKLAKE_HTTP_BIND = "127.0.0.1:32102"
$env:LINKLAKE_HTTPS_BIND = "127.0.0.1:32103"
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

For multiple TCP/UDP tunnels and HTTP host routes, use [examples/linklake-client.toml](examples/linklake-client.toml). UDP uses `[[udp_tunnels]]`, while HTTP routes use `[[http_routes]]`; public ports, names, targets, and hostnames must exactly match the policies created in the Web UI:

```powershell
cargo run -p linklake-client -- run --config .\linklake-client.toml
```

Remote control connections also require `control_ca_cert` and `control_server_name`. Public TCP and UDP ports both use `32000-32999`; the two protocols may use the same numeric port.

## Management and metrics

- Public health endpoint: `GET /api/v1/health`
- Authenticated metrics endpoint: `GET /api/v1/metrics`
- TCP policies: `GET/POST /api/v1/tcp-tunnels`
- UDP policies: `GET/POST /api/v1/udp-tunnels`
- Enable or disable a UDP policy: `POST /api/v1/udp-tunnels/:id/enabled`
- Delete a UDP policy: `DELETE /api/v1/udp-tunnels/:id`
- HTTP/HTTPS routes: `GET/POST /api/v1/http-routes`
- Enable or disable a route: `POST /api/v1/http-routes/:id/enabled`
- Route TLS settings: `PUT /api/v1/http-routes/:id/tls`
- Immediate issue or renewal: `POST /api/v1/http-routes/:id/certificate/issue|renew`
- ACME settings: `GET/PUT /api/v1/acme/config`
- Delete a route: `DELETE /api/v1/http-routes/:id`
- The Web UI configures TCP aggregate bandwidth, UDP aggregate bandwidth/session limits/idle timeouts, TCP/HTTP connection limits, the ACME environment, and HTTPS per route
- Metrics cover UDP sessions, packets, traffic, drops, and timeouts, plus HTTP/HTTPS traffic and failures, TLS handshake failures, managed, expiring, and expired certificates, ACME orders, renewals, and HTTP-01 challenges
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

ACME account credentials and certificate private keys live under `LINKLAKE_DATA_DIR/acme` and `LINKLAKE_DATA_DIR/certificates`; they are not included in the SQLite-only `backup` output. Back up those directories separately with encryption for full disaster recovery, and treat every database and certificate backup as sensitive credentials.

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

Example server configuration for enabling the UDP relay:

```text
LINKLAKE_UDP_RELAY_BIND=0.0.0.0:32104
LINKLAKE_UDP_RELAY_ENDPOINT=udp.example.com:32104
LINKLAKE_UDP_RELAY_SERVER_NAME=udp.example.com
```

Relay QUIC TLS reuses `LINKLAKE_CONTROL_CERT_PATH` and `LINKLAKE_CONTROL_KEY_PATH`. Open the relay UDP port and the UDP ports actually assigned to policies in both the cloud security group and the host firewall; do not expose the complete `32000-32999/udp` range unless it is required.

Public UDP service ports are IPv4-only in this first release. Binding the relay to IPv6 alone does not enable IPv6 access to policy ports.

## Build and verify

The repository pins Rust `1.88.0` through `rust-toolchain.toml` and dependencies through `Cargo.lock`. Install the toolchain with rustup; CI uses the same version on Windows and Linux.

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\tcp-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\udp-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\http-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-windows-package.ps1
```

On Linux:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
pwsh -NoProfile -File ./tests/https-e2e.ps1
bash scripts/package-linux.sh
bash scripts/verify-linux-package.sh
```

The TCP E2E suite covers real binary echo traffic, bandwidth limits, connection limits, reconnects, policy lifecycle, pairing timeout, and metrics. The UDP E2E suite covers real datagram echo from `0` through `65507` bytes, multiple sessions, rate-limit drops, idle expiration, fragmentation/reassembly, policy lifecycle, reconnects, same-numbered TCP/UDP ports, and metrics. Production acceptance additionally covers an independent public test host, a Linux server, and a Windows client. The HTTP E2E suite covers Host routing, request and response transfer, connection limits, client reconnects, policy lifecycle, and metrics. Linux CI runs HTTPS/ACME E2E against a local Pebble service, covering HTTP-01, SNI, issuance and renewal, HTTPS forwarding, redirects, persistence, failure recovery, and certificate metrics without contacting a public certificate authority.

Packaging scripts honor `SOURCE_DATE_EPOCH`. With the same timestamp, source, toolchain, target platform, and locked dependencies, archive ordering, timestamps, and release metadata remain stable. Windows produces a ZIP plus SHA-256; Linux produces a tar.gz plus SHA-256.

`.github/workflows/ci.yml` runs formatting, Clippy, unit tests, script syntax checks, Windows TCP/UDP/HTTP E2E, and Linux Pebble HTTPS/ACME E2E for pushes and pull requests. `.github/workflows/release.yml` builds both platform packages when manually dispatched and creates or updates a GitHub Release for `v*` tags.

## Roadmap

1. HTTP host routing: first stage complete
2. HTTPS termination and certificate automation: first stage complete
3. UDP tunnel productionization: complete
4. Flutter management client
5. Multi-node and P2P operation with explicit relay fallback

The project owner will select a license after all planned functionality is complete.
