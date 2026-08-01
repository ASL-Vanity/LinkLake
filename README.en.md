# LinkLake v2

[中文](README.md) | English

LinkLake is a cross-platform secure tunnel platform implemented from scratch in Rust, with independent core, server, client, and management-plane components.

LinkLake's code implementation, automated tests, and project documentation were produced by OpenAI GPT-5.6; the project owner is responsible for requirements, infrastructure authorization, and final acceptance.

The current release completes production TCP and UDP, multi-port/range forwarding, secret tunnels, byte-preserving TLS SNI pass-through, multi-node P2P direct paths with explicit server-relay fallback, SOCKS5 TCP/UDP, HTTP forward proxy/CONNECT, HTTP host routing, and the first stage of native HTTPS with ACME certificate automation.

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

TCP and UDP have separate operating-system port namespaces, so TCP `32001` and UDP `32001` may coexist. A UDP public port can belong to only one UDP policy. The default public range is `32000-32999`; the server can independently configure TCP and UDP with single ports or multiple ranges anywhere in `1-65535`.

The UDP relay is disabled by default. Setting `LINKLAKE_UDP_RELAY_BIND` enables it and also requires an externally reachable `LINKLAKE_UDP_RELAY_ENDPOINT` plus `LINKLAKE_UDP_RELAY_SERVER_NAME` matching the control-channel certificate. UDP has completed automated local acceptance and end-to-end acceptance across an independent public test host, a Linux server, and a Windows client.

The first UDP release listens for public service traffic on IPv4 only (`0.0.0.0`). Whether the QUIC relay also serves IPv6 depends on the bind address in `LINKLAKE_UDP_RELAY_BIND`. The client creates its local-target socket in the target address family, so the local target can be IPv4 or IPv6. Expose only the relay and policy UDP ports that are needed, and retain cloud-firewall or upstream DDoS protection.

UDP and QUIC DATAGRAM are both best-effort transports; LinkLake does not turn UDP into a reliable byte stream. Automated local tests cover datagrams up to `65507` bytes, but Internet MTU, IP fragmentation, carrier networks, proxies, and firewalls can discard larger original UDP datagrams. When the application controls packet size, `1200` bytes or less is a conservative Internet-facing default; add application-level retries, sequence numbers, or loss tolerance when required.

## Multi-port and port-range forwarding

- TCP and UDP port groups accept single ports, comma-separated lists, ascending inclusive ranges, and mixed expressions such as `32001,32010-32012`
- Public and target expressions map one-to-one in expansion order. For example, public `32001,32010-32012` maps to target `2333,2400-2402`; the expanded counts must match
- Expressions are normalized before persistence. Descending ranges, duplicate ports, out-of-range values, and ambiguous syntax are rejected; one group may expand to at most 256 mappings
- Public ports must be allowed by the server policy and must not be reserved. Target ports may use `1-65535`. The target host is entered separately as a domain, IPv4 address, or IPv6 address without a port
- TCP groups share the TCP namespace with regular TCP tunnels, SOCKS5, HTTP forward proxies, and other TCP groups. UDP groups share the UDP namespace with regular UDP tunnels, SOCKS5 UDP, and other UDP groups
- TCP and UDP may use the same numeric public ports. Group creation is transactional, so any conflicting mapping rejects the entire group
- Server-managed mode expands a group into the existing TCP/UDP client tasks. The Web UI manages whole-group lifecycle and reports online mappings, connections or sessions, and traffic

Local and report-only modes may also declare:

```toml
[[port_groups]]
name = "game-range"
protocol = "tcp"
public_ports = "32001,32010-32012"
target_host = "127.0.0.1"
target_ports = "2333,2400-2402"
```

### Public port policy

The compatible default permits only `32000-32999`. Servers support these environment variables:

```text
# Shared TCP/UDP default. Single ports, comma-separated lists, and ascending ranges are accepted.
LINKLAKE_PUBLIC_PORT_RANGES=80,443,10000-19999,30000-65535
# Optional protocol-specific overrides.
LINKLAKE_TCP_PUBLIC_PORTS=80,443,10000-65535
LINKLAKE_UDP_PUBLIC_PORTS=10000-65535
# TCP port 22 is reserved by default; add host SSH, database, or other service ports here.
LINKLAKE_RESERVED_TCP_PORTS=22,25,3306
LINKLAKE_RESERVED_UDP_PORTS=53
```

The actual management API, control, HTTP/HTTPS, TLS-SNI, and UDP-relay listener ports are automatically added to the corresponding reserved set. The Web UI reads `GET /api/v1/public-port-policy` and displays the active policy in forwarding forms. If a new range excludes a policy already stored in the database, startup fails with the conflicting policy instead of silently leaving it offline. Linux needs root or `CAP_NET_BIND_SERVICE` for `1-1023`; the packaged systemd unit grants only that capability, while manual runs must arrange it separately. Cloud security groups, host firewalls, and other listeners still determine actual reachability.

## Secret tunnels

- The visitor listens only on a local address and reaches the provider through the LinkLake TLS control channel; no public business port is opened on the server
- The Web UI selects the provider client and local target and may restrict access to one visitor client
- Policy creation returns a high-entropy `lls_...` access key once; SQLite stores only its SHA-256 hash
- Provider-side `[[secret_tunnels]]` entries can be delivered through server-managed configuration, while visitor-side `[[secret_visitors]]` entries and access keys always remain local
- Policy lifecycle, provider reconnects, per-policy/global/pending connection limits, and aggregate bandwidth limits are enforced
- The Web UI reports online state, active/total/rejected connections, bidirectional traffic, pairing timeouts, transfer errors, and lifetime timeouts

Typical uses include RDP, SSH, databases, internal administration panels, and temporary TCP services that should not expose a public port. Remote deployments must configure control-channel TLS. An access key does not replace client identity: the visitor must still authenticate with an enrolled client ID and token.

## Multi-node P2P direct paths

- A provider uses `p2p_bind` in `[client]` for both TCP and Iroh QUIC/UDP and `p2p_endpoint` for its reachable TCP address; both settings are required together. `p2p_tcp_enabled` and `p2p_iroh_enabled` can disable either transport, but at least one must remain enabled
- Iroh QUIC candidates automatically publish local, STUN/QAD public-mapping, and router port-mapping addresses. With `p2p_relay_url`, a self-hosted Iroh rendezvous service assists address discovery, NAT mapping detection, and UDP hole punching
- The server persists a node directory. Providers refresh every 30 seconds and records remain fresh for 120 seconds; the Web UI and `GET /api/v1/p2p/nodes` show candidates, UDP capability, mapping behavior, port mapping, rendezvous URL, and age
- `[[secret_visitors]]` defaults to `prefer_direct = true`, so the visitor first requests an HMAC-SHA256 ticket bound to the provider, visitor, target address, and protocol version; set it to `false` to always use relay
- Tickets expire after 30 seconds and are single-use. The provider validates them online over its authenticated control connection, rejecting expiration, replay, signature changes, and provider mismatch
- Missing candidates, timeout, refusal, authentication failure, and protocol failure are reported explicitly before the visitor falls back to the existing secret-tunnel server relay; offers, direct successes, and relay fallbacks have separate metrics and audit events
- Visitors race all Iroh QUIC/UDP and TCP candidates concurrently and send the single-use ticket only over the first transport-layer connection that succeeds; losing attempts are cancelled immediately
- Iroh carries business bytes only after its path becomes `Direct` or `Mixed`. A relay-only Iroh path is closed and falls back to the LinkLake secret-tunnel server relay so policy, metrics, and limits cannot be bypassed

After short-lived ticket authentication, TCP direct paths use `Noise_NNpsk0_25519_ChaChaPoly_SHA256`. The server creates an independent 32-byte PSK per session, ChaCha20-Poly1305 encrypts all business bytes, and both peers rekey every `2^20` messages. Iroh paths use end-to-end QUIC/TLS 1.3 encryption. PSKs are delivered only through each peer's existing authenticated control channel and never appear in public candidates or direct tickets.

```toml
[client]
p2p_bind = "0.0.0.0:40000"
p2p_endpoint = "203.0.113.10:40000"
p2p_relay_url = "https://relay.example.com"
p2p_tcp_enabled = true
p2p_iroh_enabled = true

[[secret_visitors]]
name = "private-rdp-access"
local_bind = "127.0.0.1:13389"
access_key = "lls_replace-with-the-one-time-access-key"
prefer_direct = true
```

Self-hosted rendezvous uses pinned `iroh-relay 0.92.0`. Production configuration, a systemd unit, an Nginx WebSocket reverse-proxy snippet, and an installer are under `packaging/iroh-relay/`. Supply a publicly trusted certificate for the relay hostname and expose public `443/tcp` and `7842/udp`. The default configuration binds the Relay to high loopback ports so it can coexist with the Web UI's Nginx listener. This service assists discovery and hole punching; it does not replace LinkLake's policy-controlled business relay.

## SOCKS5 TCP/UDP proxy

- The server listens for SOCKS5 TCP and UDP on the same numeric public port, while the selected LinkLake client resolves target domains and creates outbound connections
- SOCKS5 `CONNECT` and `UDP ASSOCIATE` are supported; `BIND` explicitly returns command-not-supported
- RFC 1929 username/password authentication is mandatory; anonymous and no-auth modes are rejected
- Policy creation returns a high-entropy `llp_...` password once; SQLite stores only its SHA-256 hash
- Usernames contain 1 to 64 ASCII letters, digits, dots, underscores, or hyphens
- TCP and UDP support IPv4, IPv6, and domain targets, with domains resolved by the exit client; each UDP association remembers at most 256 contacted targets and accepts responses only from those targets
- A UDP association is bound to its authenticated TCP control connection, client source IP, and first UDP endpoint, and is revoked when the control connection closes
- SOCKS5 UDP fragmentation is unsupported; datagrams with non-zero `FRAG` are dropped and counted
- TCP and UDP share the policy aggregate bandwidth limit, alongside per-policy/global/pending connection limits, handshake and pairing timeouts, policy lifecycle, and client reconnects
- The Web UI and metrics report connections, CONNECT requests, authentication failures, handshake errors, unsupported commands, target failures, TCP/UDP traffic, UDP associations/datagrams/rate-limit drops, and transfer errors

SOCKS5 TCP and regular TCP tunnels share the TCP public-port namespace. When the UDP relay is enabled, SOCKS5 also occupies the same numeric UDP port, so a regular UDP policy cannot use that port either. Without a configured UDP relay, SOCKS5 `CONNECT` remains available but `UDP ASSOCIATE` returns command-not-supported. SOCKS5 UDP reuses the QUIC DATAGRAM relay described above, remains best effort, and has the same Internet MTU risks. A public SOCKS5 service is a general network exit: protect the one-time password, restrict source access, and retain cloud firewall, host firewall, and upstream abuse controls.

## HTTP forward proxy / CONNECT

- The server listens on a dedicated public HTTP proxy port while the selected LinkLake client resolves target domains and creates outbound TCP connections
- HTTP Basic `Proxy-Authorization` is mandatory; policy creation returns a high-entropy `llh_...` password once and SQLite stores only its SHA-256 hash
- Plain HTTP requests must use `http://` absolute-form; the server verifies URI/Host consistency, rewrites the target to origin-form, and strips proxy credentials and hop-by-hop request headers
- HTTPS, WebSocket, and arbitrary TCP protocols use `CONNECT host:port`; the tunnel terminates and releases its permit when either direction closes
- Duplicate Host, duplicate Content-Length, Content-Length plus Transfer-Encoding, non-chunked Transfer-Encoding, and other request-smuggling ambiguities are rejected
- Request bodies support no body, Content-Length, and strict chunked framing; responses support HEAD, 1xx, 204/304, Content-Length, chunked, and EOF framing without guessing message boundaries from connection timing
- IPv4, IPv6, and strict ASCII domain targets, per-policy/global/pending connection limits, aggregate bidirectional bandwidth limits, lifecycle controls, exit reconnects, auditing, and metrics are supported

HTTP forward proxies, SOCKS5 proxies, and regular TCP tunnels share the TCP public-port namespace and cannot use the same port. Each plain HTTP public connection handles one proxy request and closes after the origin response; use CONNECT for long-lived connections, protocol upgrades, or HTTPS. A public forward proxy is a general network exit: protect credentials, restrict source access, and retain cloud firewall, host firewall, and upstream abuse controls.

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

## Byte-preserving TLS SNI pass-through

TLS SNI pass-through is for HTTPS, SMTPS, IMAPS, POP3S, and other TLS services where the client-side target owns the certificate and terminates TLS. The server reads only a bounded, timed ClientHello to normalize SNI. It does not decrypt or modify TLS and forwards the already-read original ClientHello plus every following byte unchanged.

- Enable a separate listener with `LINKLAKE_TLS_PASSTHROUGH_BIND`, for example `0.0.0.0:443`
- Routes match exact SNI; missing, unknown, malformed, or timed-out ClientHello messages are rejected and counted
- Server-managed and local `[[tls_routes]]` entries support lifecycle controls, per-route/global/pending limits, aggregate bandwidth limits, maximum connection lifetime, auditing, and metrics
- `LINKLAKE_TLS_PASSTHROUGH_BIND` cannot share the same IP:port with native HTTPS `LINKLAKE_HTTPS_BIND`. A public 443 endpoint must choose LinkLake TLS termination or byte-preserving pass-through, unless an upstream layer-4 proxy splits SNI to different backends
- Pass-through routes never use LinkLake ACME certificates; certificate policy, TLS versions, ALPN, and the application protocol belong to the local target

```toml
[[tls_routes]]
name = "mail-tls"
hostname = "mail.example.com"
target = "127.0.0.1:465"
```

## Run locally

```powershell
$env:LINKLAKE_ENROLLMENT_TOKEN = "choose-a-long-random-token"
$env:LINKLAKE_ADMIN_USERNAME = "admin"
$env:LINKLAKE_ADMIN_PASSWORD = "choose-a-password-with-at-least-12-characters"
$env:LINKLAKE_DATA_DIR = "C:\LinkLake\data"
$env:LINKLAKE_HTTP_BIND = "127.0.0.1:32102"
$env:LINKLAKE_HTTPS_BIND = "127.0.0.1:32103"
$env:LINKLAKE_TLS_PASSTHROUGH_BIND = "127.0.0.1:32105"
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

Production clients should use the server-managed mode shown in [examples/linklake-client.toml](examples/linklake-client.toml). Use `[client]` for one cloud, or multiple `[[servers]]` entries from [examples/linklake-client-multi-server.toml](examples/linklake-client-multi-server.toml). Each identity keeps an independent control endpoint, CA, client ID/token, and optional P2P settings. Every server independently delivers SHA-256-revisioned TCP/UDP/port-group/HTTP/TLS-SNI, secret-provider, SOCKS5-exit, and HTTP-forward-proxy configuration:

```powershell
cargo run -p linklake-client -- run --config .\linklake-client.toml
```

Three `config_mode` values are supported:

- `server_managed`: the Web UI is authoritative. The client validates and writes `managed.toml`, keeps the previous version in `managed.toml.backup`, and dynamically starts, stops, or replaces only changed agents.
- `report_only`: local `[[tcp_tunnels]]`, `[[udp_tunnels]]`, `[[port_groups]]`, `[[http_routes]]`, `[[tls_routes]]`, `[[secret_tunnels]]`, `[[socks5_proxies]]`, and `[[http_proxies]]` continue to run; the client only reports whether they match the server policy.
- `local`: local entries run and cannot be overwritten, while conflicts are still reported to the Web UI.

The server never delivers or modifies the client token, CA, control endpoint, P2P listener/candidate, log path, service settings, or `[[secret_visitors]]` access keys. A temporary file is validated before replacement and the last valid configuration is retained as a backup. If delivery fails, the configuration is damaged, or the server is offline, the client continues using the last valid configuration. Client selectors in the Web UI show the mode, sync status, and apply error.

The Linux systemd service stores managed state in `/var/lib/linklake-client/managed.toml` by default. Windows stores it beside the bootstrap configuration. Override the location with `managed_config_path` or `LINKLAKE_STATE_DIR`.

In multi-cloud mode, identities without an explicit `managed_config_path` use separate `managed.<server-name>.toml` files. A failed cloud entry does not stop the others. The same local-mode or report-only policy set is replicated to every entry. In server-managed mode, create policies on both servers that point to the same local target to publish one game or other local service through cloud A and cloud B. Multi-cloud secret visitors must select their entry with `server = "cloud-a"` in `[[secret_visitors]]`.

Remote control connections also require `control_ca_cert` and `control_server_name`. Each cloud independently defines its public port policy, so cloud A and cloud B may use different public ports; TCP and UDP may still use the same numeric port.

## Management and metrics

- Public health endpoint: `GET /api/v1/health`
- Authenticated metrics endpoint: `GET /api/v1/metrics`
- Public port policy: `GET /api/v1/public-port-policy`
- TCP policies: `GET/POST /api/v1/tcp-tunnels`
- UDP policies: `GET/POST /api/v1/udp-tunnels`
- Enable or disable a UDP policy: `POST /api/v1/udp-tunnels/:id/enabled`
- Delete a UDP policy: `DELETE /api/v1/udp-tunnels/:id`
- Port groups: `GET/POST /api/v1/port-groups`
- Enable or disable a port group: `POST /api/v1/port-groups/:id/enabled`
- Delete a port group: `DELETE /api/v1/port-groups/:id`
- HTTP/HTTPS routes: `GET/POST /api/v1/http-routes`
- TLS SNI pass-through routes: `GET/POST /api/v1/sni-routes`
- Enable or disable a TLS SNI route: `POST /api/v1/sni-routes/:id/enabled`
- Delete a TLS SNI route: `DELETE /api/v1/sni-routes/:id`
- Secret tunnels: `GET/POST /api/v1/secret-tunnels`
- Enable or disable a secret policy: `POST /api/v1/secret-tunnels/:id/enabled`
- Delete a secret policy: `DELETE /api/v1/secret-tunnels/:id`
- SOCKS5 proxies: `GET/POST /api/v1/socks5-proxies`
- Enable or disable a SOCKS5 policy: `POST /api/v1/socks5-proxies/:id/enabled`
- Delete a SOCKS5 policy: `DELETE /api/v1/socks5-proxies/:id`
- HTTP forward proxies: `GET/POST /api/v1/http-proxies`
- Enable or disable an HTTP proxy: `POST /api/v1/http-proxies/:id/enabled`
- Delete an HTTP proxy: `DELETE /api/v1/http-proxies/:id`
- Enable or disable a route: `POST /api/v1/http-routes/:id/enabled`
- Route TLS settings: `PUT /api/v1/http-routes/:id/tls`
- Immediate issue or renewal: `POST /api/v1/http-routes/:id/certificate/issue|renew`
- ACME settings: `GET/PUT /api/v1/acme/config`
- Delete a route: `DELETE /api/v1/http-routes/:id`
- P2P node directory: `GET /api/v1/p2p/nodes`
- The Web UI configures TCP/TLS-SNI/secret/SOCKS5/HTTP-forward-proxy aggregate bandwidth, UDP aggregate bandwidth/session limits/idle timeouts, TCP/HTTP/TLS-SNI/secret/SOCKS5/HTTP-proxy connection limits, secret visitor restrictions, proxy usernames, the ACME environment, and HTTPS per route
- Metrics and policy views cover P2P freshness/direct/fallback paths, TLS SNI ClientHello/unknown-host/connection/traffic events, secret connections and traffic, SOCKS5 requests/authentication/connections/traffic, HTTP proxy requests/CONNECT/authentication/malformed messages/traffic, UDP sessions/packets/traffic/drops/timeouts, HTTP/HTTPS route traffic and failures, TLS handshake failures, managed/expiring/expired certificates, ACME orders, renewals, and HTTP-01 challenges
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

Relay QUIC TLS reuses `LINKLAKE_CONTROL_CERT_PATH` and `LINKLAKE_CONTROL_KEY_PATH`. Open the relay UDP port and the UDP ports actually assigned to policies in both the cloud security group and the host firewall; do not expose the complete allowed range unless it is required.

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
$env:FLUTTER_BIN = 'F:\Tools\flutter\bin\flutter.bat'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-manager-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-manager-windows.ps1
```

On Linux:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
pwsh -NoProfile -File ./tests/https-e2e.ps1
bash scripts/package-linux.sh
bash scripts/verify-linux-package.sh
sh scripts/package-manager-linux.sh
sh scripts/verify-manager-linux.sh
```

The TCP E2E suite covers real binary echo traffic, bandwidth limits, connection limits, reconnects, policy lifecycle, pairing timeout, and metrics. The UDP E2E suite covers real datagram echo from `0` through `65507` bytes, multiple sessions, rate-limit drops, idle expiration, fragmentation/reassembly, policy lifecycle, reconnects, same-numbered TCP/UDP ports, every mapping in contiguous TCP and UDP port groups, and metrics. Production acceptance additionally covers an independent public test host, a Linux server, and a Windows client. TLS SNI E2E uses a real self-signed target and .NET `SslStream` to verify original ClientHello forwarding, a real TLS handshake/echo, unknown-SNI rejection, lifecycle recovery, deletion, and metrics. Secret E2E covers a managed provider, one-time key isolation, visitor authorization, wrong keys, connection limits, lifecycle recovery, deletion, statistics, a real direct path between two client processes, explicit relay fallback for an unreachable candidate, and the absence of a public business listener. SOCKS5 E2E covers a managed exit, one-time password isolation, mandatory and failed authentication, domain/IPv4 CONNECT, real UDP ASSOCIATE echo, UDP fragmentation rejection, TCP control-connection lifecycle, BIND rejection, connection limits, lifecycle recovery, and metrics. HTTP E2E covers both Host routing and forward-proxy one-time passwords, mandatory/failed authentication, absolute-form rewriting, credential isolation, GET/POST bodies, smuggling rejection, a real CONNECT tunnel, connection limits, client reconnects, policy lifecycle, and metrics. Linux CI runs HTTPS/ACME E2E against a local Pebble service, covering HTTP-01, SNI, issuance and renewal, HTTPS forwarding, redirects, persistence, failure recovery, and certificate metrics without contacting a public certificate authority.

On macOS, use `scripts/package-macos.sh`, `scripts/verify-macos-package.sh`, `scripts/package-manager-macos.sh`, and `scripts/verify-manager-macos.sh` to build and verify the core services and Flutter manager.

Packaging scripts honor `SOURCE_DATE_EPOCH`. With the same timestamp, source, toolchain, target platform, and locked dependencies, archive ordering, timestamps, and release metadata remain stable. Windows produces ZIP archives plus SHA-256; Linux and macOS produce tar.gz archives plus SHA-256. Every platform publishes both a LinkLake core package and a LinkLake Manager package.

`.github/workflows/ci.yml` runs formatting, Clippy, unit tests, script syntax checks, Windows TCP/UDP/HTTP/TLS-SNI/secret-P2P/SOCKS5 E2E, Linux Pebble HTTPS/ACME E2E, and Flutter Manager analysis, tests, and release builds on Windows, Linux, and macOS. `.github/workflows/soak.yml` runs the long-running weak-network, crash, restart, concurrency, and throughput matrix weekly or on demand. `.github/workflows/release.yml` builds the core and manager packages for all three platforms and creates or updates a GitHub Release for `v*` tags.

## Roadmap

1. Secret tunnels: complete
2. SOCKS5 TCP: complete
3. SOCKS5 UDP Associate: complete
4. HTTP forward proxy / CONNECT: complete
5. Multi-port and port-range forwarding: complete
6. TLS SNI pass-through: complete
7. Multi-node and P2P operation with explicit relay fallback: complete
8. Flutter management client: first cross-platform release complete

## License

LinkLake is licensed under the Apache License 2.0. Copyright belongs to ASL-Vanity and LinkLake contributors; see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for the complete terms and attribution notice.

- Third-party components and licenses: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and [`THIRD_PARTY_LICENSES.html`](THIRD_PARTY_LICENSES.html)
- LinkLake name, Twin Shores logo, and brand assets: [`TRADEMARKS.md`](TRADEMARKS.md)
- Contribution, provenance, and DCO sign-off requirements: [`CONTRIBUTING.md`](CONTRIBUTING.md)

The Apache License 2.0 does not grant rights to LinkLake branding or trademarks. Modified distributions, forks, and hosted services may accurately describe themselves as based on LinkLake, but must not imply official maintenance or endorsement.
