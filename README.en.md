# LinkLake

[中文](README.md) | English | [User guide](docs/user-guide.en.md) | [Roadmap](ROADMAP.en.md) | [Releases](https://github.com/ASL-Vanity/LinkLake/releases)

LinkLake is a cross-platform secure tunneling and service publishing platform written in Rust. Run a Client on a machine that can reach your target service and a Server at the public entry point to publish TCP, UDP and web services, or access them through private Secret tunnels.

The Server includes a Web UI. The optional Flutter desktop application, LinkLake Manager, manages servers and local clients. Server and Client can each run independently or as operating-system services.

**The current repository version is `1.1.1`.** This page describes repository capabilities. Available versions and downloadable assets are listed in [GitHub Releases](https://github.com/ASL-Vanity/LinkLake/releases).

## Core capabilities

| Scenario | Capabilities |
| --- | --- |
| Service publishing | TCP, UDP, port groups/ranges, private Secret tunnels and byte-preserving TLS SNI passthrough; weighted target pools select new connections using client health probes |
| Web and APIs | HTTP/HTTPS host routing, WebSocket, HTTP/2 and native gRPC; gRPC backends support h2c or TLS with certificate verification |
| Proxy egress | Authenticated SOCKS5 CONNECT/BIND, optional UDP ASSOCIATE and bounded FRAG reassembly; HTTP forward proxy/CONNECT with explicit private-network egress permissions |
| Certificate automation | ACME HTTP-01, Cloudflare DNS-01, wildcard certificates and renewal; challenge selection and readiness in Web UI/Manager |
| Access control | Administrator/operator/auditor roles, TOTP, session revocation and scoped API tokens; CIDRs, connection rates, bandwidth, time windows and UTC daily traffic quotas |
| Multiple entry points and HA | Clients connect to multiple independent servers; encrypted Secret P2P with controlled relay fallback; Fleet v2 generations, ownership and conflict checks, health monitoring and Cloudflare DNS failover |
| Shared state | PostgreSQL shares identities, policies, certificates, Fleet, traffic and operational state; leases and fencing constrain stale leader writes |
| Management and operations | Chinese/English web and desktop interfaces and themes, auditing, metrics and SLOs, Prometheus/Grafana, and server-coordinated remote client update tasks |

UDP relay must be enabled separately and datagrams remain best effort. Direct P2P connectivity depends on NAT and network conditions. Existing connections may need to reconnect after a node takeover or entry-point change.

## Quick start

The [user guide (Chinese)](docs/user-guide.zh-CN.md) covers release packages, TLS, system services and clusters. This local source example runs in **PowerShell 7** from the Rust repository root; `rust-toolchain.toml` pins Rust `1.91.0`. First prepare a working target service, such as `127.0.0.1:8080`.

Start the Server:

```powershell
$env:LINKLAKE_BIND = "127.0.0.1:32100"
$env:LINKLAKE_CONTROL_BIND = "127.0.0.1:32101"
$env:LINKLAKE_DATA_DIR = Join-Path $PWD "data"
$env:LINKLAKE_ADMIN_USERNAME = "admin"
$env:LINKLAKE_ADMIN_PASSWORD = Read-Host "Initial administrator password (12+ characters)" -MaskInput
$env:LINKLAKE_ENROLLMENT_TOKEN = Read-Host "Set a separate long random enrollment token" -MaskInput
cargo run --locked -p linklake-server
```

Open `http://127.0.0.1:32100`, sign in and complete the initial password change when prompted. The administrator password environment variable initializes a new account; it does not reset an existing account.

In another terminal, enroll the Client using the same enrollment token:

```powershell
$enrollmentToken = Read-Host "Server enrollment token" -MaskInput
cargo run --locked -p linklake-client -- enroll `
  --server http://127.0.0.1:32100 `
  --token $enrollmentToken `
  --name local-demo `
  --identity-file ./client-state/agent-identity.json
```

Save the returned `client_id`, one-time `client_token` and machine identity file. Create `linklake-client.toml`:

```toml
config_version = 2

[client]
control = "127.0.0.1:32101"
client_id = "replace-with-the-enrolled-UUID"
client_token = "replace-with-the-enrolled-client-token"
config_mode = "server_managed"
managed_config_path = "managed.toml"
```

```powershell
cargo run --locked -p linklake-client -- run --config ./linklake-client.toml
```

Confirm that `local-demo` is online in the Web UI. Create and enable a TCP policy using this client, public port `32080` and target `127.0.0.1:8080`. The client receives the managed configuration; connect to port `32080` on the Server to reach the service. Targets are reached from the Client, so `127.0.0.1` here refers to the Client's machine.

This example restricts management and control listeners to loopback; policies create separate service listeners. Before connecting machines across a network, configure trusted management/control TLS, bind addresses and firewalls using the [deployment guide](docs/deployment.md). The default allocatable service port range is `32000–32999`. See the [single-server](examples/linklake-client.toml) and [multi-server](examples/linklake-client-multi-server.toml) examples for more configuration.

## Platforms and installation

The release workflow covers these targets. Package names, checksums and signatures depend on the selected Release.

| Platform | Release assets and deployment |
| --- | --- |
| Windows x86_64 | Server/Client ZIP and Windows service scripts; separate Manager ZIP |
| Linux x86_64 | Server/Client tar.gz, DEB/RPM and systemd; separate Manager tar.gz |
| Containers and Kubernetes | Server OCI image for `linux/amd64`; [Docker Compose](deploy/docker-compose.yml) and [Helm chart](deploy/helm/linklake) |
| macOS | Source builds and CI compatibility; no official release assets or automatic-update channel |

## SQLite and PostgreSQL

| Mode | State and deployment | Maintenance |
| --- | --- | --- |
| Standalone SQLite | One Server process exclusively owns its data directory; suitable for an independent entry point | Back up the complete data directory and configuration; use SQLite-specific inspection, backup, recovery and update procedures |
| PostgreSQL HA | Replicas share the business database; each still needs an independent persistent directory for instance identity, unacknowledged traffic accounting and staging | PostgreSQL backup/PITR plus separate instance state, material key and external credentials; plan upgrades around cluster compatibility |

PostgreSQL leases and fencing coordinate leadership. The deployment still provides database availability, public ingress routing and load balancing. Shared database failures do not fall back to local SQLite, and existing TCP/QUIC sessions are not migrated to another replica. Multiple independent servers connected through client `[[servers]]`/Fleet are a separate deployment model from replicas sharing one PostgreSQL database.

SQLite → PostgreSQL uses an [explicit offline migration](docs/storage-migration.md) with the source process and all target replicas stopped. After the target accepts new writes, switching back to the old SQLite database is not a lossless rollback. PostgreSQL upgrades do not use the standalone SQLite snapshot update protocol; reverting an image does not revert the database. Follow [cluster upgrades and recovery](docs/postgres-upgrades.md).

PostgreSQL certificate material requires the same independent **32-byte raw key file** on every replica. Back up this key separately; replacing a deployment Secret does not re-encrypt existing material. [Key rotation](docs/certificate-key-maintenance.md) requires all replicas stopped before running the maintenance command.

## Secure updates

Before installation, verify SHA-256, GitHub build attestations and the production Ed25519 update manifest. Linux packages also have OpenPGP signatures; verify OCI signatures and provenance against the image digest. Official Windows packages intentionally omit Authenticode signing under the current personal open-source release policy.

Client, standalone Server and Manager have their own secure update procedures; the Server can also coordinate remote client updates. Development builds and signatures are not production update trust. Recovery depends on database state and whether the candidate has started or accepted writes; retaining an old binary alone does not establish a safe rollback.

See [update security](docs/update-security.md), [release supply chain](docs/release-supply-chain.md) and [PostgreSQL cluster upgrades](docs/postgres-upgrades.md) for procedures and boundaries.

## Documentation

| Topic | Documents |
| --- | --- |
| Installation and daily use | [User guide (Chinese)](docs/user-guide.zh-CN.md), [deployment guide](docs/deployment.md), [configuration example](examples/linklake-client.toml) |
| HTTP/2 and gRPC | [Routing and backend TLS](docs/http2-grpc.en.md) |
| SOCKS5 | [Supported behavior and security boundaries](docs/socks5-supported-boundaries.en.md) |
| Multiple entry points and Fleet | [Fleet Bundle v2](docs/adr/0003-fleet-bundle-v2.md), [health and DNS failover design](docs/adr/0004-fleet-health-dns-failover.md) |
| Observability | [Metrics, alerts and SLOs](docs/slo-observability.en.md) |
| Data and key maintenance | [Storage migration](docs/storage-migration.md), [cluster upgrades and recovery](docs/postgres-upgrades.md), [certificate material keys](docs/certificate-key-maintenance.md) |
| Updates and supply chain | [Update security](docs/update-security.md), [release verification](docs/release-supply-chain.md) |
| Contributing | [Roadmap](ROADMAP.en.md), [contributing guide](CONTRIBUTING.md), [security reports](SECURITY.md) |

## License and brand

Copyright 2026 ASL-Vanity and LinkLake contributors. Source code is licensed under [Apache License 2.0](LICENSE). The LinkLake name, Twin Shores logo and visual identity follow the [brand policy](TRADEMARKS.md).

Code, tests, documentation and release engineering were developed with OpenAI GPT-5.6 assistance under the project owner's requirements, review, infrastructure authorization and acceptance. See [NOTICE](NOTICE) for attribution and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) / [THIRD_PARTY_LICENSES.html](THIRD_PARTY_LICENSES.html) for third-party components.
