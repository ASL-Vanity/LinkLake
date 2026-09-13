# LinkLake Roadmap

[中文](ROADMAP.md) | English

This document separates the v1.1 feature line included in the current `v1.1.2` release target from continuing improvements. Experience, reliability, protocol-extension and high-availability work is consolidated into v1.1, with no separate `v1.0.1` planned. Future directions are not release-date commitments. See the [changelog](CHANGELOG.md) and the relevant Release for changes and published assets.

## v1.1.2 release target

- PostgreSQL shares identities, sessions, all eight policy kinds, Fleet, certificate/ACME material, traffic and operational state. Standalone SQLite remains available; shared-read failures do not fall back to a local business database.
- Instance leases, leader fencing, shared port ownership, atomic Fleet reconciliation and durable traffic spools are integrated. Every replica retains an independent persistent directory.
- Web UI and Flutter Manager provide ACME challenge configuration, readiness, HA/Fleet management and role controls. Protocol capabilities include gRPC backend TLS, SOCKS5 BIND/bounded FRAG and dynamic egress protection.
- Explicit PostgreSQL initialization, SQLite migration, rollback-eligibility checks and offline material-key rotation have maintenance commands. Update procedures distinguish standalone SQLite from PostgreSQL clusters.
- Helm shared-state and per-replica volume configuration, installation/update safeguards, the [user guide](docs/user-guide.en.md) and bilingual READMEs have been updated for this version.

The repository version is `v1.1.2`. The tag workflow produces official builds, signatures and assets; consult GitHub Releases for downloadable versions. `v1.1.0` and `v1.1.1` remain immutable source tags without corresponding public Releases. Production-server upgrades are scheduled separately; version publication does not imply that production nodes have been upgraded.

## Continuing improvements

These items guide work after v1.1.2.

### Management surfaces

- Continue organizing Web UI page, component and state boundaries, and improve responsive charts and the secure-update entry.
- Refine Flutter Manager material themes, history trends, client-status charts, user/session management and current identity display.
- Continue aligning authorization, errors, updates, Fleet, health and high-availability semantics across the Web UI and Manager.

### Secure remote updates

- Improve check, download, scheduling, status and recovery experiences for persistent server, client and Manager update tasks while keeping database compatibility and rollback limits explicit.
- Require clients to opt in and actively claim remote update tasks; the server must not turn the update channel into arbitrary command execution.
- Enforce interactive administrator authorization, exact confirmation, CSRF/Origin protection, single-flight locking, audit records, and fail-closed behavior for high-risk actions.

### Protocols and target pools

- Complete HTTP forward-proxy connection reuse and multi-request keep-alive.
- Improve compatibility with complex backends using HTTP/1.1 `h2c Upgrade` and TLS/ALPN for local gRPC targets.
- Continue refining port, timeout, ordering, memory-budget and abuse controls for SOCKS5 `BIND` and UDP `FRAG`.
- Improve application health probes under weak networks and slow targets while retaining automatic ejection/recovery and weighted selection from healthy targets only.

### Multi-cloud and Fleet

- Distinguish node presence, control-channel availability, and real application reachability.
- Improve Fleet generation, source, ownership, synchronization progress and conflict presentation, including preview and manual-resolution flows.
- Complete Cloudflare DNS failover drills, freeze/cooldown/recovery behavior, and coordinated multi-server updates.

### PostgreSQL and high availability

- Evolve PostgreSQL schema compatibility, explicit migration ledgers and disaster-recovery operations while retaining standalone SQLite.
- Refine instance leases, leader election, fencing tokens, public-port ownership and takeover behavior under complex failures.
- Improve leases, idempotency, recovery and external-side-effect reconciliation for certificate renewal, updates, alerts and Fleet jobs; database fencing is not a transaction guarantee across external services.
- Improve the presentation of members, leases, port ownership, takeover and abnormal states in the Web UI and Manager.

### Platforms, dependencies, and release

- Complete install, upgrade, configuration-preservation, failure-recovery, and removal semantics for Windows, DEB, RPM, and Helm.
- Split framework, database, cryptography, configuration-parser, GitHub Actions, and Docker toolchain upgrades into reviewable batches instead of merging mixed major upgrades.
- Maintain official builds, asset identities, checksums and signing for subsequent releases. Schedule production deployment separately around each environment's database state, recovery plan and maintenance window.

Continuing quality goals: consistent APIs and management entry points, fail-closed update and authorization behavior, and auditable protocol, accounting, database-recovery and HA boundaries. These goals do not claim acceptance in every environment or completed production staging.

## Continuing boundaries

- Long-duration and weak-network coverage remains in a separate soak workflow.
- macOS remains source- and CI-compatible; official packages, Developer ID, notarization, and automatic updates are not currently promised.
- Official Windows assets remain unsigned with Authenticode under the personal open-source policy. Obtain them from the official Release and verify SHA-256, GitHub attestations, and the LinkLake Ed25519 manifest.
- Release signing, database migration, authorization, and network-policy changes must fail closed and retain a verifiable recovery path.
