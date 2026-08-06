# LinkLake Roadmap

[中文](ROADMAP.md) | English

This document describes the product direction after `v1.0.0`. The project will not publish a separate `v1.0.1`; the previously separate experience, reliability, protocol-extension, and high-availability scopes are consolidated into `v1.1.0`. Version scope is a plan rather than a date commitment. GitHub milestones, issues, and final acceptance gates remain the source of truth.

## v1.1.0: complete feature release

Goal: complete the management, update, protocol, multi-cloud, high-availability, and platform-delivery capabilities in one release. No intermediate version is published during development; complete testing, remediation, staging, and release begin after the feature set is frozen.

### Management surfaces

- Split the large Web UI file into page, component, and state modules, and complete responsive charts and the secure-update entry.
- Complete Flutter Manager material themes, history trends, client-status charts, full user/session management, and current identity display.
- Align authorization, errors, updates, Fleet, health, and high-availability semantics across the Web UI and Manager.

### Secure remote updates

- Persist server, client, and Manager update tasks with check, download, scheduling, status, failure recovery, and rollback flows.
- Require clients to opt in and actively claim remote update tasks; the server must not turn the update channel into arbitrary command execution.
- Enforce interactive administrator authorization, exact confirmation, CSRF/Origin protection, single-flight locking, audit records, and fail-closed behavior for high-risk actions.

### Protocols and target pools

- Complete HTTP forward-proxy connection reuse and multi-request keep-alive.
- Implement HTTP/1.1 `h2c Upgrade` and TLS/ALPN for local gRPC targets.
- Implement SOCKS5 `BIND` and UDP `FRAG` with port, timeout, ordering, memory-budget, and abuse controls.
- Probe forwarded targets at the application layer, automatically eject and recover unhealthy targets, and select weighted targets only from the healthy set.

### Multi-cloud and Fleet

- Distinguish node presence, control-channel availability, and real application reachability.
- Expose Fleet generation, source, ownership, synchronization progress, and conflict details with preview and manual resolution.
- Complete Cloudflare DNS failover drills, freeze/cooldown/recovery behavior, and coordinated multi-server updates.

### PostgreSQL and high availability

- Add a PostgreSQL storage backend and explicit migration ledger while retaining SQLite for single-instance deployments.
- Implement instance leases, leader election, fencing tokens, public-port ownership, and safe failover.
- Ensure certificate renewal, updates, alerting, Fleet, and other background tasks execute once and recover correctly across instances.
- Expose members, leases, port ownership, takeover, and abnormal states in the Web UI and Manager.

### Platforms, dependencies, and release

- Complete install, upgrade, configuration-preservation, failure-recovery, and removal semantics for Windows, DEB, RPM, and Helm.
- Split framework, database, cryptography, configuration-parser, GitHub Actions, and Docker toolchain upgrades into reviewable batches instead of merging mixed major upgrades.
- After feature freeze, run the unified Rust, Flutter, browser, all-protocol, update, HA, installer, and supply-chain gates; stage in Shanghai first, then upgrade Singapore and publish the formal release.

Acceptance: every public capability has consistent APIs and management entry points; update and authorization remain fail-closed; protocol and HA boundaries are auditable; all unified test, staging, and release gates pass.

## Continuing boundaries

- Long-duration and weak-network validation remains in the separate soak workflow and does not block this feature-development cycle or its short unified acceptance pass.
- macOS remains source- and CI-compatible; official packages, Developer ID, notarization, and automatic updates are not currently promised.
- Official Windows assets remain unsigned with Authenticode under the personal open-source policy. Obtain them from the official Release and verify SHA-256, GitHub attestations, and the LinkLake Ed25519 manifest.
- Release signing, database migration, authorization, and network-policy changes must fail closed and retain a verifiable recovery path.
