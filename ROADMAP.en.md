# LinkLake Roadmap

[中文](ROADMAP.md) | English

This document describes the product direction after `v1.0.0`. Version scopes are plans, not date commitments. GitHub milestones, issues, CI, and acceptance evidence are the source of truth for actual status.

## v1.0.1: experience and maintainability

Goal: reduce management-surface maintenance cost and close desktop-management gaps without changing established protocol semantics or configuration compatibility.

- Split the large Web UI file into page, component, and state modules while preserving RBAC and browser-test semantics.
- Use container-size observation for wide, narrow, drawer, and chart responsiveness, and expose a discoverable secure-update management entry.
- Complete Flutter Manager material themes, history trends, client-status charts, full user editing, and current-user/role identity.
- Establish `main` merge gates, immutable `v*` tag rules, version milestones, and executable issues.
- Review automated dependency updates. Major upgrades must be separated, migrated, and pass the complete protocol and supply-chain gates instead of being merged as an undifferentiated batch.

Acceptance: all existing protocol E2E, security baseline, and three-platform build gates pass; new Web UI and Manager entry points have automated coverage; release, update, and rollback remain fail-closed.

## v1.1.0: reliability and multi-cloud visibility

Goal: make multi-target and multi-server deployments react to real application health while keeping each decision observable.

- Probe forwarded targets at the application layer with thresholds, ejection, recovery, and anti-flap behavior.
- Connect weighted target selection to health state while preserving explicit failure and fallback metrics.
- Improve Fleet and Cloudflare DNS failover drills, synchronization-conflict visibility, and source-identity reporting.
- Add first-install, upgrade, failure rollback, and configuration-preservation E2E for Windows, DEB, and RPM packages.
- Align multi-cloud state, update state, and failure-diagnostics semantics across the Web UI and Flutter Manager.

Acceptance: health ejection and recovery are deterministically reproducible; failover produces audit records and metrics; installer E2E covers success, failure, and rollback paths.

## v1.2.0: highly available control plane and protocol extensions

Goal: support a multi-instance control plane with explicit consistency boundaries and extend modern backend protocols one capability at a time.

- Add a PostgreSQL storage backend and explicit migration tooling while retaining SQLite for single-instance deployments.
- Implement multi-instance leases, port ownership, failover, and coordination that prevents duplicate listeners.
- Add TLS/ALPN for local gRPC targets and evaluate a safe HTTP/1.1 `h2c Upgrade` implementation.
- Evaluate real demand, attack surface, and interoperability for SOCKS5 `BIND` and UDP `FRAG` separately. Continue to reject them explicitly until an evaluation is accepted; never silently degrade.

Acceptance: multi-instance failover cannot produce dual writes, duplicate listeners, or unauthorized takeover; every new protocol capability has explicit boundaries, negative tests, audit coverage, and end-to-end verification.

## Continuing boundaries

- Long-duration and weak-network validation remains in the separate soak workflow and does not replace short-cycle feature gates.
- macOS remains source- and CI-compatible; official packages, Developer ID, notarization, and automatic updates are not currently promised.
- Official Windows assets remain unsigned with Authenticode under the personal open-source policy. Obtain them from the official Release and verify SHA-256, GitHub attestations, and the LinkLake Ed25519 manifest.
- Release signing, database migration, authorization, and network-policy changes must fail closed and retain a verifiable recovery path.
