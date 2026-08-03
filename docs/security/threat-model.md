# LinkLake Threat Model / LinkLake 威胁模型

## 1. Scope and security goals / 范围与目标

This document defines the baseline threat model for LinkLake's server, client, Web UI and management API, public forwarding listeners, updater, release pipeline, and multi-cloud deployments. It is a living engineering document, not an external penetration-test report or a formal proof of security.

本文覆盖 LinkLake 服务端、客户端、Web UI 与管理 API、公网转发监听器、更新器、发布链路和多云部署。它是持续维护的工程基线，不等同于第三方渗透测试或形式化安全证明。

Primary goals:

- Only authenticated and authorized operators can change clients, users, credentials, and forwarding policies.
- Control-plane and management-plane credentials remain confidential and cannot be replayed indefinitely.
- Public forwarding exposes only explicitly configured services, protocols, ports, and destinations.
- Updates are authentic, integrity checked, rollback resistant, safely extracted, and recoverable.
- A compromised client, relay, public visitor, or cloud host has a bounded blast radius.
- Security-relevant actions are auditable without placing secrets in logs.

Availability against volumetric attacks, protection of a fully compromised operating-system administrator, and security of third-party applications behind LinkLake are not guaranteed by LinkLake alone.

## 2. Assets / 资产

| Asset | Security property |
| --- | --- |
| Administrator, operator, and auditor accounts | Password secrecy, strong session handling, role isolation, recovery without privilege bypass |
| Client enrollment and control credentials | Confidentiality, authenticity, bounded lifetime, revocation, replay resistance |
| Forwarding policies and managed configuration | Authorized changes, integrity, deterministic precedence, auditability |
| Tunnel payload and metadata | Confidentiality/integrity where the selected protocol provides it; minimum necessary retention |
| TLS and release-signing private keys | Offline or tightly scoped custody, non-exportability where possible, rotation and revocation |
| SQLite state, backups, logs, and metrics | Integrity, least-privilege access, redaction, recoverable backup/restore |
| Release artifacts and update manifests | Publisher authenticity, digest integrity, version monotonicity, platform/product binding |
| Public listeners and cloud bandwidth | Controlled exposure, connection/rate limits, resistance to proxy and amplification abuse |

## 3. Trust boundaries and data flows / 信任边界与数据流

```text
Untrusted Internet visitors
        |
        v
[Public data plane: TCP / UDP / HTTP(S) / TLS-SNI / SOCKS5 / secret tunnel]
        |
        v
[LinkLake server or relay] <==== authenticated control channel ====> [LinkLake client]
        |                                                               |
        | management API / Web UI                                        v
        v                                                        [Private target service]
[Administrator / operator / auditor browser]

[Release CI + signing key] -> signed manifest + artifacts -> [Updater] -> [Installed binary]
```

The principal trust boundaries are:

1. **Management plane:** browser to Web UI/API. The browser, reverse proxy, server process, session store, and administrator endpoint are distinct trust zones.
2. **Control plane:** client to server. Enrollment, authentication, policy delivery, heartbeats, revocation, and reconnect behavior cross an untrusted network.
3. **Public data plane:** arbitrary visitors to published listeners and then to private targets. Visitor input and target responses are untrusted.
4. **Host boundary:** LinkLake processes rely on operating-system users, filesystem ACLs, service managers, firewalls, and cloud security groups.
5. **Update boundary:** GitHub, CI runners, release assets, signing infrastructure, mirrors/CDNs, the updater helper, and the installed service must not be treated as one trust domain.
6. **Multi-cloud boundary:** each cloud server or relay is independently compromiseable; adding a second egress or relay increases both availability and the trusted computing base.

## 4. Adversaries and assumptions / 对手与假设

The model considers unauthenticated internet attackers, malicious visitors, stolen low-privilege accounts, compromised clients, compromised relay/cloud hosts, malicious or vulnerable target services, dependency/release-supply-chain attackers, and attackers with read access to backups or logs.

The operating system, hypervisor, DNS registrar, certificate authority, and cloud control plane are assumed to work as configured. A root/Administrator compromise can read process memory, replace binaries, or alter firewall rules and is therefore outside the guarantees of the application layer. Their compromise remains an operational risk requiring separate controls.

## 5. Threats, controls, and residual risk / 威胁、控制与剩余风险

| Area and threat | Baseline controls | Residual risk and required follow-up |
| --- | --- | --- |
| Credential theft, weak defaults, session hijacking | Password hashing, forced change of bootstrap credentials, secure cookies, role-based access, last-administrator protection, redacted logs | Endpoint malware, browser compromise, reused passwords, and stolen session cookies remain possible; add MFA, session inventory/revocation, and credential rotation procedures |
| Unauthorized policy or user changes | Administrator/operator/auditor separation, API authorization, audit records, validation before activation | RBAC implementation bugs or a stolen privileged account can still alter exposure; require negative authorization tests and independent audit review |
| Control-channel impersonation or replay | Authenticated encrypted transport, enrollment credentials, server-managed policy state, reconnect validation | Long-lived or copied enrollment material can expand access; define expiry, one-time enrollment, key rotation, and immediate revocation semantics |
| Managed configuration conflicting with local files | Explicit server authority and deterministic validation; startup rejects invalid/conflicting active policy | Incorrect operator intent can still distribute a harmful but valid policy; add previews, approval boundaries, versioned rollback, and signed policy snapshots |
| SSRF, open-proxy, and lateral-movement abuse | Explicit policy types, target/port validation, reserved-port policy, per-role management authorization | SOCKS5/HTTP proxy and broad destination policies are inherently powerful; default-deny private/metadata destinations unless explicitly authorized and test IPv4/IPv6/DNS rebinding cases |
| Public TCP/HTTP/TLS input attacks | Protocol parsing, listener scoping, connection/pending limits, bandwidth and lifetime limits | Target services remain responsible for application-layer authentication and patching; malformed traffic and slow-client resource exhaustion need fuzzing and soak tests |
| UDP spoofing and amplification | Explicit UDP policies, bounded mappings/timeouts, port ranges, host/cloud firewall controls | Stateless traffic enables spoofing and reflection; enforce response amplification limits, per-source quotas, idle expiry, and abuse telemetry |
| Tunnel payload disclosure or modification | Encrypted authenticated control/tunnel mechanisms where configured; TLS pass-through preserves end-to-end TLS | Plain TCP/UDP targets and compromised endpoints can expose content; document protocol guarantees and avoid claiming end-to-end encryption where LinkLake terminates or forwards plaintext |
| Update manifest forgery or artifact replacement | Independent Ed25519 trust root, SHA-256 checks, product/platform/version binding, HTTPS/repository constraints | CI or signing-key compromise can create valid malicious releases; use offline or hardware-backed production keys, protected environments, transparency, and dual-control rotation |
| Update rollback or freeze | Minimum updater version, semantic version checks, signed manifest validity ranges, post-install version verification | An attacker controlling distribution may withhold updates; add freshness/expiry policy and monitored update compliance |
| Archive traversal, decompression bombs, or helper-plan tampering | Path and entry limits, staged digest verification, product-specific replacement, helper-plan digests, backup and rollback | Parser vulnerabilities and disk exhaustion remain possible; retain adversarial archive tests and run updater with minimum filesystem privileges |
| Database, backup, log, or metric disclosure | Local persistence, integrity checks, role separation, audit design, secret-redaction expectations | Host readers may obtain topology, usernames, target addresses, or tokens accidentally logged; define retention, ACLs, encryption-at-rest expectations, and redaction tests |
| Dependency and CI compromise | Locked dependencies, license policy, cargo-audit/cargo-deny, OSV, gitleaks, actionlint/zizmor, Trivy, pinned Actions in the security workflow, Dependabot cooldown | Scanners can lag disclosures and build scripts may execute during compilation; review lockfile diffs, minimize build scripts, pin release workflows, and verify provenance |
| Multi-cloud relay/server compromise | Independent hosts and policies can improve availability; clients can establish multiple authorized routes | Every additional server observes metadata and may forward traffic; use distinct credentials, per-server policy scope, revocation, and avoid assuming two untrusted clouds equal end-to-end confidentiality |
| Denial of service and resource exhaustion | Connection/pending/global limits, bandwidth limits, listener ranges, cloud firewall and observability | Volumetric attacks can exhaust upstream links before application controls apply; require provider-level DDoS controls and capacity/runbook testing |

## 6. Security invariants / 必须保持的安全不变量

- Pull requests from forks receive no repository or deployment secrets and never use `pull_request_target` to execute untrusted code.
- GitHub Actions referenced by the security workflow use immutable commit SHAs and minimum permissions; checkout credentials are not persisted.
- New vulnerability findings fail CI. A temporary exception names one exact advisory, documents the dependency path and remediation reason, and expires automatically.
- No update is installed unless signature, digests, product, platform, version, archive layout, staged binary, and post-install service checks all succeed.
- Public exposure is deny-by-default: a listener exists only for a validated active policy, and reserved management/control ports cannot be allocated as public forwarding ports.
- Logs, metrics, errors, and audit events must not contain passwords, session cookies, enrollment secrets, private keys, raw authorization headers, or complete sensitive payloads.

## 7. Validation and review / 验证与审查

The automated baseline covers dependency advisories, license/source policy, lockfiles across supported ecosystems, repository history secrets, workflow syntax and security, and filesystem vulnerabilities/misconfiguration. Protocol E2E tests, updater rollback tests, authorization tests, fuzzing, load/abuse tests, disaster recovery, and manual configuration review remain necessary.

Before a stable release, LinkLake should commission a separate independent review of authentication/session handling, control protocol and cryptography, proxy/SSRF boundaries, UDP abuse resistance, updater/signing design, release CI, and representative Windows/Linux/macOS packages. Findings and remediation evidence should be tracked separately from this living model.
