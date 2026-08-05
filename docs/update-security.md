# LinkLake v1.0 Update Security Model

Date: 2026-08-05

## Threat model and compatibility audit

The audit covered the former client-only updater, server startup order, Windows/systemd/launchd definitions, all package layouts, Manager bundles, and the Release workflow.

The previous updater already restricted HTTPS hosts and repository paths, checked GitHub and `.sha256` digests, bounded archives, staged binaries, used same-directory replacement, restored services, and rolled back failures. The productization gaps were: no server updater; server version output occurred after startup-related work; checksum and asset shared one publisher trust domain; no stable Manager installation protocol; helper plans were client-specific; and no separation between production and test signing or key-rotation metadata.

The v1.0 design protects against corrupted downloads, asset/checksum disagreement, replacement of GitHub release assets by a compromised repository publisher, path traversal, links and archive bombs, staged-file tampering, wrong-target replacement, concurrent target changes, service recovery failure, installed-version mismatch, server schema/ledger incompatibility, an interrupted database migration or rollback, and forged server recovery state in a writable update directory.

It does not by itself protect against a malicious build signed by an authorized production key, production-key disclosure, full administrator/root compromise of the running host, operating-system trust-root compromise, or a privileged process indefinitely locking a Manager installation. Mitigations include least-privilege CI, offline production-key generation, protected tags/releases, rotation and revocation, helper timeouts, and automatic rollback.

## Signed manifest

Every tagged release, whether stable or a SemVer prerelease, publishes `linklake-release-manifest-v1.json` and `linklake-release-manifest-v1.sig`. The manifest binds `release_version`, `key_id`, `minimum_updater_version`, creation time, and each asset's `component`, `target`, `name`, `sha256`, and `size`. Assets are strictly sorted by component, target, and name. The detached signature is Ed25519 over one canonical byte encoding: compact UTF-8 JSON in the declared struct-field order followed by exactly one LF. Verifiers reject alternate whitespace, field order, duplicate identities, and trailing bytes even when a detached signature is otherwise valid.

Verification order is: GitHub HTTPS/repository ownership; GitHub asset digest; Ed25519 manifest; release/key validity/minimum updater; signed asset identity/size/digest; `.sha256`; archive and internal `release.json`; staged digest; hashed helper plan; installed version; and service recovery.

Production policy rejects network downgrade. Downgrade is a local verified-backup operation. `--allow-downgrade` is effective only with the explicit `--development-signature` test policy.

## Official platform scope

The formal updater manifest intentionally contains only `windows-x86_64` and `linux-x86_64` install assets. macOS remains build- and CI-compatible from source, but has no official GitHub Release package, signed-manifest entry, automatic-update path, Developer ID, or notarization gate. References to launchd in this model describe source compatibility rather than a supported official distribution channel.

## Key management and rotation

- Production private keys are supplied only through the `LINKLAKE_RELEASE_SIGNING_KEY_B64` CI secret. They must never be generated or stored in the repository, artifacts, logs, or updater state.
- `security/release-keys.json` contains public keys, purpose, and semantic-version validity ranges only.
- The committed RFC 8032 private fixture is marked development and is rejected by production policy.
- Rotation first adds a new public key with a future `not_before_version`, ships an updater that trusts old and new keys, then changes CI secrets, and finally assigns the old key a `not_after_version`.
- Emergency revocation requires another trusted production key. Without one, a new trust root must be distributed through a separate authenticated channel.

The production public key `linklake-production-2026-08-a` is registered for the `1.0.0` release line. Tagged Releases still fail closed unless `LINKLAKE_RELEASE_SIGNING_KEY_ID` selects that registered production key and `LINKLAKE_RELEASE_SIGNING_KEY_B64` contains the matching private seed. Using the development fixture to bypass this check is prohibited.

## Replacement invariants

- Client operations replace only the selected executable. Server operations require an explicit data directory; when a service is registered, its configured `LINKLAKE_DATA_DIR` must canonically equal that argument before any snapshot or replacement. The old binary creates a SQLite snapshot outside live data, the candidate rehearses migration against an isolated clone, and a failure before candidate-service handoff restores the authenticated snapshot before the old binary is restored. Configuration, certificates, logs, and managed state remain outside the replacement set.
- Incoming and displaced executables are renamed within the target parent directory.
- A service is controlled only if it references the target executable. A previously stopped service remains stopped; a previously running service must become stably active again.
- Manager binds the complete staged and installed directory trees into the helper plan, copies the staged payload beside the installation directory, verifies the copied tree, and switches directories on the target volume. Flutter passes its PID and must exit after `requires_manager_exit=true`; the helper waits for that exact process with a bounded timeout before touching the installation.
- Every plan has a UUID operation directory, durable active marker and journal, update lock, and SHA-256 binding. Server plans, markers, journals, backup metadata, and snapshot metadata additionally carry HMAC-SHA-256 authentication using a random key stored only in the actual server data directory. Windows state directories receive a protected DACL and reject UNC, verbatim, and device paths. Server snapshots also bind the operation ID, plan digest, source schema/ledger, rollback binary, and candidate migration contract.
- Any digest, version, rename, migration preflight, or failure before candidate-service handoff attempts automatic restoration and records a final JSON status. Automatic server rollback restores the database first, verifies the source schema/ledger, and only then restores the old binary. If the candidate service may already have accepted writes, LinkLake deliberately keeps the authenticated marker and requires manual recovery rather than restoring an older snapshot and losing those writes. `linklake-server update recover --yes --data-dir <path>` authenticates the marker and follows the same rule.
- Manual server rollback across a schema or migration-ledger boundary fails closed unless both `--restore-database-snapshot` and `--confirm-data-loss` are supplied with `--yes`.

## Stable interfaces

Client exposes `check-update`, `update download/apply/status/rollback`, hidden helper commands, and `--version`/`--version-json`. Server exposes the same commands plus `update recover`; server `apply`, `rollback`, and `recover` require an explicit data directory so binary and SQLite state cannot be disconnected.

Manager uses:

```text
linklake-client manager-update download --current-version <semver>
linklake-client manager-update apply --install-dir <dir> --manager-pid <pid> --yes
linklake-client manager-update status
linklake-client manager-update rollback --install-dir <dir> --manager-pid <pid> --yes
```

Successful commands return JSON. `apply` and `rollback` return `schema_version=2`, the helper PID, the Manager PID, the status path, the exit deadline, and `requires_manager_exit=true`. The UI exits only after parsing that response, then polls `status` until `succeeded`, `rolled_back`, or `failed`. The machine-readable contract is `docs/manager-update-json-schema.json`; Flutter's lower-level adapter is `apps/linklake_manager/lib/update_protocol.dart`.

Conflicting or unsafe conditions fail closed: another staged/installed tree digest, a changed release version or platform, an unknown install directory, the updater PID supplied as the Manager PID, Manager exit timeout, a remaining directory lock, failed same-volume rename, or failed post-switch validation. No operation edits environment files, SQLite databases, ACME state, certificates, or logs inside or outside the Manager payload.
