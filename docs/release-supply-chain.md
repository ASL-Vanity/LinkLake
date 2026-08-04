# Release supply-chain security

Formal LinkLake releases carry three independent evidence layers: package SHA-256 sidecars, GitHub/Sigstore artifact attestations, and the updater's own Ed25519 release manifest. Any failure stops the workflow before assets are uploaded to a GitHub Release.

## Release order

1. Full CI, security scanning, and Windows, Linux, and macOS packaging run concurrently for the same tagged commit. Any failed gate prevents publication. Each platform builds and verifies both core and Manager packages; Linux also produces DEB and RPM packages.
2. Only after every CI, security, and platform-packaging job succeeds does the publish job merge the artifacts, recalculate every `.sha256`, and reject missing platforms, wrong versions, duplicate names, symbolic links, and tampered packages.
3. A pinned Syft version scans every ZIP, tar.gz, DEB, and RPM independently and creates a one-to-one detailed SPDX 2.x SBOM. LinkLake verifies each document's structure, size, and non-empty package set, then writes its SHA-256 sidecar.
4. `scripts/prepare-release-attestations.mjs` links those detailed documents into a release collection through SPDX `externalDocumentRefs` and creates a deterministically sorted `linklake-<version>-release-subjects.sha256`. Both build-provenance and SBOM attestations must use exactly that subject set.
5. `linklake-release-sign` reads the production Ed25519 seed from a CI secret, creates `linklake-release-manifest-v1.json` plus its detached signature, and immediately verifies them. The private key is never passed as a command argument or written to the repository, artifacts, or logs.
6. The GitHub attestations and Ed25519 verification must all succeed before the GitHub Release is created or updated.

## Workflow boundaries

- Every `uses:` reference is pinned to an immutable 40-character commit SHA; human-readable versions are comments only.
- Every checkout uses `persist-credentials: false`.
- Formal release jobs use `actions/cache/restore` and never save a privileged cache.
- Shell commands consume explicit environment variables instead of interpolating GitHub expressions into command text.
- Only the `v*` tag publish job receives `id-token: write`, `attestations: write`, and `artifact-metadata: write`.
- Tag releases reuse CI and security through `workflow_call`. Ordinary branch pushes still run CI directly, while tags no longer start a second duplicate CI run.
- There are no zizmor workflow-security suppressions. `scripts/check-workflow-hardening.mjs`, actionlint, and zizmor enforce the contract.

## Consumer verification

Verify the published SHA-256 first, then the GitHub attestation:

```sh
sha256sum --check linklake-<version>-linux-x86_64.tar.gz.sha256
gh attestation verify linklake-<version>-linux-x86_64.tar.gz --repo OWNER/REPOSITORY
```

The LinkLake updater additionally checks the Ed25519 manifest, asset identity, platform, size, digest, archive paths, internal `release.json`, installed version, and service recovery. GitHub attestations complement rather than replace the LinkLake updater trust root.

## Local gates

```sh
node scripts/check-workflow-hardening.mjs
node --test tests/release-attestations.test.mjs
node scripts/check-security-exceptions.mjs
```

The real SBOM and GitHub OIDC attestations are produced only in a formal tag workflow. Local tests validate the release set, digests, SPDX contract, workflow permissions, and execution order.
