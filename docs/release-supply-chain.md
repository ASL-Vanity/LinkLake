# Release supply-chain security

Formal LinkLake releases combine independent evidence chains: SHA-256 sidecars; Windows Authenticode; macOS Developer ID plus Apple notarization; Linux detached OpenPGP signatures; OCI SBOM/provenance and keyless Cosign signing for GHCR; GitHub file attestations; and the updater's own Ed25519 release manifest. Any required failure closes the release.

## Release order

1. Full CI, security scanning, and the three platform package jobs run concurrently for the tagged commit.
2. Windows signs every packaged EXE/DLL with a fingerprint-pinned Authenticode identity and RFC 3161 timestamp. macOS uses a Developer ID Application identity, hardened runtime, App Store Connect API notarization, and staples the Manager app. Linux creates and re-verifies detached OpenPGP signatures for tar.gz, DEB, and RPM packages.
3. Only after all three native-signing jobs succeed may the container job push immutable tags to GHCR. Buildx attaches OCI SBOM/provenance; GitHub publishes image provenance; Cosign keyless-signs the digest and immediately verifies the exact workflow OIDC identity.
4. The aggregate release job re-verifies Linux signatures and all SHA-256 sidecars and rejects missing platforms, wrong versions, duplicate names, links, or tampered packages.
5. Pinned Syft scans each ZIP, tar.gz, DEB, and RPM. LinkLake validates the detailed SPDX documents and builds one deterministic subject list and release collection SBOM.
6. `linklake-release-sign` reads the production Ed25519 seed from a CI secret, creates the canonical manifest plus detached signature, and immediately verifies it. Platform signatures, SBOMs, and container evidence are explicitly excluded from updater-installable assets.
7. The GitHub file attestations, Ed25519 verification, and every earlier platform/image gate must succeed before the GitHub Release is created or updated.

## Formal release secrets

Tagged releases require the following GitHub Actions Secrets and fail closed on missing values or fingerprint mismatches:

| Platform | Secret | Purpose |
| --- | --- | --- |
| Windows | `LINKLAKE_WINDOWS_SIGNING_PFX_B64` | Base64 Authenticode PFX |
| Windows | `LINKLAKE_WINDOWS_SIGNING_PFX_PASSWORD` | PFX password |
| Windows | `LINKLAKE_WINDOWS_SIGNING_CERT_SHA256` | Pinned DER certificate SHA-256 |
| macOS | `LINKLAKE_MACOS_SIGNING_CERT_P12_B64` | Base64 Developer ID Application P12 |
| macOS | `LINKLAKE_MACOS_SIGNING_CERT_PASSWORD` | P12 password |
| macOS | `LINKLAKE_MACOS_SIGNING_IDENTITY` | `Developer ID Application: ...` identity |
| macOS | `LINKLAKE_MACOS_SIGNING_CERT_SHA256` | Pinned Developer ID certificate SHA-256 |
| macOS | `LINKLAKE_APPLE_API_KEY_P8_B64` | App Store Connect API private key |
| macOS | `LINKLAKE_APPLE_API_KEY_ID` | 10-character API key ID |
| macOS | `LINKLAKE_APPLE_API_ISSUER_ID` | API issuer UUID |
| Linux | `LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64` | Base64 OpenPGP private-key export |
| Linux | `LINKLAKE_LINUX_GPG_PASSPHRASE` | Key passphrase sent to GPG over stdin |
| Linux | `LINKLAKE_LINUX_GPG_FINGERPRINT` | Pinned 40-character primary fingerprint |
| Updater | `LINKLAKE_RELEASE_SIGNING_KEY_B64` | Production Ed25519 seed |
| Updater | `LINKLAKE_RELEASE_SIGNING_KEY_ID` | Registered production key ID |

No production private key is generated or committed. The repository still contains only the development Ed25519 public key; formal publication remains intentionally blocked until an offline production key is created, its public key is committed, and all required Secrets are configured.

## Workflow boundaries

- Every `uses:` reference is pinned to an immutable 40-character commit SHA; human-readable versions are comments only.
- Every checkout uses `persist-credentials: false`.
- Formal release jobs use `actions/cache/restore` and never save a privileged cache.
- Shell commands consume explicit environment variables instead of interpolating GitHub expressions into command text.
- Only `v*` tag evidence jobs receive OIDC/attestation permissions. The container job additionally receives only the `packages: write` permission needed for GHCR.
- Tag releases reuse CI and security through `workflow_call`. Ordinary branch pushes still run CI directly, while tags no longer start a second duplicate CI run.
- There are no zizmor workflow-security suppressions. `scripts/check-workflow-hardening.mjs`, actionlint, and zizmor enforce the contract.

## Consumer verification

Verify the published SHA-256 first, then the GitHub attestation:

```sh
sha256sum --check linklake-<version>-linux-x86_64.tar.gz.sha256
gh attestation verify linklake-<version>-linux-x86_64.tar.gz --repo OWNER/REPOSITORY
```

Linux consumers should pin the published public-key fingerprint before verifying the detached signature:

```sh
gpg --import linklake-linux-release-public-key.asc
gpg --fingerprint <pinned-40-character-fingerprint>
gpg --verify linklake-<version>-linux-x86_64.tar.gz.asc linklake-<version>-linux-x86_64.tar.gz
```

Use the recorded `image@sha256:...` reference for GHCR and verify its Cosign workflow identity. Windows consumers can use `Get-AuthenticodeSignature`; macOS consumers can use `codesign --verify`, `spctl --assess`, and `xcrun stapler validate`.

The LinkLake updater additionally checks the Ed25519 manifest, asset identity, platform, size, digest, archive paths, internal `release.json`, installed version, and service recovery. Native signatures, GitHub attestations, and the updater trust root complement rather than replace one another.

## Local gates

```sh
node scripts/check-workflow-hardening.mjs
node --test tests/release-attestations.test.mjs tests/macos-signing-contract.test.mjs
sh tests/linux-signing-contract.sh
node scripts/check-security-exceptions.mjs
```

The real SBOM and GitHub OIDC attestations are produced only in a formal tag workflow. Local tests validate the release set, digests, SPDX contract, workflow permissions, and execution order.
