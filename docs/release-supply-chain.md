# Release supply-chain security

Formal LinkLake releases publish official Windows and Linux binaries only. Under the personal open-source policy for `v1.0.0`, Windows packages are intentionally unsigned: Windows may show an Unknown Publisher or SmartScreen warning. This does not remove the required integrity and source evidence: obtain the package only from the official GitHub Release and verify its SHA-256 sidecar, GitHub file attestation, and the updater's Ed25519 release manifest. Linux additionally requires detached OpenPGP signatures. OCI SBOM/provenance and keyless Cosign signing for GHCR remain required. macOS remains source- and CI-compatible, but it has no official binary asset, updater-manifest entry, automatic-update channel, Developer ID, or notarization gate.

Every SemVer prerelease tag, including `v1.0.0-rc.1`, `v1.0.0-beta.1`, and `v1.0.0-preview.1`, is deliberately published as a GitHub prerelease and keeps the production Ed25519 updater trust root, Linux OpenPGP signatures, GitHub attestations, and GHCR Cosign evidence active. A stable tag has no SemVer prerelease identifier (for example, `v1.0.0`); every valid tag fails closed unless the Linux and updater credentials are present and valid. The official Windows job always selects `-WindowsSigningMode none` and receives no Windows PFX credentials. The retained `-Mode pfx` backend is a future, explicitly approved operator opt-in; `-Mode cloud` is deliberately unimplemented and fails closed. The workflow also reconciles an existing Release's prerelease state before it uploads assets. No Apple credential is part of the release policy.

## Release order

1. Full CI and security scanning run for the tagged commit. The official Windows and Linux package jobs run in parallel; reusable CI continues to build and test macOS source compatibility, but it does not create a release asset.
2. Windows packages are built in explicit unsigned mode and the signer rejects any injected PFX credential in that mode. Every tagged release, including every SemVer prerelease, creates and re-verifies detached Linux OpenPGP signatures for tar.gz, DEB, and RPM packages.
3. Only after both official package jobs succeed may the container job push immutable tags to GHCR. Buildx attaches OCI SBOM/provenance; GitHub publishes image provenance; Cosign keyless-signs the digest and immediately verifies the exact workflow OIDC identity.
4. The aggregate release job re-verifies Linux signatures and all SHA-256 sidecars and rejects missing Windows/Linux packages, macOS archives, wrong versions, duplicate names, links, or tampered packages.
5. Pinned Syft scans each ZIP, tar.gz, DEB, and RPM. LinkLake validates the detailed SPDX documents and builds one deterministic subject list and release collection SBOM.
6. `linklake-release-sign` reads the production Ed25519 seed from a CI secret, creates the canonical manifest plus detached signature, and immediately verifies it. Platform signatures, SBOMs, and container evidence are explicitly excluded from updater-installable assets.
7. The GitHub file attestations, Ed25519 verification, and every earlier platform/image gate must succeed before the GitHub Release is created or updated. Its release notes disclose the unsigned Windows policy.

## Formal release secrets

Every valid SemVer tag requires the Linux OpenPGP and updater secrets below. No Windows PFX Secret belongs to the formal release Secret inventory: the official Windows job is explicitly unsigned for `v1.0.0`. A future, separately approved `-Mode pfx` workflow would require `LINKLAKE_WINDOWS_SIGNING_PFX_B64`, `LINKLAKE_WINDOWS_SIGNING_PFX_PASSWORD`, and `LINKLAKE_WINDOWS_SIGNING_CERT_SHA256`, but this release workflow neither injects nor requires them.

| Platform | Secret | Purpose |
| --- | --- | --- |
| Linux | `LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64` | Base64 OpenPGP private-key export |
| Linux | `LINKLAKE_LINUX_GPG_PASSPHRASE` | Key passphrase sent to GPG over stdin |
| Linux | `LINKLAKE_LINUX_GPG_FINGERPRINT` | Pinned 40-character primary fingerprint |
| Updater | `LINKLAKE_RELEASE_SIGNING_KEY_B64` | Production Ed25519 seed |
| Updater | `LINKLAKE_RELEASE_SIGNING_KEY_ID` | Registered production key ID |

No production private key is generated or committed by the repository. Publication remains intentionally blocked until an offline production updater key is created, its public key is committed, and the required Linux and updater Secrets are configured.

The optional `scripts/generate-linux-release-key.sh` helper is intended only for an operator-controlled offline container or workstation. It refuses overwrites, receives the passphrase through standard input to GnuPG, verifies a test signature with a fresh public-only keyring, and writes only the explicitly selected backup directory. `scripts/verify-linux-release-key-backup.sh` independently checks the encrypted private export, passphrase, public key, and pinned fingerprint. Private-key output must remain outside the repository and be backed up before the matching GitHub Secrets are configured.

## Workflow boundaries

- Every `uses:` reference is pinned to an immutable 40-character commit SHA; human-readable versions are comments only.
- Every checkout uses `persist-credentials: false`.
- Formal release jobs use `actions/cache/restore` and never save a privileged cache.
- The aggregate job downloads only artifacts named `linklake-*`; CI evidence and Buildx diagnostic records cannot enter `dist` or a GitHub Release.
- The official Windows job passes `-WindowsSigningMode none`, injects no Windows PFX credentials, and refuses to silently sign a package if any such credential is present. The optional PFX backend requires an explicit approved workflow; cloud signing is reserved and fails closed.
- macOS source/CI artifacts are intentionally excluded from the official release set before SBOM, attestation, and updater-manifest generation.
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

Windows users should expect the unsigned-package warning, download only the official Release, compare `Get-FileHash -Algorithm SHA256` output with the published `.sha256` sidecar, and verify the GitHub file attestation with `gh attestation verify`. The built-in updater independently validates the production Ed25519 manifest before automated installation. These checks provide integrity and release provenance, but they do not provide the operating-system publisher identity that Authenticode would provide. Use the recorded `image@sha256:...` reference for GHCR and verify its Cosign workflow identity. macOS users must build from source and use the CI/source-validation guidance; there is no official macOS package or native-signing chain to verify.

The LinkLake updater additionally checks the Ed25519 manifest, asset identity, platform, size, digest, archive paths, internal `release.json`, installed version, and service recovery. The formal manifest contains only Windows and Linux install assets, so macOS has no compatible official asset or automatic-update path. Linux OpenPGP, GitHub attestations, and the updater trust root complement rather than replace one another; none substitutes for the missing native Windows publisher identity.

## Local gates

```sh
node scripts/check-workflow-hardening.mjs
node --test tests/release-attestations.test.mjs tests/macos-signing-contract.test.mjs
sh tests/linux-signing-contract.sh
node scripts/check-security-exceptions.mjs
```

The real SBOM and GitHub OIDC attestations are produced only in a formal tag workflow. Local tests validate the release set, digests, SPDX contract, workflow permissions, and execution order.
