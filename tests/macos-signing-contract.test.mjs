import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

test('macOS signing keeps certificate passwords out of command arguments', () => {
  const setup = read('scripts/setup-macos-signing.sh');
  const importer = read('scripts/import-macos-p12.swift');
  assert.match(importer, /SecPKCS12Import/);
  assert.match(importer, /ProcessInfo\.processInfo\.environment/);
  assert.doesNotMatch(setup, /security\s+import/);
  assert.doesNotMatch(setup, /-P\s+["']?\$LINKLAKE_MACOS_SIGNING_CERT_PASSWORD/);
  assert.doesNotMatch(setup, /--password/);
});

test('macOS source packaging retains its local signing hardening', () => {
  const core = read('scripts/package-macos.sh');
  const manager = read('scripts/package-manager-macos.sh');
  const notarize = read('scripts/notarize-macos-artifact.sh');
  const verifyManager = read('scripts/verify-manager-macos.sh');
  for (const source of [core, manager]) {
    assert.match(source, /--options runtime/);
    assert.match(source, /--timestamp/);
    assert.match(source, /notarize-macos-artifact\.sh/);
  }
  assert.match(notarize, /notarytool submit/);
  assert.match(notarize, /stapler staple/);
  assert.match(verifyManager, /stapler validate/);
  assert.match(verifyManager, /spctl --assess/);
});

test('official releases keep Windows unsigned while preserving Linux and supply-chain gates', () => {
  const workflow = read('.github/workflows/release.yml');
  const ci = read('.github/workflows/ci.yml');
  const releaseAssets = read('scripts/prepare-release-attestations.mjs');
  const packageSboms = read('scripts/generate-package-sboms.mjs');
  const windowsSigner = read('scripts/sign-windows-artifacts.ps1');

  assert.match(workflow, /release tag must start with v/);
  assert.match(workflow, /semver_pattern=/);
  assert.match(workflow, /version_without_build="\$\{version%%\+\*\}"/);
  assert.match(workflow, /if \[\[ "\$version_without_build" == \*-\* \]\]/);
  assert.match(workflow, /RELEASE_PRERELEASE/);
  assert.match(workflow, /if \[\[ "\$RELEASE_PRERELEASE" == true \]\]/);
  assert.match(workflow, /gh api --method PATCH/);
  assert.match(workflow, /-f prerelease=true/);
  assert.match(workflow, /-f prerelease=false/);
  assert.match(workflow, /gh release edit "\$TAG" --notes/);
  assert.match(workflow, /existing_notes="\$\(gh release view "\$TAG" --json body --jq \.body\)"/);
  assert.doesNotMatch(workflow, /\[\[ "\$TAG" == \*-rc\.\* \]\]/);
  assert.match(workflow, /Windows unsigned release packages/);
  assert.equal((workflow.match(/-WindowsSigningMode none/g) ?? []).length, 2);
  assert.match(
    workflow,
    /Windows packages are intentionally unsigned under the personal open-source release policy for LinkLake/,
  );
  assert.doesNotMatch(workflow, /LINKLAKE_WINDOWS_SIGNING_(?:REQUIRED|PFX|CERT)/);
  assert.doesNotMatch(workflow, /RequireAuthenticode/);
  assert.match(workflow, /LINKLAKE_LINUX_SIGNING_REQUIRED:.*startsWith\(github\.ref, 'refs\/tags\/v'\)/);
  assert.match(workflow, /Create and verify production Ed25519 release manifest/);
  assert.match(workflow, /actions\/attest@/);
  assert.match(workflow, /cosign sign --yes/);
  assert.match(windowsSigner, /\[ValidateSet\('none', 'pfx', 'cloud'\)\]/);
  assert.match(windowsSigner, /Windows packages are intentionally unsigned by release policy/);
  assert.match(windowsSigner, /Cloud Windows signing is reserved but not implemented/);
  assert.match(windowsSigner, /Select -Mode pfx explicitly in a future approved signing workflow/);
  assert.doesNotMatch(workflow, /^\s*macos-package:/m);
  assert.doesNotMatch(workflow, /LINKLAKE_MACOS_/);
  assert.doesNotMatch(workflow, /setup-macos-signing\.sh/);
  assert.match(ci, /^\s*macos-test:/m);
  assert.match(ci, /runs-on: macos-latest/);
  assert.match(releaseAssets, /windows-x86_64/);
  assert.match(releaseAssets, /linux-x86_64/);
  assert.doesNotMatch(releaseAssets, /macos-/);
  assert.doesNotMatch(packageSboms, /macos-/);
});
