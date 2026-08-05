#!/usr/bin/env node
// 对工作流执行本地、确定性的最小权限与不可变 Action 引用检查。
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workflowDirectory = path.join(root, '.github', 'workflows');

function fail(message) {
  console.error(`workflow hardening check failed: ${message}`);
  process.exit(1);
}

function workflowJob(text, jobId) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((line) => line === `  ${jobId}:`);
  if (start < 0) fail(`workflow is missing job ${jobId}`);
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^  [A-Za-z0-9_-]+:\s*$/.test(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

const workflowFiles = fs
  .readdirSync(workflowDirectory)
  .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
  .sort();

for (const name of workflowFiles) {
  const text = fs.readFileSync(path.join(workflowDirectory, name), 'utf8');
  const lines = text.split(/\r?\n/);
  lines.forEach((line, index) => {
    const uses = line.match(/^\s*-?\s*uses:\s*([^\s#]+)(?:\s+#.*)?$/);
    const localWorkflow = /^\.\/\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(uses?.[1] ?? '');
    const pinnedAction = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$/.test(
      uses?.[1] ?? '',
    );
    if (uses && !localWorkflow && !pinnedAction) {
      fail(`${name}:${index + 1} must pin uses to a full 40-character commit SHA`);
    }
  });

  for (let index = 0; index < lines.length; index += 1) {
    if (!/uses:\s*actions\/checkout@[0-9a-f]{40}/.test(lines[index])) continue;
    const indent = lines[index].match(/^\s*/)[0].length;
    let block = '';
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const current = lines[cursor];
      const currentIndent = current.match(/^\s*/)[0].length;
      if (/^\s*-\s+/.test(current) && currentIndent <= indent) break;
      block += `${current}\n`;
    }
    if (!/^\s*persist-credentials:\s*false\s*$/m.test(block)) {
      fail(`${name}:${index + 1} checkout must disable persisted credentials`);
    }
  }
}

const release = fs.readFileSync(path.join(workflowDirectory, 'release.yml'), 'utf8');
const ci = fs.readFileSync(path.join(workflowDirectory, 'ci.yml'), 'utf8');
const security = fs.readFileSync(path.join(workflowDirectory, 'security.yml'), 'utf8');
const webuiSmoke = fs.readFileSync(path.join(root, 'scripts', 'run-webui-smoke.ps1'), 'utf8');
const windowsSigner = fs.readFileSync(path.join(root, 'scripts', 'sign-windows-artifacts.ps1'), 'utf8');
const linuxSigner = fs.readFileSync(path.join(root, 'scripts', 'sign-linux-artifacts.sh'), 'utf8');
const windowsPackage = fs.readFileSync(path.join(root, 'scripts', 'package-windows.ps1'), 'utf8');
const windowsManagerPackage = fs.readFileSync(
  path.join(root, 'scripts', 'package-manager-windows.ps1'),
  'utf8',
);
const packageSboms = fs.readFileSync(path.join(root, 'scripts', 'generate-package-sboms.mjs'), 'utf8');
const nativeLinuxContractRunner = fs.readFileSync(
  path.join(root, 'tests', 'run-native-linux-package-contracts.sh'),
  'utf8',
);
const nativeLinuxContract = fs.readFileSync(
  path.join(root, 'tests', 'native-linux-package-contract.sh'),
  'utf8',
);
const nativeLinuxDebDockerfile = fs.readFileSync(
  path.join(root, 'tests', 'native-linux-package-contract-deb.Dockerfile'),
  'utf8',
);
const nativeLinuxRpmDockerfile = fs.readFileSync(
  path.join(root, 'tests', 'native-linux-package-contract-rpm.Dockerfile'),
  'utf8',
);
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const packageLock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
if (!/^\s*workflow_call:\s*$/m.test(ci) || !/^\s*workflow_call:\s*$/m.test(security)) {
  fail('CI and security workflows must remain reusable by the release workflow');
}
for (const reusable of ['./.github/workflows/ci.yml', './.github/workflows/security.yml']) {
  if (!release.includes(`uses: ${reusable}`)) {
    fail(`release workflow does not reuse ${reusable}`);
  }
}
const publishJob = workflowJob(release, 'publish');
for (const gate of ['ci-gate', 'security-gate', 'container-package']) {
  if (!new RegExp(`^      - ${gate}\\s*$`, 'm').test(publishJob)) {
    fail(`release publication does not depend on ${gate}`);
  }
}
const containerJob = workflowJob(release, 'container-package');
for (const gate of ['ci-gate', 'security-gate', 'windows-package', 'linux-package']) {
  if (!new RegExp(`^      - ${gate}\\s*$`, 'm').test(containerJob)) {
    fail(`container publication does not depend on ${gate}`);
  }
}
if (/^\s*macos-package:/m.test(release) || /LINKLAKE_MACOS_|setup-macos-signing\.sh/.test(release)) {
  fail('official release workflow must exclude macOS assets and Apple signing credentials');
}
if (/macos-/.test(packageSboms)) {
  fail('per-package release SBOM generation must exclude macOS assets before attestation preparation');
}
for (const marker of [
  'webui-smoke:',
  'Install locked WebUI test dependencies',
  'npm ci',
  'node ./node_modules/playwright/cli.js install chromium',
  'run-webui-smoke.ps1',
  'Upload WebUI smoke evidence',
]) {
  if (!ci.includes(marker)) fail(`CI WebUI smoke contract is missing ${marker}`);
}
const playwrightVersion = packageJson.devDependencies?.playwright;
if (!/^\d+\.\d+\.\d+$/.test(playwrightVersion ?? '')) {
  fail('Playwright must use an exact semantic version in package.json');
}
const lockedPlaywright = packageLock.packages?.['node_modules/playwright'];
if (
  packageLock.lockfileVersion !== 3 ||
  lockedPlaywright?.version !== playwrightVersion ||
  !/^sha512-[A-Za-z0-9+/=]+$/.test(lockedPlaywright?.integrity ?? '')
) {
  fail('package-lock.json does not pin the declared Playwright package and integrity');
}
if (/\$env:NODE_PATH\s*=|codex-runtimes|C:\\Users\\Laker/i.test(webuiSmoke)) {
  fail('WebUI smoke test must not depend on a developer-specific Node runtime path');
}
if (!security.includes('tests/native-linux-package-contract.test.mjs')) {
  fail('security workflow must run the native Linux package release-contract test');
}
if (/uses:\s*actions\/cache@[0-9a-f]{40}/.test(release)) {
  fail('release workflow must use actions/cache/restore and never save a privileged cache');
}
for (const required of [
  'id-token: write',
  'attestations: write',
  'artifact-metadata: write',
  'actions/attest@',
  'anchore/sbom-action/download-syft@',
  'generate-package-sboms.mjs',
  'prepare-release-attestations.mjs',
  'release-subjects.sha256',
  'LINKLAKE_LINUX_SIGNING_REQUIRED',
  'sign-linux-artifacts.sh',
  'verify-linux-release-signatures.sh',
  'container-package:',
  'packages: write',
  'docker/build-push-action@',
  'sigstore/cosign-installer@',
  'actions/attest-build-provenance@',
  'cosign sign --yes',
  'cosign verify',
]) {
  if (!release.includes(required)) fail(`release workflow is missing ${required}`);
}
const windowsJob = workflowJob(release, 'windows-package');
for (const marker of [
  'Windows unsigned release packages',
  'Verify Windows package integrity (unsigned policy)',
  'Verify Flutter manager Windows package integrity (unsigned policy)',
]) {
  if (!windowsJob.includes(marker)) {
    fail(`Windows unsigned release policy is missing ${marker}`);
  }
}
if ((windowsJob.match(/-WindowsSigningMode none/g) ?? []).length !== 2) {
  fail('both Windows packages must explicitly select unsigned signing mode');
}
if (/LINKLAKE_WINDOWS_SIGNING_(?:REQUIRED|PFX|CERT)/.test(release) || /RequireAuthenticode/.test(windowsJob)) {
  fail('official release workflow must not inject Windows signing credentials or require Authenticode');
}
if (!release.includes('Windows packages are intentionally unsigned under the personal open-source release policy for LinkLake')) {
  fail('published release notes must disclose the unsigned Windows policy');
}
if (
  !release.includes('RELEASE_PRERELEASE') ||
  !release.includes('version_without_build="${version%%+*}"') ||
  !release.includes('if [[ "$version_without_build" == *-* ]]') ||
  !release.includes('if [[ "$RELEASE_PRERELEASE" == true ]]')
) {
  fail('all SemVer prerelease tags must publish as GitHub prereleases');
}
for (const marker of [
  'gh api --method PATCH',
  '-f prerelease=true',
  '-f prerelease=false',
  'gh release edit "$TAG" --notes',
  'existing_notes="$(gh release view "$TAG" --json body --jq .body)"',
]) {
  if (!release.includes(marker)) {
    fail(`existing release channel or unsigned-notice reconciliation is missing ${marker}`);
  }
}
if (release.includes('[[ "$TAG" == *-rc.* ]]')) {
  fail('release classification must not special-case only RC suffixes');
}
if (!release.includes("LINKLAKE_LINUX_SIGNING_REQUIRED: ${{ startsWith(github.ref, 'refs/tags/v')")) {
  fail('every tagged release, including release candidates, must require Linux OpenPGP signing');
}
const linuxJob = workflowJob(release, 'linux-package');
const nativeLinuxOrder = [
  'Verify DEB and RPM packages',
  'Verify native DEB package install and upgrade contract',
  'Verify native RPM package install and upgrade contract',
  'Sign Linux release packages with OpenPGP',
].map((marker) => linuxJob.indexOf(marker));
if (
  nativeLinuxOrder.some((value) => value < 0) ||
  nativeLinuxOrder.some((value, index) => index > 0 && value <= nativeLinuxOrder[index - 1])
) {
  fail('native DEB/RPM installation contracts must run after package verification and before Linux signing');
}
for (const invocation of [
  'sh tests/run-native-linux-package-contracts.sh deb',
  'sh tests/run-native-linux-package-contracts.sh rpm',
]) {
  if (!linuxJob.includes(invocation)) {
    fail(`Linux release job is missing native package contract invocation: ${invocation}`);
  }
}
for (const marker of [
  'timeout --foreground 600 docker build',
  'timeout --foreground 300 docker run',
  '--pull=false',
  '--network none',
  '--user 0:0',
  '--security-opt no-new-privileges:true',
  '--memory 1g',
  '--pids-limit 256',
  'readonly',
  '--tmpfs /tmp:exec,mode=1777,size=1g',
  'mktemp -d',
]) {
  if (!nativeLinuxContractRunner.includes(marker)) {
    fail(`native Linux package contract runner is missing ${marker}`);
  }
}
if (/(?:--env|-e)\s+(?:LINKLAKE_|GITHUB_TOKEN|GH_TOKEN)/.test(nativeLinuxContractRunner) ||
    /LINKLAKE_(?:LINUX_GPG|RELEASE_SIGNING)_/.test(nativeLinuxContractRunner)) {
  fail('native Linux package containers must not receive release signing credentials');
}
for (const [name, dockerfile] of [
  ['DEB', nativeLinuxDebDockerfile],
  ['RPM', nativeLinuxRpmDockerfile],
]) {
  if (!/^FROM\s+[^\s]+@sha256:[a-f0-9]{64}$/m.test(dockerfile) || /^\s*(?:ADD|COPY)\s+/m.test(dockerfile)) {
    fail(`${name} native package contract image must use a pinned base and no workspace build context`);
  }
}
if (
  !nativeLinuxContract.includes('assert_new_installation_ready') ||
  !nativeLinuxContract.includes('assert_operator_configuration_is_preserved') ||
  !nativeLinuxContract.includes('systemd-analyze verify')
) {
  fail('native Linux package contract must cover first installation, upgrades, configuration preservation, and systemd units');
}
if (!release.includes('Create and verify production Ed25519 release manifest')) {
  fail('every tagged release must retain the production updater signing gate');
}
if (!release.includes("pattern: 'linklake-*'")) {
  fail('release aggregation must download only LinkLake publication artifacts');
}
if ((release.match(/uses:\s*actions\/attest@[0-9a-f]{40}/g) ?? []).length !== 2) {
  fail('release workflow must create exactly one provenance and one SBOM attestation');
}

const order = [
  'Reverify Linux OpenPGP signatures after artifact transfer',
  'Generate per-package SPDX SBOMs',
  'Verify packages and prepare attestation subjects',
  'Create and verify production Ed25519 release manifest',
  'Attest release build provenance',
  'Attest release SBOM',
  'Publish GitHub release',
].map((marker) => release.indexOf(marker));
if (order.some((value) => value < 0) || order.some((value, index) => index > 0 && value <= order[index - 1])) {
  fail('release evidence, signing, attestation, and publication steps are in an unsafe order');
}

if (
  !windowsSigner.includes("[ValidateSet('none', 'pfx', 'cloud')]") ||
  !windowsSigner.includes('Windows packages are intentionally unsigned by release policy') ||
  !windowsSigner.includes('Cloud Windows signing is reserved but not implemented') ||
  !windowsSigner.includes('Select -Mode pfx explicitly in a future approved signing workflow')
) {
  fail('Windows signing policy must make unsigned release mode and the reserved cloud-signing boundary explicit');
}
if (!windowsSigner.includes('Import-PfxCertificate') || !windowsSigner.includes('/tr $timestampUri.AbsoluteUri')) {
  fail('the optional PFX signing backend must retain temporary import and RFC 3161 timestamp verification');
}
if (
  !windowsPackage.includes('sign-windows-artifacts.ps1') ||
  !windowsManagerPackage.includes('sign-windows-artifacts.ps1') ||
  !windowsPackage.includes('-Mode $WindowsSigningMode') ||
  !windowsManagerPackage.includes('-Mode $WindowsSigningMode')
) {
  fail('Windows core and Manager packages must invoke the shared explicit signing policy');
}
if (/\/(?:p|p7)\s+\$env:LINKLAKE_WINDOWS_SIGNING_PFX_PASSWORD/i.test(windowsSigner)) {
  fail('Windows signing password must not be passed to SignTool arguments');
}
if (!linuxSigner.includes('--passphrase-fd 0') || /--passphrase(?:=|\s+)["']?\$LINKLAKE_LINUX_GPG_PASSPHRASE/.test(linuxSigner)) {
  fail('Linux signing passphrase must be supplied through standard input');
}
const releaseLines = release.split(/\r?\n/);
for (let index = 0; index < releaseLines.length; index += 1) {
  const line = releaseLines[index];
  const single = line.match(/^\s*run:\s+(.+)$/);
  if (single && single[1].includes('${{')) {
    fail(`release.yml:${index + 1} interpolates a GitHub expression directly into a shell command`);
  }
  if (!/^\s*run:\s*[|>]\s*$/.test(line)) continue;
  const indent = line.match(/^\s*/)[0].length;
  for (let cursor = index + 1; cursor < releaseLines.length; cursor += 1) {
    const current = releaseLines[cursor];
    if (current.trim() && current.match(/^\s*/)[0].length <= indent) break;
    if (current.includes('${{')) {
      fail(`release.yml:${cursor + 1} interpolates a GitHub expression directly into a shell block`);
    }
  }
}

if (fs.existsSync(path.join(root, '.github', 'zizmor.yml'))) {
  fail('zizmor suppressions are not allowed after workflow hardening');
}

console.log(`validated ${workflowFiles.length} hardened GitHub Actions workflows`);
