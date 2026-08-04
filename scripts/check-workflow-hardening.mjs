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
const macosSetup = fs.readFileSync(path.join(root, 'scripts', 'setup-macos-signing.sh'), 'utf8');
const macosImporter = fs.readFileSync(path.join(root, 'scripts', 'import-macos-p12.swift'), 'utf8');
const windowsPackage = fs.readFileSync(path.join(root, 'scripts', 'package-windows.ps1'), 'utf8');
const windowsManagerPackage = fs.readFileSync(
  path.join(root, 'scripts', 'package-manager-windows.ps1'),
  'utf8',
);
const macosPackage = fs.readFileSync(path.join(root, 'scripts', 'package-macos.sh'), 'utf8');
const macosManagerPackage = fs.readFileSync(path.join(root, 'scripts', 'package-manager-macos.sh'), 'utf8');
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
for (const gate of ['ci-gate', 'security-gate', 'windows-package', 'linux-package', 'macos-package']) {
  if (!new RegExp(`^      - ${gate}\\s*$`, 'm').test(containerJob)) {
    fail(`container publication does not depend on ${gate}`);
  }
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
  'LINKLAKE_WINDOWS_SIGNING_REQUIRED',
  'LINKLAKE_LINUX_SIGNING_REQUIRED',
  'sign-linux-artifacts.sh',
  'verify-linux-release-signatures.sh',
  'LINKLAKE_MACOS_SIGNING_REQUIRED',
  'setup-macos-signing.sh',
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
const stableNativeSigningGate =
  "startsWith(github.ref, 'refs/tags/v') && !contains(github.ref_name, '-')";
if ((release.match(new RegExp(stableNativeSigningGate.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) ?? []).length < 3) {
  fail('stable releases must require Windows and macOS native signing while prereleases remain testable');
}
if (!release.includes("LINKLAKE_LINUX_SIGNING_REQUIRED: ${{ startsWith(github.ref, 'refs/tags/v')")) {
  fail('every tagged release, including release candidates, must require Linux OpenPGP signing');
}
if (!release.includes('Create and verify production Ed25519 release manifest')) {
  fail('every tagged release must retain the production updater signing gate');
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

if (!windowsSigner.includes('Import-PfxCertificate') || !windowsSigner.includes('/tr $timestampUri.AbsoluteUri')) {
  fail('Windows release signing must import a temporary PFX and require an RFC 3161 timestamp');
}
if (
  !windowsPackage.includes('sign-windows-artifacts.ps1') ||
  !windowsManagerPackage.includes('sign-windows-artifacts.ps1')
) {
  fail('Windows core and Manager packages must invoke the shared Authenticode signer');
}
if (/\/(?:p|p7)\s+\$env:LINKLAKE_WINDOWS_SIGNING_PFX_PASSWORD/i.test(windowsSigner)) {
  fail('Windows signing password must not be passed to SignTool arguments');
}
if (!linuxSigner.includes('--passphrase-fd 0') || /--passphrase(?:=|\s+)["']?\$LINKLAKE_LINUX_GPG_PASSPHRASE/.test(linuxSigner)) {
  fail('Linux signing passphrase must be supplied through standard input');
}
if (!macosImporter.includes('SecPKCS12Import') || /security\s+import/.test(macosSetup)) {
  fail('macOS P12 import must use Security.framework without a password-bearing security command');
}
if (
  !macosPackage.includes('notarize-macos-artifact.sh') ||
  !macosManagerPackage.includes('notarize-macos-artifact.sh')
) {
  fail('macOS core and Manager packages must pass Apple notarization');
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
