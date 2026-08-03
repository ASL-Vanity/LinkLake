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

const workflowFiles = fs
  .readdirSync(workflowDirectory)
  .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
  .sort();

for (const name of workflowFiles) {
  const text = fs.readFileSync(path.join(workflowDirectory, name), 'utf8');
  const lines = text.split(/\r?\n/);
  lines.forEach((line, index) => {
    const uses = line.match(/^\s*-?\s*uses:\s*([^\s#]+)(?:\s+#.*)?$/);
    if (uses && !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$/.test(uses[1])) {
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
]) {
  if (!release.includes(required)) fail(`release workflow is missing ${required}`);
}
if ((release.match(/uses:\s*actions\/attest@[0-9a-f]{40}/g) ?? []).length !== 2) {
  fail('release workflow must create exactly one provenance and one SBOM attestation');
}

const order = [
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
