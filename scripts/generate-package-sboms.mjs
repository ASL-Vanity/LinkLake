#!/usr/bin/env node
// 使用固定版本的 Syft 为每一个实际发布包生成独立 SPDX 文档。
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';

const [distArgument, version] = process.argv.slice(2);
const syftCommand = process.env.SYFT_CMD;
const semverPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const maximumSbomBytes = 16 * 1024 * 1024;

function fail(message) {
  console.error(`package SBOM generation failed: ${message}`);
  process.exit(1);
}

if (!distArgument || !version || !semverPattern.test(version) || !syftCommand) {
  fail('usage: SYFT_CMD=<trusted-syft> generate-package-sboms.mjs <dist-directory> <semantic-version>');
}

const dist = path.resolve(distArgument);
const distStatus = fs.lstatSync(dist);
if (!distStatus.isDirectory() || distStatus.isSymbolicLink()) fail('dist path must be a real directory');
const syft = path.resolve(syftCommand);
const syftStatus = fs.lstatSync(syft);
if (!syftStatus.isFile() || syftStatus.isSymbolicLink()) fail('SYFT_CMD must point to a real executable file');

const escapedVersion = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const [rpmVersion, ...rpmPrereleaseParts] = version.split('-');
const rpmRelease = rpmPrereleaseParts.length
  ? `0.${rpmPrereleaseParts.join('-').replaceAll('-', '.')}`
  : '1';
const escapedRpmVersion = rpmVersion.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const escapedRpmRelease = rpmRelease.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const patterns = [
  new RegExp(
    `^linklake(-manager)?-${escapedVersion}-(windows-x86_64\\.zip|linux-x86_64\\.tar\\.gz|macos-(?:x86_64|arm64|aarch64)\\.tar\\.gz)$`,
  ),
  new RegExp(`^linklake_${escapedVersion}_(?:amd64|arm64)\\.deb$`),
  new RegExp(
    `^linklake-${escapedRpmVersion}-${escapedRpmRelease}(?:\\.[A-Za-z0-9_]+)*\\.(?:x86_64|aarch64)\\.rpm$`,
  ),
];

const assets = fs
  .readdirSync(dist, { withFileTypes: true })
  .filter((entry) => entry.isFile() && !entry.isSymbolicLink() && patterns.some((pattern) => pattern.test(entry.name)))
  .map((entry) => entry.name)
  .sort((left, right) => left.localeCompare(right, 'en'));
if (assets.length === 0) fail('no release packages were found');

for (const name of assets) {
  const asset = path.join(dist, name);
  const sbom = `${asset}.spdx.json`;
  const result = spawnSync(syft, ['scan', `file:${asset}`, '-o', `spdx-json=${sbom}`], {
    cwd: dist,
    env: { ...process.env, SYFT_CHECK_FOR_APP_UPDATE: 'false' },
    stdio: 'inherit',
    windowsHide: true,
  });
  if (result.error) fail(`could not start Syft for ${name}: ${result.error.message}`);
  if (result.status !== 0) fail(`Syft failed for ${name} with exit code ${result.status}`);

  const status = fs.statSync(sbom);
  if (status.size === 0 || status.size > maximumSbomBytes) {
    fail(`SBOM for ${name} must be non-empty and no larger than 16 MiB`);
  }
  let document;
  try {
    document = JSON.parse(fs.readFileSync(sbom, 'utf8'));
  } catch (error) {
    fail(`Syft produced invalid JSON for ${name}: ${error.message}`);
  }
  if (
    !/^SPDX-2\.\d+$/.test(document.spdxVersion ?? '') ||
    document.dataLicense !== 'CC0-1.0' ||
    typeof document.documentNamespace !== 'string' ||
    !Array.isArray(document.packages) ||
    document.packages.length === 0
  ) {
    fail(`Syft produced an incomplete SPDX document for ${name}`);
  }
  const bytes = fs.readFileSync(sbom);
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  const sbomName = path.basename(sbom);
  fs.writeFileSync(`${sbom}.sha256`, `${digest}  ${sbomName}\n`, 'ascii');
}

console.log(`generated and validated ${assets.length} per-package SPDX SBOMs`);
