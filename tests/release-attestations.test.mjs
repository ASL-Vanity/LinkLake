import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const script = path.join(root, 'scripts', 'prepare-release-attestations.mjs');
const version = '1.0.0-rc.1';

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function writeAsset(directory, name, value = `${name}\n`) {
  fs.writeFileSync(path.join(directory, name), value);
  fs.writeFileSync(path.join(directory, `${name}.sha256`), `${digest(value)}  ${name}\n`, 'ascii');
}

function writeDetailedSbom(directory, assetName) {
  const sbomName = `${assetName}.spdx.json`;
  const value = JSON.stringify({
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: assetName,
    documentNamespace: `https://linklake.invalid/spdx/${encodeURIComponent(assetName)}`,
    creationInfo: { created: '2026-08-03T00:00:00Z', creators: ['Tool: test'] },
    packages: [{ SPDXID: 'SPDXRef-Package-LinkLake', name: 'LinkLake', downloadLocation: 'NOASSERTION' }],
  });
  writeAsset(directory, sbomName, value);
}

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'linklake-release-evidence-'));
  const assets = [
    `linklake-${version}-windows-x86_64.zip`,
    `linklake-${version}-linux-x86_64.tar.gz`,
    `linklake-${version}-macos-arm64.tar.gz`,
    `linklake-manager-${version}-windows-x86_64.zip`,
    `linklake-manager-${version}-linux-x86_64.tar.gz`,
    `linklake-manager-${version}-macos-arm64.tar.gz`,
    `linklake_${version}_amd64.deb`,
    'linklake-1.0.0-0.rc.1.x86_64.rpm',
  ];
  for (const name of assets) {
    writeAsset(directory, name);
    writeDetailedSbom(directory, name);
  }
  return directory;
}

function run(directory) {
  return execFileSync(process.execPath, [script, directory, version], { encoding: 'utf8' });
}

test('prepares deterministic release subjects and an SBOM checksum', () => {
  const directory = fixture();
  try {
    const output = run(directory);
    assert.match(output, /prepared 8 release subjects/);
    const subjects = fs
      .readFileSync(path.join(directory, `linklake-${version}-release-subjects.sha256`), 'ascii')
      .trim()
      .split('\n');
    assert.equal(subjects.length, 8);
    const collection = JSON.parse(
      fs.readFileSync(path.join(directory, `linklake-${version}-release.spdx.json`), 'utf8'),
    );
    assert.equal(collection.packages.length, 8);
    assert.equal(collection.externalDocumentRefs.length, 8);
    assert.equal(collection.relationships.length, 16);
    assert.ok(fs.existsSync(path.join(directory, `linklake-${version}-release.spdx.json.sha256`)));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('rejects a tampered package checksum', () => {
  const directory = fixture();
  try {
    fs.appendFileSync(path.join(directory, `linklake-${version}-linux-x86_64.tar.gz`), 'tamper');
    assert.throws(() => run(directory), /SHA-256 sidecar does not match/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('rejects an incomplete cross-platform package set', () => {
  const directory = fixture();
  try {
    fs.rmSync(path.join(directory, `linklake-manager-${version}-macos-arm64.tar.gz`));
    fs.rmSync(path.join(directory, `linklake-manager-${version}-macos-arm64.tar.gz.sha256`));
    assert.throws(() => run(directory), /exactly one macOS core package and one macOS manager package/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('rejects a malformed or empty SPDX document', () => {
  const directory = fixture();
  try {
    const detail = `linklake-${version}-linux-x86_64.tar.gz.spdx.json`;
    fs.writeFileSync(
      path.join(directory, detail),
      JSON.stringify({ spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', packages: [] }),
    );
    fs.writeFileSync(
      path.join(directory, `${detail}.sha256`),
      `${digest(fs.readFileSync(path.join(directory, detail)))}  ${detail}\n`,
      'ascii',
    );
    assert.throws(() => run(directory), /per-package SBOM does not satisfy/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
