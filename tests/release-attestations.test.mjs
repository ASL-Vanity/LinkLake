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
const version = '1.0.0';

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
    `linklake-manager-${version}-windows-x86_64.zip`,
    `linklake-manager-${version}-linux-x86_64.tar.gz`,
    `linklake_${version}_amd64.deb`,
    'linklake-1.0.0-1.x86_64.rpm',
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

test('prepares deterministic Windows and Linux release subjects and an SBOM checksum', () => {
  const directory = fixture();
  try {
    const output = run(directory);
    assert.match(output, /prepared 6 release subjects/);
    const subjects = fs
      .readFileSync(path.join(directory, `linklake-${version}-release-subjects.sha256`), 'ascii')
      .trim()
      .split('\n');
    assert.equal(subjects.length, 6);
    const collection = JSON.parse(
      fs.readFileSync(path.join(directory, `linklake-${version}-release.spdx.json`), 'utf8'),
    );
    assert.equal(collection.packages.length, 6);
    assert.equal(collection.externalDocumentRefs.length, 6);
    assert.equal(collection.relationships.length, 12);
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

test('rejects an incomplete official Windows and Linux package set', () => {
  const directory = fixture();
  try {
    const name = `linklake-manager-${version}-linux-x86_64.tar.gz`;
    for (const suffix of ['', '.sha256', '.spdx.json', '.spdx.json.sha256']) {
      fs.rmSync(path.join(directory, `${name}${suffix}`));
    }
    assert.throws(() => run(directory), /required release package is missing/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('rejects macOS archives and stray macOS evidence from the official release evidence set', () => {
  const directory = fixture();
  try {
    const name = `linklake-${version}-macos-arm64.tar.gz`;
    writeAsset(directory, name);
    writeDetailedSbom(directory, name);
    assert.throws(() => run(directory), /macOS release evidence is not permitted/);

    fs.rmSync(path.join(directory, name));
    fs.rmSync(path.join(directory, `${name}.sha256`));
    fs.rmSync(path.join(directory, `${name}.spdx.json`));
    fs.rmSync(path.join(directory, `${name}.spdx.json.sha256`));
    const straySbom = `${name}.spdx.json`;
    writeAsset(directory, straySbom);
    assert.throws(() => run(directory), /macOS release evidence is not permitted/);
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
