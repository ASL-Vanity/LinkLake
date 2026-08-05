#!/usr/bin/env node
// 校验发布资产与 SHA-256 旁车文件，并生成供 GitHub 证明使用的固定主体清单。
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const [distArgument, version] = process.argv.slice(2);
const semverPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const digestPattern = /^[0-9a-f]{64}$/;
const maximumSbomBytes = 16 * 1024 * 1024;

function fail(message) {
  console.error(`release attestation preparation failed: ${message}`);
  process.exit(1);
}

if (!distArgument || !version || !semverPattern.test(version)) {
  fail('usage: prepare-release-attestations.mjs <dist-directory> <semantic-version>');
}

const dist = path.resolve(distArgument);
let distStatus;
try {
  distStatus = fs.lstatSync(dist);
} catch (error) {
  fail(`cannot inspect dist directory: ${error.message}`);
}
if (!distStatus.isDirectory() || distStatus.isSymbolicLink()) {
  fail('dist path must be a real directory');
}

const entries = fs.readdirSync(dist, { withFileTypes: true });
const files = new Map();
const caseInsensitiveNames = new Set();
for (const entry of entries) {
  if (!entry.isFile() || entry.isSymbolicLink()) {
    fail(`dist must contain only regular files: ${entry.name}`);
  }
  const folded = entry.name.toLocaleLowerCase('en-US');
  if (caseInsensitiveNames.has(folded)) {
    fail(`case-insensitive duplicate asset name: ${entry.name}`);
  }
  caseInsensitiveNames.add(folded);
  files.set(entry.name, path.join(dist, entry.name));
}

for (const reserved of ['linklake-release-manifest-v1.json', 'linklake-release-manifest-v1.sig']) {
  if (files.has(reserved)) {
    fail(`stale signed release metadata is not allowed before signing: ${reserved}`);
  }
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function verifySidecar(sidecarName) {
  const sidecar = files.get(sidecarName);
  const text = fs.readFileSync(sidecar, 'ascii');
  const match = text.match(/^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)\r?\n?$/);
  if (!match) {
    fail(`invalid SHA-256 sidecar format: ${sidecarName}`);
  }
  const targetName = sidecarName.slice(0, -'.sha256'.length);
  if (match[2] !== targetName || path.basename(match[2]) !== match[2]) {
    fail(`SHA-256 sidecar targets an unexpected file: ${sidecarName}`);
  }
  const target = files.get(targetName);
  if (!target) {
    fail(`SHA-256 sidecar target is missing: ${targetName}`);
  }
  const actual = sha256(target);
  if (!digestPattern.test(match[1]) || match[1] !== actual) {
    fail(`SHA-256 sidecar does not match ${targetName}`);
  }
}

for (const name of files.keys()) {
  if (name.endsWith('.sha256')) verifySidecar(name);
}

const escapedVersion = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const macosEvidencePattern = new RegExp(
  `^linklake(?:-manager)?-${escapedVersion}-macos(?:[-._]|$)`,
  'i',
);
for (const name of files.keys()) {
  if (macosEvidencePattern.test(name)) {
    fail(`macOS release evidence is not permitted: ${name}`);
  }
}
const archivePattern = new RegExp(
  `^linklake(-manager)?-${escapedVersion}-(windows-x86_64\\.zip|linux-x86_64\\.tar\\.gz)$`,
);
const [rpmVersion, ...rpmPrereleaseParts] = version.split('-');
const rpmRelease = rpmPrereleaseParts.length
  ? `0.${rpmPrereleaseParts.join('-').replaceAll('-', '.')}`
  : '1';
const escapedRpmVersion = rpmVersion.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const escapedRpmRelease = rpmRelease.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const debPattern = new RegExp(`^linklake_${escapedVersion}_(?:amd64|arm64)\\.deb$`);
const rpmPattern = new RegExp(
  `^linklake-${escapedRpmVersion}-${escapedRpmRelease}(?:\\.[A-Za-z0-9_]+)*\\.(?:x86_64|aarch64)\\.rpm$`,
);
const primaryAssets = [...files.keys()]
  .filter((name) => archivePattern.test(name) || debPattern.test(name) || rpmPattern.test(name))
  .sort((left, right) => left.localeCompare(right, 'en'));

for (const name of files.keys()) {
  if (/^linklake.*\.(?:zip|tar\.gz|deb|rpm)$/.test(name) && !primaryAssets.includes(name)) {
    fail(`release package name does not match the requested version or platform contract: ${name}`);
  }
}

const requiredArchiveSuffixes = [
  `linklake-${version}-windows-x86_64.zip`,
  `linklake-${version}-linux-x86_64.tar.gz`,
  `linklake-manager-${version}-windows-x86_64.zip`,
  `linklake-manager-${version}-linux-x86_64.tar.gz`,
];
for (const name of requiredArchiveSuffixes) {
  if (!primaryAssets.includes(name)) fail(`required release package is missing: ${name}`);
}

if (!primaryAssets.some((name) => name.endsWith('.deb'))) fail('a DEB package is required');
if (!primaryAssets.some((name) => name.endsWith('.rpm'))) fail('an RPM package is required');

for (const name of primaryAssets) {
  if (!files.has(`${name}.sha256`)) fail(`release package has no SHA-256 sidecar: ${name}`);
}

if (primaryAssets.length > 1024) fail('GitHub attestation subject limit exceeded');
const subjectsName = `linklake-${version}-release-subjects.sha256`;
const subjects = primaryAssets.map((name) => `${sha256(files.get(name))}  ${name}`).join('\n');
fs.writeFileSync(path.join(dist, subjectsName), `${subjects}\n`, 'ascii');

function readSpdx(name) {
  const file = files.get(name);
  if (!file) fail(`per-package SBOM is missing: ${name}`);
  if (!files.has(`${name}.sha256`)) fail(`per-package SBOM has no SHA-256 sidecar: ${name}`);
  const status = fs.statSync(file);
  if (status.size === 0 || status.size > maximumSbomBytes) {
    fail(`per-package SBOM must be non-empty and no larger than 16 MiB: ${name}`);
  }
  let document;
  try {
    document = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    fail(`per-package SBOM is not valid JSON (${name}): ${error.message}`);
  }
  if (
    !/^SPDX-2\.\d+$/.test(document.spdxVersion ?? '') ||
    document.dataLicense !== 'CC0-1.0' ||
    typeof document.documentNamespace !== 'string' ||
    !Array.isArray(document.packages) ||
    document.packages.length === 0
  ) {
    fail(`per-package SBOM does not satisfy the required SPDX 2.x contract: ${name}`);
  }
  return { document, file };
}

const releaseSetDigest = crypto.createHash('sha256').update(`${subjects}\n`, 'utf8').digest('hex');
const describedPackages = [];
const externalDocumentRefs = [];
const relationships = [];
for (const [index, assetName] of primaryAssets.entries()) {
  const detailName = `${assetName}.spdx.json`;
  const detail = readSpdx(detailName);
  const assetDigest = sha256(files.get(assetName));
  const packageId = `SPDXRef-ReleaseAsset-${index + 1}-${assetDigest.slice(0, 12)}`;
  const documentId = `DocumentRef-Asset-${index + 1}-${assetDigest.slice(0, 12)}`;
  describedPackages.push({
    SPDXID: packageId,
    name: assetName,
    versionInfo: version,
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    checksums: [{ algorithm: 'SHA256', checksumValue: assetDigest }],
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
  });
  externalDocumentRefs.push({
    externalDocumentId: documentId,
    spdxDocument: detail.document.documentNamespace,
    checksum: { algorithm: 'SHA256', checksumValue: sha256(detail.file) },
  });
  relationships.push(
    {
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: packageId,
    },
    {
      spdxElementId: packageId,
      relationshipType: 'DESCRIBED_BY',
      relatedSpdxElement: `${documentId}:SPDXRef-DOCUMENT`,
    },
  );
}

const sbomName = `linklake-${version}-release.spdx.json`;
const sbomPath = path.join(dist, sbomName);
const collection = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: `LinkLake ${version} release package collection`,
  documentNamespace: `https://linklake.dev/spdx/releases/${version}/${releaseSetDigest}`,
  creationInfo: {
    created: new Date().toISOString(),
    creators: ['Tool: LinkLake release evidence'],
  },
  externalDocumentRefs,
  packages: describedPackages,
  relationships,
  documentDescribes: describedPackages.map((item) => item.SPDXID),
};
fs.writeFileSync(sbomPath, `${JSON.stringify(collection, null, 2)}\n`, 'utf8');
const sbomDigest = sha256(sbomPath);
fs.writeFileSync(path.join(dist, `${sbomName}.sha256`), `${sbomDigest}  ${sbomName}\n`, 'ascii');

console.log(
  `prepared ${primaryAssets.length} release subjects and linked ${externalDocumentRefs.length} detailed SPDX documents`,
);
