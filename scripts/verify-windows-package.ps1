param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist'),
    [string]$ExpectedSha256
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $projectRoot 'packaging\windows\installer-common.ps1')
$OutputDirectory = Resolve-LinkLakeSafePath ([IO.Path]::GetFullPath($OutputDirectory)) 'package output directory'
$manifest = Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'Cargo.toml')
$match = [regex]::Match($manifest, '(?ms)\[workspace\.package\].*?version\s*=\s*"([^"]+)"')
if (-not $match.Success) { throw 'Could not read the workspace version.' }
$version = $match.Groups[1].Value
$archive = Join-Path $OutputDirectory "linklake-$version-windows-x86_64.zip"
$checksum = "$archive.sha256"

if (-not (Test-Path -LiteralPath $archive)) { throw "Missing archive: $archive" }
if ((Get-Item -Force -LiteralPath $archive).Length -gt 1GB) { throw 'Windows release archive exceeds the size limit.' }

$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
$declaredHash = Read-LinkLakeSha256Sidecar $checksum ([IO.Path]::GetFileName($archive))
if ($actualHash -ne $declaredHash) { throw "SHA-256 mismatch: $actualHash != $declaredHash" }
if ($ExpectedSha256) {
    if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'ExpectedSha256 must contain exactly 64 hexadecimal characters.' }
    if ($actualHash -ne $ExpectedSha256.ToLowerInvariant()) { throw 'Archive does not match the trusted expected SHA-256.' }
}

$verifyRoot = Join-Path $env:TEMP "linklake-package-verify-$([guid]::NewGuid().ToString('N'))"
try {
    $inspection = Expand-LinkLakeZipArchiveSafely $archive $verifyRoot
    $entries = @($inspection.Entries)
    $required = @(
        'bin/linklake-server.exe',
        'bin/linklake-client.exe',
        'windows/installer-common.ps1',
        'windows/install-server.ps1',
        'windows/install-client.ps1',
        'windows/uninstall.ps1',
        'README.md',
        'README.en.md',
        'CHANGELOG.md',
        'LICENSE',
        'NOTICE',
        'THIRD_PARTY_NOTICES.md',
        'THIRD_PARTY_LICENSES.html',
        'TRADEMARKS.md',
        'release.json',
        'checksums.sha256'
    )
    foreach ($entry in $required) {
        if ($entries -notcontains $entry) { throw "Missing archive entry: $entry" }
    }

    $release = Read-LinkLakeReleaseIdentity $verifyRoot 'windows-x86_64'
    if ($release.version -ne $version) { throw 'release.json version does not match the workspace package version.' }
    Assert-LinkLakePackageChecksums $verifyRoot
    $null = Assert-LinkLakePackageBinary (Join-Path $verifyRoot 'bin\linklake-server.exe') 'LinkLake Server' $release
    $null = Assert-LinkLakePackageBinary (Join-Path $verifyRoot 'bin\linklake-client.exe') 'LinkLake Client' $release
}
finally {
    if (Test-Path -LiteralPath $verifyRoot) { Remove-Item -LiteralPath $verifyRoot -Recurse -Force }
}

Write-Host "Verified $archive"
Write-Host "SHA256 $actualHash"
