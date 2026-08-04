param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist')
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $projectRoot 'packaging\windows\installer-common.ps1')
$OutputDirectory = Resolve-LinkLakeSafePath ([IO.Path]::GetFullPath($OutputDirectory)) 'package output directory'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$manifest = Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'Cargo.toml')
$match = [regex]::Match($manifest, '(?ms)\[workspace\.package\].*?version\s*=\s*"([^"]+)"')
if (-not $match.Success) { throw 'Could not read the workspace version.' }
$version = $match.Groups[1].Value
if (-not (Test-LinkLakeSemVer $version)) { throw 'Workspace version is not valid semantic version text.' }
$packageName = "linklake-$version-windows-x86_64"
$stage = Join-Path $OutputDirectory $packageName
$archive = Join-Path $OutputDirectory "$packageName.zip"
$sourceDateEpoch = if ($env:SOURCE_DATE_EPOCH) {
    if ($env:SOURCE_DATE_EPOCH -notmatch '^[0-9]+$') { throw 'SOURCE_DATE_EPOCH must contain decimal digits only.' }
    try { [long]$env:SOURCE_DATE_EPOCH }
    catch { throw 'SOURCE_DATE_EPOCH must be a signed 64-bit integer.' }
}
else {
    $gitTimestamp = & git -C $projectRoot log -1 --format=%ct 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitTimestamp) { [long]$gitTimestamp } else { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
}
$latestAllowedEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 86400
if ($sourceDateEpoch -lt 315532800 -or $sourceDateEpoch -gt $latestAllowedEpoch) {
    throw 'Build timestamp must be between January 1, 1980 and 24 hours in the future.'
}
$archiveTimestamp = [DateTimeOffset]::FromUnixTimeSeconds($sourceDateEpoch)
$commitOutput = & git -C $projectRoot rev-parse --short=12 HEAD
if ($LASTEXITCODE -ne 0 -or -not $commitOutput) { throw 'Could not resolve the Git commit for release.json.' }
$commit = ([string]$commitOutput).Trim()
if ($commit -notmatch '^[0-9a-f]{12}$') { throw 'Git returned an invalid release commit identity.' }
$env:LINKLAKE_GIT_COMMIT = $commit

& cargo build --release --workspace --locked
if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }

if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
if (Test-Path -LiteralPath "$archive.sha256") { Remove-Item -LiteralPath "$archive.sha256" -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $stage 'bin'), (Join-Path $stage 'windows'), `
    (Join-Path $stage 'examples') | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'target\release\linklake-server.exe') -Destination (Join-Path $stage 'bin')
Copy-Item -LiteralPath (Join-Path $projectRoot 'target\release\linklake-client.exe') -Destination (Join-Path $stage 'bin')
Copy-Item -Path (Join-Path $projectRoot 'packaging\windows\*.ps1') -Destination (Join-Path $stage 'windows')
Copy-Item -Path (Join-Path $projectRoot 'examples\*') -Destination (Join-Path $stage 'examples')
Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md'), (Join-Path $projectRoot 'README.en.md'), `
    (Join-Path $projectRoot 'CHANGELOG.md'), (Join-Path $projectRoot 'LICENSE'), `
    (Join-Path $projectRoot 'NOTICE'), (Join-Path $projectRoot 'THIRD_PARTY_NOTICES.md'), `
    (Join-Path $projectRoot 'THIRD_PARTY_LICENSES.html'), (Join-Path $projectRoot 'TRADEMARKS.md') `
    -Destination $stage

$windowsSigningRequired = $env:LINKLAKE_WINDOWS_SIGNING_REQUIRED -match '^(?i:1|true|yes)$'
& (Join-Path $projectRoot 'scripts\sign-windows-artifacts.ps1') `
    -Required:$windowsSigningRequired `
    -Path @(
        (Join-Path $stage 'bin\linklake-server.exe'),
        (Join-Path $stage 'bin\linklake-client.exe')
    )

$manifestData = [ordered]@{
    product = 'LinkLake'
    version = $version
    target = 'windows-x86_64'
    built_unix_seconds = $sourceDateEpoch
    commit = $commit
} | ConvertTo-Json
[IO.File]::WriteAllText(
    (Join-Path $stage 'release.json'),
    $manifestData + "`n",
    [Text.UTF8Encoding]::new($false)
)

$checksumLines = Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($stage.Length).TrimStart([char]92, [char]47).Replace([char]92, [char]47)
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
    "$hash  $relative"
}
[IO.File]::WriteAllLines(
    (Join-Path $stage 'checksums.sha256'),
    [string[]]$checksumLines,
    [Text.Encoding]::ASCII
)

Get-ChildItem -LiteralPath $stage -Recurse -File | ForEach-Object {
    $_.LastWriteTimeUtc = $archiveTimestamp.UtcDateTime
}

Add-Type -AssemblyName System.IO.Compression
$archiveStream = [IO.File]::Open($archive, [IO.FileMode]::CreateNew)
$zip = [IO.Compression.ZipArchive]::new(
    $archiveStream,
    [IO.Compression.ZipArchiveMode]::Create,
    $false
)
try {
    Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($stage.Length).TrimStart([char]92, [char]47).Replace([char]92, [char]47)
        $entry = $zip.CreateEntry($relative, [IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = $archiveTimestamp
        $source = [IO.File]::OpenRead($_.FullName)
        $destination = $entry.Open()
        try {
            $source.CopyTo($destination)
        }
        finally {
            $destination.Dispose()
            $source.Dispose()
        }
    }
}
finally {
    $zip.Dispose()
    $archiveStream.Dispose()
}
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$archive.sha256" -Value "$hash  $([IO.Path]::GetFileName($archive))" -Encoding ascii
Write-Host "Created $archive"
