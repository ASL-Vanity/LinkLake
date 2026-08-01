param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist'),
    [string]$FlutterExecutable = $(if ($env:FLUTTER_BIN) { $env:FLUTTER_BIN } else { 'flutter' })
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$managerRoot = Join-Path $projectRoot 'apps\linklake_manager'
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$manifest = Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'Cargo.toml')
$match = [regex]::Match($manifest, '(?ms)\[workspace\.package\].*?version\s*=\s*"([^"]+)"')
if (-not $match.Success) { throw 'Could not read the workspace version.' }
$version = $match.Groups[1].Value
$pubspec = Get-Content -Raw -LiteralPath (Join-Path $managerRoot 'pubspec.yaml')
$pubspecMatch = [regex]::Match($pubspec, '(?m)^version:\s*([^\s]+)')
if (-not $pubspecMatch.Success) { throw 'Could not read the LinkLake Manager version.' }
$managerVersion = $pubspecMatch.Groups[1].Value
$packageName = "linklake-manager-$version-windows-x86_64"
$stage = Join-Path $OutputDirectory $packageName
$archive = Join-Path $OutputDirectory "$packageName.zip"
$sourceDateEpoch = if ($env:SOURCE_DATE_EPOCH) {
    [long]$env:SOURCE_DATE_EPOCH
}
else {
    $gitTimestamp = & git -C $projectRoot log -1 --format=%ct 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitTimestamp) { [long]$gitTimestamp } else { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
}
$archiveTimestamp = [DateTimeOffset]::FromUnixTimeSeconds($sourceDateEpoch)

Push-Location $managerRoot
try {
    & $FlutterExecutable pub get
    if ($LASTEXITCODE -ne 0) { throw 'Flutter dependency resolution failed.' }
    & $FlutterExecutable build windows --release `
        "--dart-define=LINKLAKE_MANAGER_VERSION=$managerVersion" `
        "--dart-define=LINKLAKE_RELEASE_VERSION=$version"
    if ($LASTEXITCODE -ne 0) { throw 'Flutter Windows release build failed.' }
}
finally {
    Pop-Location
}

$bundle = Join-Path $managerRoot 'build\windows\x64\runner\Release'
if (-not (Test-Path -LiteralPath (Join-Path $bundle 'linklake_manager.exe'))) {
    throw "Missing Flutter Windows bundle: $bundle"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
if (Test-Path -LiteralPath "$archive.sha256") { Remove-Item -LiteralPath "$archive.sha256" -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item -Path (Join-Path $bundle '*') -Destination $stage -Recurse -Force
Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md'), `
    (Join-Path $projectRoot 'README.en.md'), (Join-Path $projectRoot 'LICENSE'), `
    (Join-Path $projectRoot 'NOTICE'), (Join-Path $projectRoot 'THIRD_PARTY_NOTICES.md'), `
    (Join-Path $projectRoot 'THIRD_PARTY_LICENSES.html'), (Join-Path $projectRoot 'TRADEMARKS.md') `
    -Destination $stage
Copy-Item -LiteralPath (Join-Path $managerRoot 'README.md') `
    -Destination (Join-Path $stage 'MANAGER_README.md')

[ordered]@{
    product = 'LinkLake Manager'
    component = 'manager'
    version = $version
    target = 'windows-x86_64'
    built_unix_seconds = $sourceDateEpoch
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'release.json') -Encoding utf8

Get-ChildItem -LiteralPath $stage -Recurse -File | ForEach-Object {
    $_.LastWriteTimeUtc = $archiveTimestamp.UtcDateTime
}
Add-Type -AssemblyName System.IO.Compression
$archiveStream = [IO.File]::Open($archive, [IO.FileMode]::CreateNew)
$zip = [IO.Compression.ZipArchive]::new($archiveStream, [IO.Compression.ZipArchiveMode]::Create, $false)
try {
    Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($stage.Length).TrimStart([char]92, [char]47).Replace([char]92, [char]47)
        $entry = $zip.CreateEntry($relative, [IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = $archiveTimestamp
        $source = [IO.File]::OpenRead($_.FullName)
        $destination = $entry.Open()
        try { $source.CopyTo($destination) }
        finally { $destination.Dispose(); $source.Dispose() }
    }
}
finally {
    $zip.Dispose()
    $archiveStream.Dispose()
}
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$archive.sha256" -Value "$hash  $([IO.Path]::GetFileName($archive))" -Encoding ascii
Write-Host "Created $archive"
