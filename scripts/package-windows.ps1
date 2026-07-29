param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist')
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$manifest = Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'Cargo.toml')
$match = [regex]::Match($manifest, '(?ms)\[workspace\.package\].*?version\s*=\s*"([^"]+)"')
if (-not $match.Success) { throw 'Could not read the workspace version.' }
$version = $match.Groups[1].Value
$packageName = "linklake-$version-windows-x86_64"
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
Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md'), (Join-Path $projectRoot 'README.en.md') -Destination $stage

$manifestData = [ordered]@{
    product = 'LinkLake'
    version = $version
    target = 'windows-x86_64'
    built_unix_seconds = $sourceDateEpoch
} | ConvertTo-Json
Set-Content -LiteralPath (Join-Path $stage 'release.json') -Value $manifestData -Encoding utf8

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
