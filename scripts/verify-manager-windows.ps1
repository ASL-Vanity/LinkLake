param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist')
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifest = Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'Cargo.toml')
$match = [regex]::Match($manifest, '(?ms)\[workspace\.package\].*?version\s*=\s*"([^"]+)"')
if (-not $match.Success) { throw 'Could not read the workspace version.' }
$version = $match.Groups[1].Value
$archive = Join-Path $OutputDirectory "linklake-manager-$version-windows-x86_64.zip"
$checksum = "$archive.sha256"
if (-not (Test-Path -LiteralPath $archive)) { throw "Missing archive: $archive" }
if (-not (Test-Path -LiteralPath $checksum)) { throw "Missing checksum: $checksum" }
$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
$declaredHash = ((Get-Content -Raw -LiteralPath $checksum).Trim().Split(' ')[0]).ToLowerInvariant()
if ($actualHash -ne $declaredHash) { throw "SHA-256 mismatch: $actualHash != $declaredHash" }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
try {
    $entries = @($zip.Entries | ForEach-Object { $_.FullName.Replace([char]92, [char]47) })
    foreach ($entry in @('linklake_manager.exe', 'linklake-client.exe', 'flutter_windows.dll', 'data/app.so', 'data/icudtl.dat', 'README.md', 'README.en.md', 'MANAGER_README.md', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'THIRD_PARTY_LICENSES.html', 'TRADEMARKS.md', 'release.json')) {
        if ($entries -notcontains $entry) { throw "Missing archive entry: $entry" }
    }
}
finally { $zip.Dispose() }
Write-Host "Verified $archive"
Write-Host "SHA256 $actualHash"
