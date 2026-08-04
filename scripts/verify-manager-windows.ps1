param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist'),
    [switch]$RequireAuthenticode
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
$verifyRoot = Join-Path $env:TEMP "linklake-manager-verify-$([guid]::NewGuid().ToString('N'))"
try {
    Expand-Archive -LiteralPath $archive -DestinationPath $verifyRoot
    $clientVersion = (& (Join-Path $verifyRoot 'linklake-client.exe') --version).Trim()
    if ($clientVersion -notmatch [regex]::Escape($version) -or $clientVersion -notmatch 'target=windows-x86_64') {
        throw "Invalid packaged updater build information: $clientVersion"
    }
    $release = Get-Content -Raw -LiteralPath (Join-Path $verifyRoot 'release.json') | ConvertFrom-Json
    if ($release.component -ne 'manager' -or -not $release.commit) { throw 'Invalid Manager release identity.' }
    if ($RequireAuthenticode) {
        $peArtifacts = @(Get-ChildItem -LiteralPath $verifyRoot -Recurse -File | Where-Object {
                $_.Extension.ToLowerInvariant() -in @('.exe', '.dll')
            })
        if ($peArtifacts.Count -eq 0) { throw 'The Manager package contains no PE artifacts to verify.' }
        foreach ($artifact in $peArtifacts) {
            $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
            if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
                $null -eq $signature.SignerCertificate -or
                $null -eq $signature.TimeStamperCertificate) {
                throw "The required Authenticode signature or timestamp is invalid: $($artifact.Name)"
            }
        }
    }
}
finally {
    if (Test-Path -LiteralPath $verifyRoot) { Remove-Item -LiteralPath $verifyRoot -Recurse -Force }
}
Write-Host "Verified $archive"
Write-Host "SHA256 $actualHash"
