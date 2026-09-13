param([switch]$SkipBuild, [string]$TargetDir = '')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath 'Variable:PSNativeCommandUseErrorActionPreference') {
    $PSNativeCommandUseErrorActionPreference = $false
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$binarySuffix = if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' }
$targetRoot = if ($TargetDir) { [IO.Path]::GetFullPath($TargetDir) } else { Join-Path $projectRoot 'target' }
$server = Join-Path $targetRoot "debug/linklake-server$binarySuffix"
$client = Join-Path $targetRoot "debug/linklake-client$binarySuffix"
$versionMatch = [regex]::Match((Get-Content -LiteralPath (Join-Path $projectRoot 'Cargo.toml') -Raw), '(?m)^version\s*=\s*"([^"]+)"')
if (-not $versionMatch.Success) { throw 'Workspace version is missing from Cargo.toml.' }
$expectedVersion = $versionMatch.Groups[1].Value
$root = Join-Path $projectRoot 'target\version-contract'

if (-not $SkipBuild) {
    & cargo build -p linklake-server -p linklake-client --locked --target-dir $targetRoot
    if ($LASTEXITCODE -ne 0) { throw 'Could not build version-contract binaries.' }
}
New-Item -ItemType Directory -Force -Path $root | Out-Null
$blockedLogPath = Join-Path $root 'not-a-directory'
[IO.File]::WriteAllText($blockedLogPath, 'version output must not touch logging')
$previousLogDirectory = $env:LINKLAKE_LOG_DIR
$env:LINKLAKE_LOG_DIR = $blockedLogPath
try {
    foreach ($binary in @($server, $client)) {
        $text = (& $binary --version).Trim()
        if ($LASTEXITCODE -ne 0 -or $text -notmatch [regex]::Escape($expectedVersion) -or $text -notmatch 'target=') {
            throw "Invalid side-effect-free version output from $binary`: $text"
        }
        $json = ((& $binary --version-json) -join "`n") | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or $json.version -ne $expectedVersion -or -not $json.product -or -not $json.target) {
            throw "Invalid side-effect-free version JSON from $binary."
        }
    }
}
finally {
    if ($null -eq $previousLogDirectory) {
        Remove-Item Env:LINKLAKE_LOG_DIR -ErrorAction SilentlyContinue
    }
    else {
        $env:LINKLAKE_LOG_DIR = $previousLogDirectory
    }
}

[ordered]@{
    ok = $true
    version = $expectedVersion
    logging_untouched = $true
    server = $server
    client = $client
} | ConvertTo-Json
