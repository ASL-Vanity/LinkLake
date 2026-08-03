param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath 'Variable:PSNativeCommandUseErrorActionPreference') {
    $PSNativeCommandUseErrorActionPreference = $false
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$binarySuffix = if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' }
$server = Join-Path $projectRoot "target\debug\linklake-server$binarySuffix"
$client = Join-Path $projectRoot "target\debug\linklake-client$binarySuffix"
$root = Join-Path $projectRoot 'target\version-contract'

if (-not $SkipBuild) {
    & cargo build -p linklake-server -p linklake-client
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
        if ($LASTEXITCODE -ne 0 -or $text -notmatch '0\.8\.0-rc\.1' -or $text -notmatch 'target=') {
            throw "Invalid side-effect-free version output from $binary`: $text"
        }
        $json = ((& $binary --version-json) -join "`n") | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or $json.version -ne '0.8.0-rc.1' -or -not $json.product -or -not $json.target) {
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
    version = '0.8.0-rc.1'
    logging_untouched = $true
    server = $server
    client = $client
} | ConvertTo-Json
