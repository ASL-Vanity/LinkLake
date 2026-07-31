param(
    [ValidateSet('quick', 'ci', 'soak')][string]$Profile = 'quick',
    [int]$DurationMinutes = 60,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target\e2e'

if (-not $SkipBuild) {
    $previousTarget = $env:CARGO_TARGET_DIR
    try {
        $env:CARGO_TARGET_DIR = $targetRoot
        & cargo build --workspace --locked
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
    } finally {
        $env:CARGO_TARGET_DIR = $previousTarget
    }
}

$quickSuites = @('tcp-e2e.ps1', 'udp-e2e.ps1', 'secret-e2e.ps1')
$fullSuites = @(
    'tcp-e2e.ps1',
    'udp-e2e.ps1',
    'secret-e2e.ps1',
    'managed-config-e2e.ps1',
    'sni-e2e.ps1',
    'socks5-e2e.ps1',
    'http-e2e.ps1'
)
$deadline = [DateTime]::UtcNow.AddMinutes([Math]::Max(1, $DurationMinutes))
$round = 0
$results = [System.Collections.Generic.List[object]]::new()

do {
    $round += 1
    $suites = if ($Profile -eq 'quick') { $quickSuites } else { $fullSuites }
    if ($Profile -eq 'soak') { $suites = $suites | Sort-Object { Get-Random } }
    foreach ($suite in $suites) {
        $path = Join-Path $PSScriptRoot $suite
        $watch = [Diagnostics.Stopwatch]::StartNew()
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $path -SkipBuild
        $exitCode = $LASTEXITCODE
        $watch.Stop()
        $results.Add([pscustomobject]@{
            round = $round
            suite = $suite
            elapsed_seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3)
            exit_code = $exitCode
        })
        if ($exitCode -ne 0) {
            $results | ConvertTo-Json -Depth 4 | Write-Host
            throw "$suite failed in reliability round $round."
        }
        if ($Profile -eq 'soak' -and [DateTime]::UtcNow -ge $deadline) { break }
    }
} while ($Profile -eq 'soak' -and [DateTime]::UtcNow -lt $deadline)

$summary = [pscustomobject]@{
    profile = $Profile
    rounds = $round
    suites = $results.Count
    total_seconds = [Math]::Round(($results | Measure-Object elapsed_seconds -Sum).Sum, 3)
    results = $results
}
$summary | ConvertTo-Json -Depth 5
