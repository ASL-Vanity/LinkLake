param(
    [ValidateSet('quick', 'ci', 'soak')][string]$Profile = 'quick',
    [int]$DurationMinutes = 60,
    [switch]$SkipBuild,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target\e2e'
$udpTargetRoot = Join-Path $projectRoot 'target\udp-e2e'
$binarySuffix = if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' }

if (-not $SkipBuild) {
    $previousTarget = $env:CARGO_TARGET_DIR
    try {
        $env:CARGO_TARGET_DIR = $targetRoot
        & cargo build --workspace --locked
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
        $udpDebugRoot = Join-Path $udpTargetRoot 'debug'
        New-Item -ItemType Directory -Force -Path $udpDebugRoot | Out-Null
        foreach ($binary in @('linklake-server', 'linklake-client')) {
            $fileName = "$binary$binarySuffix"
            Copy-Item -LiteralPath (Join-Path $targetRoot "debug\$fileName") `
                -Destination (Join-Path $udpDebugRoot $fileName) -Force
        }
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

function Write-ReliabilityReport {
    if (-not $OutputPath) { return }
    $absolute = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $absolute
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    $total = ($results | Measure-Object elapsed_seconds -Sum).Sum
    if ($null -eq $total) { $total = 0 }
    $report = [pscustomobject]@{
        profile = $Profile
        rounds = $round
        suites = $results.Count
        total_seconds = [Math]::Round($total, 3)
        results = $results
    }
    $temporary = "$absolute.tmp"
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding utf8
    Move-Item -LiteralPath $temporary -Destination $absolute -Force
}

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
        Write-ReliabilityReport
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
Write-ReliabilityReport
$summary | ConvertTo-Json -Depth 5
