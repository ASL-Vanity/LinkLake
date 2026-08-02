param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath 'Variable:PSNativeCommandUseErrorActionPreference') {
    $PSNativeCommandUseErrorActionPreference = $false
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$root = Join-Path $projectRoot 'target\update-e2e'
$buildRoot = Join-Path $projectRoot 'target'
$stateRoot = Join-Path $root 'state'
$installRoot = Join-Path $root 'install'
$helperRoot = Join-Path $root 'helper'
$binaryName = if ($env:OS -eq 'Windows_NT') { 'linklake-client.exe' } else { 'linklake-client' }
$builtClient = Join-Path $buildRoot "debug\$binaryName"
$releaseClient = Join-Path $buildRoot "release\$binaryName"
$targetClient = Join-Path $installRoot $binaryName
$helperClient = Join-Path $helperRoot $binaryName

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-Plan {
    param(
        [string]$Name,
        [string]$StagedClient,
        [string]$StagedHash,
        [string]$FromVersion,
        [string]$ToVersion
    )
    $plans = Join-Path $stateRoot 'plans'
    New-Item -ItemType Directory -Force -Path $plans | Out-Null
    $planPath = Join-Path $plans "$Name.json"
    $json = [ordered]@{
        schema_version = 1
        operation = 'apply'
        state_directory = $stateRoot
        target_executable = $targetClient
        staged_executable = $StagedClient
        expected_target_sha256 = Get-Sha256 $targetClient
        staged_sha256 = $StagedHash
        from_version = $FromVersion
        to_version = $ToVersion
        service_installed = $false
        service_was_running = $false
        created_unix_seconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    } | ConvertTo-Json
    [IO.File]::WriteAllText($planPath, $json, [Text.UTF8Encoding]::new($false))
    return $planPath
}

function Invoke-Helper {
    param([string]$PlanPath, [switch]$ExpectFailure)
    $planHash = Get-Sha256 $PlanPath
    & $helperClient __update-helper --plan $PlanPath --plan-sha256 $planHash
    $exitCode = $LASTEXITCODE
    if ($ExpectFailure) {
        if ($exitCode -eq 0) { throw 'The update helper unexpectedly accepted a broken binary.' }
    }
    elseif ($exitCode -ne 0) {
        throw "The update helper failed with exit code $exitCode."
    }
}

function Wait-UpdateState {
    param([string]$ExpectedState, [string]$ExpectedOperation)
    $statusPath = Join-Path $stateRoot 'status.json'
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        if (Test-Path -LiteralPath $statusPath) {
            $status = Get-Content -Raw -LiteralPath $statusPath | ConvertFrom-Json
            if ($status.state -eq $ExpectedState -and $status.operation -eq $ExpectedOperation) {
                return $status
            }
            if ($status.state -eq 'failed') {
                throw "Update operation failed: $($status.error)"
            }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for update state $ExpectedState/$ExpectedOperation."
}

if (-not $SkipBuild) {
    & cargo build -p linklake-client
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the updater E2E client.' }
    & cargo build -p linklake-client --release
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the updater E2E release client.' }
}
if (-not (Test-Path -LiteralPath $builtClient)) { throw "Missing client binary: $builtClient" }
if (-not (Test-Path -LiteralPath $releaseClient)) { throw "Missing release client binary: $releaseClient" }

foreach ($path in @($stateRoot, $installRoot, $helperRoot)) {
    if (Test-Path -LiteralPath $path) {
        $resolved = (Resolve-Path -LiteralPath $path).Path
        $expectedRoot = [IO.Path]::GetFullPath($root)
        if (-not $resolved.StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unsafe updater E2E cleanup target: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $path | Out-Null
}

Copy-Item -LiteralPath $builtClient -Destination $targetClient
Copy-Item -LiteralPath $builtClient -Destination $helperClient
$versionOutput = (& $targetClient --version).Trim()
$version = ($versionOutput -split '\s+')[-1]
if (-not $version) { throw 'The client did not report a version.' }
$originalHash = Get-Sha256 $targetClient

$successStage = Join-Path $stateRoot 'staging\success'
New-Item -ItemType Directory -Force -Path $successStage | Out-Null
$successClient = Join-Path $successStage $binaryName
Copy-Item -LiteralPath $releaseClient -Destination $successClient
$releaseHash = Get-Sha256 $successClient
if ($releaseHash -eq $originalHash) { throw 'Debug and release clients unexpectedly have the same digest.' }
$successPlan = Write-Plan -Name 'success' -StagedClient $successClient `
    -StagedHash $releaseHash -FromVersion $version -ToVersion $version
Invoke-Helper -PlanPath $successPlan
    $successStatus = Get-Content -Raw -LiteralPath (Join-Path $stateRoot 'status.json') | ConvertFrom-Json
if ($successStatus.state -ne 'succeeded') { throw "Unexpected success status: $($successStatus.state)" }
if ((Get-Sha256 $targetClient) -ne $releaseHash) { throw 'Successful replacement did not install the release binary.' }

& $targetClient update rollback --yes --state-dir $stateRoot
if ($LASTEXITCODE -ne 0) { throw 'The manual rollback command could not be scheduled.' }
$null = Wait-UpdateState -ExpectedState 'rolled_back' -ExpectedOperation 'rollback'
if ((Get-Sha256 $targetClient) -ne $originalHash) { throw 'Manual rollback did not restore the debug client.' }

$failureStage = Join-Path $stateRoot 'staging\failure'
New-Item -ItemType Directory -Force -Path $failureStage | Out-Null
$failureClient = Join-Path $failureStage $binaryName
[IO.File]::WriteAllBytes($failureClient, [Text.Encoding]::UTF8.GetBytes('not-an-executable'))
$failurePlan = Write-Plan -Name 'failure' -StagedClient $failureClient `
    -StagedHash (Get-Sha256 $failureClient) -FromVersion $version -ToVersion '9.9.9-test'
Invoke-Helper -PlanPath $failurePlan -ExpectFailure
$failureStatus = Get-Content -Raw -LiteralPath (Join-Path $stateRoot 'status.json') | ConvertFrom-Json
if ($failureStatus.state -ne 'rolled_back') { throw "Automatic rollback did not complete: $($failureStatus.state)" }
if (-not $failureStatus.error) { throw 'The failed update status did not preserve the failure reason.' }
if ((Get-Sha256 $targetClient) -ne $originalHash) { throw 'Automatic rollback did not restore the original binary.' }
if ((& $targetClient --version).Trim() -ne $versionOutput) { throw 'Restored client version does not match the original.' }

[ordered]@{
    ok = $true
    version = $version
    successful_replace = $true
    manual_rollback = $true
    automatic_rollback = $true
    backup_count = @(Get-ChildItem -LiteralPath (Join-Path $stateRoot 'backups') -Directory).Count
    status_file = Join-Path $stateRoot 'status.json'
} | ConvertTo-Json
