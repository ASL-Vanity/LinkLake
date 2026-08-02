param(
    [switch]$SkipBuild,
    [ValidateSet('client', 'server')]
    [string]$Product = 'client'
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
$binaryBaseName = "linklake-$Product"
$binaryName = if ($env:OS -eq 'Windows_NT') { "$binaryBaseName.exe" } else { $binaryBaseName }
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
        schema_version = 2
        operation = 'apply'
        product = $Product
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
    & cargo build -p $binaryBaseName
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the updater E2E client.' }
    & cargo build -p $binaryBaseName --release
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
$versionMatch = [regex]::Match($versionOutput, '\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\b')
$version = if ($versionMatch.Success) { $versionMatch.Value } else { $null }
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

$tamperStage = Join-Path $stateRoot 'staging\tampered'
New-Item -ItemType Directory -Force -Path $tamperStage | Out-Null
$tamperClient = Join-Path $tamperStage $binaryName
Copy-Item -LiteralPath $releaseClient -Destination $tamperClient
$tamperPlan = Write-Plan -Name 'tampered-staged' -StagedClient $tamperClient `
    -StagedHash (Get-Sha256 $tamperClient) -FromVersion $version -ToVersion $version
[IO.File]::AppendAllText($tamperClient, 'tampered')
Invoke-Helper -PlanPath $tamperPlan -ExpectFailure
$tamperStatus = Get-Content -Raw -LiteralPath (Join-Path $stateRoot 'status.json') | ConvertFrom-Json
if ($tamperStatus.state -ne 'failed' -or $tamperStatus.error -notmatch 'staged binary digest changed') {
    throw 'Staged binary tampering was not rejected with a stable failure status.'
}
if ((Get-Sha256 $targetClient) -ne $originalHash) { throw 'Staged tampering changed the installed binary.' }

$concurrentStage = Join-Path $stateRoot 'staging\concurrent'
New-Item -ItemType Directory -Force -Path $concurrentStage | Out-Null
$concurrentClient = Join-Path $concurrentStage $binaryName
Copy-Item -LiteralPath $releaseClient -Destination $concurrentClient
$concurrentPlan = Write-Plan -Name 'concurrent-target' -StagedClient $concurrentClient `
    -StagedHash (Get-Sha256 $concurrentClient) -FromVersion $version -ToVersion $version
Copy-Item -LiteralPath $releaseClient -Destination $targetClient -Force
Invoke-Helper -PlanPath $concurrentPlan -ExpectFailure
$concurrentStatus = Get-Content -Raw -LiteralPath (Join-Path $stateRoot 'status.json') | ConvertFrom-Json
if ($concurrentStatus.state -ne 'failed' -or $concurrentStatus.error -notmatch 'installed binary changed') {
    throw 'Concurrent target changes were not rejected.'
}
Copy-Item -LiteralPath $builtClient -Destination $targetClient -Force

$serviceStage = Join-Path $stateRoot 'staging\service-failure'
New-Item -ItemType Directory -Force -Path $serviceStage | Out-Null
$serviceClient = Join-Path $serviceStage $binaryName
Copy-Item -LiteralPath $releaseClient -Destination $serviceClient
$servicePlan = Write-Plan -Name 'service-failure' -StagedClient $serviceClient `
    -StagedHash (Get-Sha256 $serviceClient) -FromVersion $version -ToVersion $version
$env:LINKLAKE_UPDATE_TEST_FAIL_SERVICE_RECOVERY = '1'
try {
    Invoke-Helper -PlanPath $servicePlan -ExpectFailure
}
finally {
    Remove-Item Env:LINKLAKE_UPDATE_TEST_FAIL_SERVICE_RECOVERY -ErrorAction SilentlyContinue
}
$serviceStatus = Get-Content -Raw -LiteralPath (Join-Path $stateRoot 'status.json') | ConvertFrom-Json
if ($serviceStatus.state -ne 'rolled_back' -or $serviceStatus.error -notmatch 'service recovery failure') {
    throw 'Service recovery failure did not trigger automatic rollback.'
}
if ((Get-Sha256 $targetClient) -ne $originalHash) { throw 'Service failure rollback did not restore the original binary.' }

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
    product = $Product
    version = $version
    successful_replace = $true
    manual_rollback = $true
    automatic_rollback = $true
    staged_tamper_rejected = $true
    concurrent_target_change_rejected = $true
    service_failure_rollback = $true
    backup_count = @(Get-ChildItem -LiteralPath (Join-Path $stateRoot 'backups') -Directory).Count
    status_file = Join-Path $stateRoot 'status.json'
} | ConvertTo-Json
