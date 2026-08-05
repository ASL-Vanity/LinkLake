$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$commonPath = Join-Path $repositoryRoot 'packaging\windows\installer-common.ps1'
$serverInstallerPath = Join-Path $repositoryRoot 'packaging\windows\install-server.ps1'

function Assert-Contract {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Rejected {
    param([Parameter(Mandatory)][scriptblock]$Action, [Parameter(Mandatory)][string]$Message)
    $rejected = $false
    try { & $Action }
    catch { $rejected = $true }
    if (-not $rejected) { throw $Message }
}

function Write-HandoffRecordFixture {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$DataDirectory,
        [Parameter(Mandatory)][string]$InstallDirectory,
        [hashtable]$Overrides = @{}
    )
    $operationId = [guid]::NewGuid().ToString('N')
    $snapshotPath = Join-Path $Directory ".server-before-upgrade-$([guid]::NewGuid().ToString('N')).sqlite3"
    $rollbackPrimary = Join-Path $InstallDirectory 'linklake-server.exe'
    $rollbackBackup = Join-Path $InstallDirectory ".linklake-server.backup-$([guid]::NewGuid().ToString('N')).exe"
    foreach ($path in @($rollbackPrimary, $rollbackBackup)) {
        [IO.File]::WriteAllBytes($path, [byte[]](1, 2, 3))
    }
    $record = [ordered]@{
        schema_version = 1
        kind = 'linklake-server-candidate-handoff'
        operation_id = $operationId
        service_name = 'LinkLakeServer'
        data_directory = $DataDirectory
        install_directory = $InstallDirectory
        snapshot_directory = $Directory
        snapshot_path = $snapshotPath
        snapshot_sha256 = ('a' * 64)
        rollback_binary_paths = @($rollbackPrimary, $rollbackBackup)
        rollback_binary_sha256 = ('b' * 64)
        created_unix_seconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }
    foreach ($key in $Overrides.Keys) { $record[$key] = $Overrides[$key] }
    [IO.File]::WriteAllText(
        (Join-Path $Directory 'candidate-handoff.json'),
        ($record | ConvertTo-Json -Compress -Depth 4),
        [Text.UTF8Encoding]::new($false)
    )
}

$commonSource = [IO.File]::ReadAllText($commonPath, [Text.Encoding]::UTF8)
$serverSource = [IO.File]::ReadAllText($serverInstallerPath, [Text.Encoding]::UTF8)
[void][scriptblock]::Create($commonSource)
[void][scriptblock]::Create($serverSource)
. $commonPath

$events = [Collections.Generic.List[string]]::new()
try {
    Invoke-LinkLakeTransactionalChange `
        -Stop { $null = $events.Add('stop') } `
        -Apply { $null = $events.Add('apply') } `
        -Validate { $null = $events.Add('validate') } `
        -Start { $null = $events.Add('start'); throw 'simulated candidate failure' } `
        -Rollback { $null = $events.Add('rollback') } `
        -Recover { $null = $events.Add('recover') } `
        -CandidateHandoffStarted { $true } `
        -Handoff { $null = $events.Add('handoff') } `
        -WasRunning $true -ShouldStart $true
    throw 'The candidate-handoff fixture unexpectedly succeeded.'
}
catch {
    Assert-Contract ($_.Exception.Message -match 'automatic rollback is intentionally disabled') `
        'Candidate handoff failure did not report manual recovery.'
}
Assert-Contract ($events -contains 'handoff') 'Candidate handoff did not invoke preservation.'
Assert-Contract (-not ($events -contains 'rollback')) 'Candidate handoff incorrectly invoked automatic rollback.'
Assert-Contract (-not ($events -contains 'recover')) 'Candidate handoff incorrectly restarted the old service.'

$events.Clear()
try {
    Invoke-LinkLakeTransactionalChange `
        -Stop { $null = $events.Add('stop') } `
        -Apply { $null = $events.Add('apply') } `
        -Validate { $null = $events.Add('validate') } `
        -Start { $null = $events.Add('start'); throw 'simulated candidate failure' } `
        -Rollback { $null = $events.Add('rollback') } `
        -Recover { $null = $events.Add('recover') } `
        -CandidateHandoffStarted { throw 'candidate state is unavailable' } `
        -Handoff { $null = $events.Add('handoff') } `
        -WasRunning $true -ShouldStart $true
    throw 'The unknown candidate-handoff fixture unexpectedly succeeded.'
}
catch {
    Assert-Contract ($_.Exception.Message -match 'automatic rollback is intentionally disabled') `
        'An unknown candidate handoff state did not fail closed.'
}
Assert-Contract ($events -contains 'handoff') 'An unknown candidate handoff state did not preserve handoff evidence.'
Assert-Contract (-not ($events -contains 'rollback')) 'An unknown candidate handoff state invoked automatic rollback.'
Assert-Contract (-not ($events -contains 'recover')) 'An unknown candidate handoff state restarted the old service.'

$events.Clear()
try {
    Invoke-LinkLakeTransactionalChange `
        -Stop { $null = $events.Add('stop') } `
        -Apply { $null = $events.Add('apply') } `
        -Validate { $null = $events.Add('validate') } `
        -Start { $null = $events.Add('start'); throw 'simulated pre-handoff failure' } `
        -Rollback { $null = $events.Add('rollback') } `
        -Recover { $null = $events.Add('recover') } `
        -CandidateHandoffStarted { $false } `
        -Handoff { $null = $events.Add('handoff') } `
        -WasRunning $true -ShouldStart $true
    throw 'The pre-handoff fixture unexpectedly succeeded.'
}
catch {}
Assert-Contract ($events -contains 'rollback') 'Pre-handoff failure did not retain normal automatic rollback.'
Assert-Contract ($events -contains 'recover') 'Pre-handoff failure did not retain normal service recovery.'
Assert-Contract (-not ($events -contains 'handoff')) 'Pre-handoff failure unexpectedly used handoff preservation.'

Assert-Contract ((Get-LinkLakeCandidateHandoffRecoveryDecision $false $false $false) -eq 'automatic_rollback') `
    'Pre-handoff recovery decision changed unexpectedly.'
Assert-Contract ((Get-LinkLakeCandidateHandoffRecoveryDecision $true $false $false) -eq 'preserve_for_manual_recovery') `
    'Candidate handoff without consent was not preserved.'
Assert-Contract ((Get-LinkLakeCandidateHandoffRecoveryDecision $true $true $false) -eq 'preserve_for_manual_recovery') `
    'Single confirmation incorrectly authorized snapshot restore.'
Assert-Contract ((Get-LinkLakeCandidateHandoffRecoveryDecision $true $true $true) -eq 'restore_snapshot') `
    'Double confirmation did not authorize snapshot restore.'

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "linklake-server-handoff-contract-$([guid]::NewGuid().ToString('N'))"
$temporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
$temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if (-not $temporaryRoot.StartsWith($temporaryParent, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Test root escaped the temporary directory.'
}
try {
    $dataDirectory = Join-Path $temporaryRoot 'data'
    $installDirectory = Join-Path $temporaryRoot 'install'
    $handoffDirectory = Join-Path $temporaryRoot ".linklake-server-upgrade-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Force -Path $dataDirectory, $installDirectory, $handoffDirectory | Out-Null
    Write-HandoffRecordFixture $handoffDirectory $dataDirectory $installDirectory
    $record = Read-LinkLakeServerCandidateHandoffRecord `
        -HandoffDirectory $handoffDirectory -ExpectedDataDirectory $dataDirectory `
        -ExpectedInstallDirectory $installDirectory -ExpectedServiceName 'LinkLakeServer'
    Assert-Contract ($record.OperationId -match '^[0-9a-f]{32}$') 'Valid handoff record did not preserve operation binding.'
    Assert-Contract ($record.RollbackBinaryPaths.Count -eq 2) 'Valid handoff record lost rollback binary bindings.'

    Write-HandoffRecordFixture $handoffDirectory $dataDirectory $installDirectory @{
        snapshot_path = (Join-Path $temporaryRoot 'outside.sqlite3')
    }
    Assert-Rejected {
        Read-LinkLakeServerCandidateHandoffRecord `
            -HandoffDirectory $handoffDirectory -ExpectedDataDirectory $dataDirectory `
            -ExpectedInstallDirectory $installDirectory -ExpectedServiceName 'LinkLakeServer'
    } 'An escaped snapshot path was accepted.'

    Write-HandoffRecordFixture $handoffDirectory $dataDirectory $installDirectory @{
        snapshot_directory = '\\example.invalid\share\candidate-handoff'
    }
    Assert-Rejected {
        Read-LinkLakeServerCandidateHandoffRecord `
            -HandoffDirectory $handoffDirectory -ExpectedDataDirectory $dataDirectory `
            -ExpectedInstallDirectory $installDirectory -ExpectedServiceName 'LinkLakeServer'
    } 'A UNC handoff record path was accepted.'

    Write-HandoffRecordFixture $handoffDirectory $dataDirectory $installDirectory @{
        service_name = 'OtherService'
    }
    Assert-Rejected {
        Read-LinkLakeServerCandidateHandoffRecord `
            -HandoffDirectory $handoffDirectory -ExpectedDataDirectory $dataDirectory `
            -ExpectedInstallDirectory $installDirectory -ExpectedServiceName 'LinkLakeServer'
    } 'A mismatched service binding was accepted.'

    Write-HandoffRecordFixture $handoffDirectory $dataDirectory $installDirectory @{
        snapshot_sha256 = ('A' * 64)
    }
    Assert-Rejected {
        Read-LinkLakeServerCandidateHandoffRecord `
            -HandoffDirectory $handoffDirectory -ExpectedDataDirectory $dataDirectory `
            -ExpectedInstallDirectory $installDirectory -ExpectedServiceName 'LinkLakeServer'
    } 'An uppercase snapshot digest was accepted.'

    Write-HandoffRecordFixture $handoffDirectory $dataDirectory $installDirectory
    $junction = Join-Path $temporaryRoot ".linklake-server-upgrade-$([guid]::NewGuid().ToString('N'))"
    & cmd.exe /d /c "mklink /J `"$junction`" `"$handoffDirectory`"" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create a junction fixture for handoff path validation.' }
    Assert-Rejected {
        Read-LinkLakeServerCandidateHandoffRecord `
            -HandoffDirectory $junction -ExpectedDataDirectory $dataDirectory `
            -ExpectedInstallDirectory $installDirectory -ExpectedServiceName 'LinkLakeServer'
    } 'A reparse-point handoff directory was accepted.'
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Force -Recurse
    }
}

$recordIndex = $serverSource.IndexOf('$script:databaseHandoffRecordPath = New-LinkLakeServerCandidateHandoffRecord', [StringComparison]::Ordinal)
$stageIndex = $serverSource.IndexOf("New-LinkLakeServerCandidateHandoffStage `$record.HandoffDirectory 'candidate-starting'", [StringComparison]::Ordinal)
$candidateIndex = $serverSource.IndexOf('$script:databaseCandidateStarted = $true', [StringComparison]::Ordinal)
$startIndex = $serverSource.IndexOf('Start-LinkLakeServiceChecked $serviceName', $candidateIndex, [StringComparison]::Ordinal)
Assert-Contract ($recordIndex -ge 0 -and $stageIndex -gt $recordIndex -and $candidateIndex -gt $stageIndex -and $startIndex -gt $candidateIndex) `
    'The installer does not durably record candidate handoff before candidate service start.'
$handoffStart = $serverSource.IndexOf('    $handoff = {', [StringComparison]::Ordinal)
$handoffEnd = $serverSource.IndexOf('    $recover = {', $handoffStart, [StringComparison]::Ordinal)
Assert-Contract ($handoffStart -ge 0 -and $handoffEnd -gt $handoffStart) 'Could not isolate the installer handoff callback.'
$handoffBody = $serverSource.Substring($handoffStart, $handoffEnd - $handoffStart)
Assert-Contract ($handoffBody.Contains('Stop-LinkLakeServiceChecked $serviceName 10')) 'Handoff callback does not stop the candidate service.'
Assert-Contract (-not $handoffBody.Contains("-CommandArguments @('restore'")) 'Handoff callback performs an automatic database restore.'
Assert-Contract ($serverSource.Contains('-RecoverCandidateHandoffDirectory') -and
    $serverSource.Contains('-RestoreAfterCandidateHandoff') -and $serverSource.Contains('-ConfirmDataLoss')) `
    'The explicit candidate handoff recovery parameters are missing.'
Assert-Contract ($commonSource.Contains('$CandidateHandoffStarted') -and $commonSource.Contains('automatic rollback is intentionally disabled')) `
    'The transactional framework does not expose candidate handoff protection.'

[ordered]@{
    ok = $true
    candidate_handoff_automatic_database_rollback_disabled = $true
    explicit_double_confirmation_required = $true
    unsafe_record_paths_rejected = $true
    service_remains_stopped_after_handoff = $true
} | ConvertTo-Json -Compress
