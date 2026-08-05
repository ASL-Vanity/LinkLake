param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath 'Variable:PSNativeCommandUseErrorActionPreference') {
    $PSNativeCommandUseErrorActionPreference = $false
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$root = Join-Path $projectRoot 'target\server-update-e2e'
$buildRoot = Join-Path $projectRoot 'target'
$stateRoot = Join-Path $root 'state'
$dataRoot = Join-Path $root 'data'
$installRoot = Join-Path $root 'install'
$helperRoot = Join-Path $root 'helper'
$installerCommonPath = Join-Path $projectRoot 'packaging\windows\installer-common.ps1'
$binaryName = if ($env:OS -eq 'Windows_NT') { 'linklake-server.exe' } else { 'linklake-server' }
$debugBinary = Join-Path $buildRoot "debug\$binaryName"
$releaseBinary = Join-Path $buildRoot "release\$binaryName"
$targetBinary = Join-Path $installRoot $binaryName
$helperBinary = Join-Path $helperRoot $binaryName

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$serverUpdateTestAuthKeyHex = '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'
$previousServerUpdateTestAuthKey = [Environment]::GetEnvironmentVariable('LINKLAKE_UPDATE_TEST_SERVER_AUTH_KEY_HEX', 'Process')

if ($env:OS -eq 'Windows_NT') {
    # 复用安装器的真实目录 ACL 模板，避免测试夹具放宽服务端更新的生产边界。
    . $installerCommonPath
}

function Test-LinkLakeWindowsAdministrator {
    if ($env:OS -ne 'Windows_NT') { return $true }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-LinkLakeServerUpdateDataDirectoryFixture {
    if ($env:OS -ne 'Windows_NT') { return $true }
    if (-not (Test-LinkLakeWindowsAdministrator)) { return $false }
    $plan = New-LinkLakeDirectoryTransactionPlan $dataRoot -WritableByService
    Install-LinkLakeDirectoryPlans @($plan)
    return $true
}

function Initialize-LinkLakeServerUpdateAuthenticationKeyFixture {
    if ($env:OS -ne 'Windows_NT') { return }
    $keyPath = Join-Path $dataRoot '.linklake-server-update-auth.key'
    $bytes = for ($index = 0; $index -lt $serverUpdateTestAuthKeyHex.Length; $index += 2) {
        [Convert]::ToByte($serverUpdateTestAuthKeyHex.Substring($index, 2), 16)
    }
    [IO.File]::WriteAllBytes($keyPath, [byte[]]$bytes)

    # 夹具必须复现生产认证密钥的完整边界：Administrator 所有、受保护 DACL，
    # 且仅 SYSTEM、Administrators、LocalService 可访问。不能让 release 二进制
    # 因继承 ACL 而接受一个测试专用的弱密钥。
    $acl = [Security.AccessControl.FileSecurity]::new()
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $localService = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl.SetOwner($administrators)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($system, $administrators, $localService)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $identity, 'FullControl', $allow
            ))
    }
    Set-Acl -LiteralPath $keyPath -AclObject $acl
}

function Add-LinkLakeServerUpdateUnsafeDataDirectoryRule {
    if ($env:OS -ne 'Windows_NT') { return }
    $acl = Get-Acl -LiteralPath $dataRoot
    $authenticatedUsers = [Security.Principal.SecurityIdentifier]::new('S-1-5-11')
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $authenticatedUsers, 'Modify', $inheritance,
            [Security.AccessControl.PropagationFlags]::None, $allow
        ))
    Set-Acl -LiteralPath $dataRoot -AclObject $acl
}

function Get-ServerUpdateHmac([string]$Purpose, [byte[]]$Payload) {
    $prefix = [Text.Encoding]::ASCII.GetBytes("linklake-server-update-state/v1`0")
    $purposeBytes = [Text.Encoding]::UTF8.GetBytes($Purpose)
    $input = [byte[]]::new($prefix.Length + $purposeBytes.Length + 1 + $Payload.Length)
    [Buffer]::BlockCopy($prefix, 0, $input, 0, $prefix.Length)
    [Buffer]::BlockCopy($purposeBytes, 0, $input, $prefix.Length, $purposeBytes.Length)
    $input[$prefix.Length + $purposeBytes.Length] = 0
    [Buffer]::BlockCopy($Payload, 0, $input, $prefix.Length + $purposeBytes.Length + 1, $Payload.Length)
    $hmac = [Security.Cryptography.HMACSHA256]::new([byte[]](1..32))
    try {
        return ([BitConverter]::ToString($hmac.ComputeHash($input))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hmac.Dispose()
    }
}

function Write-ServerAuthenticatedJson([string]$Path, [string]$Purpose, [string]$Json) {
    $payload = [Text.Encoding]::UTF8.GetBytes($Json)
    [IO.File]::WriteAllBytes($Path, $payload)
    $authentication = [ordered]@{
        schema_version = 1
        purpose = $Purpose
        payload_sha256 = ([Security.Cryptography.SHA256]::Create().ComputeHash($payload) | ForEach-Object { $_.ToString('x2') }) -join ''
        hmac_sha256 = Get-ServerUpdateHmac $Purpose $payload
    } | ConvertTo-Json -Compress
    $sidecar = Join-Path (Split-Path -Parent $Path) ".$(Split-Path -Leaf $Path).auth"
    [IO.File]::WriteAllText($sidecar, $authentication, [Text.UTF8Encoding]::new($false))
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Remove-TestRoot {
    if (-not (Test-Path -LiteralPath $root)) { return }
    $resolved = (Resolve-Path -LiteralPath $root).Path
    $expected = [IO.Path]::GetFullPath($root)
    if (-not [string]::Equals($resolved, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe server updater E2E cleanup target: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Invoke-ServerInspect([string]$BinaryPath) {
    $json = (& $BinaryPath __update-db-inspect --data-dir $dataRoot) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'The server database inspection command failed.' }
    return $json | ConvertFrom-Json
}

function New-ServerUpdateContext([object]$Installed, [object]$Staged) {
    [ordered]@{
        schema_version = 1
        canonical_data_dir = $Installed.canonical_data_dir
        canonical_database_path = $Installed.canonical_database_path
        installed_executable = (Resolve-Path -LiteralPath $targetBinary).Path
        installed_executable_sha256 = $Installed.executable_sha256
        installed_version = $Installed.version
        staged_executable = (Resolve-Path -LiteralPath $releaseStage).Path
        staged_executable_sha256 = $Staged.executable_sha256
        staged_version = $Staged.version
        source_schema = $Installed.observed_schema
        source_ledger_sha256 = $Installed.ledger_sha256
        candidate_min_schema = $Staged.min_readable_schema
        candidate_max_schema = $Staged.max_readable_schema
        candidate_target_schema = $Staged.target_schema
        migration_contract_sha256 = $Staged.migration_contract_sha256
    }
}

function Write-ServerApplyPlan([object]$Installed, [object]$Staged) {
    $operationId = [guid]::NewGuid().ToString()
    $operationDirectory = Join-Path (Join-Path $stateRoot 'operations') $operationId
    New-Item -ItemType Directory -Force -Path $operationDirectory | Out-Null
    $planPath = Join-Path $operationDirectory 'plan.json'
    $plan = [ordered]@{
        schema_version = 3
        operation_id = $operationId
        operation_directory = $operationDirectory
        operation = 'apply'
        product = 'server'
        state_directory = $stateRoot
        target_executable = (Resolve-Path -LiteralPath $targetBinary).Path
        staged_executable = (Resolve-Path -LiteralPath $releaseStage).Path
        expected_target_sha256 = Get-Sha256 $targetBinary
        staged_sha256 = Get-Sha256 $releaseStage
        from_version = $Installed.version
        to_version = $Staged.version
        service_installed = $false
        service_was_running = $false
        server_database = [ordered]@{
            kind = 'apply'
            context = New-ServerUpdateContext $Installed $Staged
        }
        created_unix_seconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    } | ConvertTo-Json -Depth 12
    Write-ServerAuthenticatedJson $planPath 'helper-plan' $plan
    $planSha256 = Get-Sha256 $planPath
    $active = [ordered]@{
        schema_version = 3
        operation_id = $operationId
        product = 'server'
        plan_path = $planPath
        plan_sha256 = $planSha256
        created_unix_seconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    } | ConvertTo-Json
    Write-ServerAuthenticatedJson (Join-Path $stateRoot 'active.json') 'active-marker' $active
    [pscustomobject]@{ Path = $planPath; Sha256 = $planSha256 }
}

function Invoke-ServerHelper([object]$Plan, [switch]$ExpectFailure, [string]$ExpectedFailurePattern) {
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # 将原生 stderr 捕获为对象，既避免 Windows PowerShell 在 Stop 模式下中断，
        # 也让负向安全测试能够断言实际拒绝原因。
        $ErrorActionPreference = 'Continue'
        $output = @(& $helperBinary __update-helper --plan $Plan.Path --plan-sha256 $Plan.Sha256 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $outputText = (@($output | ForEach-Object { [string]$_ }) -join "`n")
    if ($ExpectFailure) {
        if ($exitCode -eq 0) { throw 'The server updater unexpectedly accepted a failure-injection plan.' }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedFailurePattern) -and
            $outputText -notmatch $ExpectedFailurePattern) {
            throw "The server updater rejected the plan for an unexpected reason: $outputText"
        }
        return $outputText
    }
    if ($exitCode -ne 0) {
        throw "The server updater helper failed with exit code ${exitCode}: $outputText"
    }
}

function Wait-ServerUpdateState([string]$ExpectedState, [string]$ExpectedOperation) {
    $statusPath = Join-Path $stateRoot 'status.json'
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        if (Test-Path -LiteralPath $statusPath) {
            $status = Get-Content -Raw -LiteralPath $statusPath | ConvertFrom-Json
            if ($status.state -eq $ExpectedState -and $status.operation -eq $ExpectedOperation) {
                return $status
            }
            if ($status.state -eq 'failed') {
                throw "Server update operation failed: $($status.error)"
            }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for server update state $ExpectedState/$ExpectedOperation."
}

function Initialize-ServerDatabase {
    $bindPort = Get-FreeTcpPort
    $controlPort = Get-FreeTcpPort
    $previous = @{}
    foreach ($name in @('LINKLAKE_DATA_DIR', 'LINKLAKE_BIND', 'LINKLAKE_CONTROL_BIND', 'LINKLAKE_LOG_DIR', 'LINKLAKE_ENROLLMENT_TOKEN')) {
        $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    $env:LINKLAKE_DATA_DIR = $dataRoot
    $env:LINKLAKE_BIND = "127.0.0.1:$bindPort"
    $env:LINKLAKE_CONTROL_BIND = "127.0.0.1:$controlPort"
    $env:LINKLAKE_LOG_DIR = (Join-Path $dataRoot 'logs')
    # Use a public fixture value so the bootstrap cannot generate or log a local token.
    $env:LINKLAKE_ENROLLMENT_TOKEN = 'linklake-e2e-public-test-token'
    $process = $null
    try {
        $process = Start-Process -FilePath $debugBinary -PassThru -WindowStyle Hidden
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            if (Test-Path -LiteralPath (Join-Path $dataRoot 'linklake.sqlite3') -PathType Leaf) { return }
            if ($process.HasExited) { throw "The bootstrap server exited with code $($process.ExitCode)." }
            Start-Sleep -Milliseconds 200
        } while ([DateTime]::UtcNow -lt $deadline)
        throw 'The bootstrap server did not create its persistent SQLite database.'
    }
    finally {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            $process.WaitForExit()
        }
        foreach ($name in $previous.Keys) {
            if ($null -eq $previous[$name]) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
            else { Set-Item "Env:$name" $previous[$name] }
        }
    }
}

$result = $null
try {
    Remove-TestRoot
    if (-not $SkipBuild) {
        & cargo build -p linklake-server
        if ($LASTEXITCODE -ne 0) { throw 'Could not build the debug server updater fixture.' }
        & cargo build -p linklake-server --release
        if ($LASTEXITCODE -ne 0) { throw 'Could not build the release server updater fixture.' }
    }
    if (-not (Test-Path -LiteralPath $debugBinary)) { throw "Missing debug server binary: $debugBinary" }
    if (-not (Test-Path -LiteralPath $releaseBinary)) { throw "Missing release server binary: $releaseBinary" }

    foreach ($path in @($stateRoot, $dataRoot, $installRoot, $helperRoot)) {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
    }
    $windowsProtectedDataDirectoryFixture = Initialize-LinkLakeServerUpdateDataDirectoryFixture
    Initialize-ServerDatabase
    $env:LINKLAKE_UPDATE_TEST_SERVER_AUTH_KEY_HEX = $serverUpdateTestAuthKeyHex
    if ($env:LINKLAKE_UPDATE_TEST_SERVER_AUTH_KEY_HEX -ne $serverUpdateTestAuthKeyHex) {
        throw 'The debug server updater test authentication environment was not retained.'
    }
    # Debug helper 使用固定测试密钥；同时预置同一字节值并采用生产等价 ACL，
    # 以便后续 release 二进制的人工回滚路径验证真实的密钥读取和 DACL 门禁。
    if ($windowsProtectedDataDirectoryFixture) {
        Initialize-LinkLakeServerUpdateAuthenticationKeyFixture
    }
    Copy-Item -LiteralPath $debugBinary -Destination $targetBinary
    Copy-Item -LiteralPath $debugBinary -Destination $helperBinary
    $releaseStage = Join-Path (Join-Path $stateRoot 'staging\candidate') $binaryName
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $releaseStage) | Out-Null
    Copy-Item -LiteralPath $releaseBinary -Destination $releaseStage

    $originalBinarySha256 = Get-Sha256 $targetBinary
    $before = Invoke-ServerInspect $targetBinary
    $candidate = Invoke-ServerInspect $releaseStage
    $unsafeDataDirectoryRejected = $false
    if ($env:OS -eq 'Windows_NT') {
        $unsafePlan = Write-ServerApplyPlan $before $candidate
        if ($windowsProtectedDataDirectoryFixture) {
            try {
                Add-LinkLakeServerUpdateUnsafeDataDirectoryRule
                Invoke-ServerHelper $unsafePlan -ExpectFailure `
                    -ExpectedFailurePattern 'LinkLake protected ownership and DACL' | Out-Null
                $unsafeDataDirectoryRejected = $true
            }
            finally {
                # 负向验证后必须恢复同一安装器模板，不能让后续成功路径使用放宽的 ACL。
                Set-LinkLakeDirectoryAcl $dataRoot -WritableByService
            }
        }
        else {
            # 非提升桌面会话不能把 owner 改为 BA；现有继承 ACL 应被 helper 拒绝。
            Invoke-ServerHelper $unsafePlan -ExpectFailure `
                -ExpectedFailurePattern 'LinkLake protected ownership and DACL' | Out-Null
            $unsafeDataDirectoryRejected = $true
        }
    }

    if ($env:OS -eq 'Windows_NT' -and -not $windowsProtectedDataDirectoryFixture) {
        if ($env:GITHUB_ACTIONS -eq 'true') {
            throw 'Windows server-update E2E requires an elevated administrator token to create the production owner/DACL fixture.'
        }
        $result = [ordered]@{
            ok = $true
            schema = $before.observed_schema
            successful_server_update = $false
            manual_server_rollback = $false
            database_preflight = $true
            automatic_database_then_binary_rollback = $false
            unsafe_data_directory_rejected = $unsafeDataDirectoryRejected
            windows_protected_acl_e2e = 'skipped_requires_elevation'
            test_state_cleaned = $true
        }
    }
    else {
        $successPlan = Write-ServerApplyPlan $before $candidate
        Invoke-ServerHelper $successPlan | Out-Null
        $success = Get-Content -Raw -LiteralPath (Join-Path $stateRoot 'status.json') | ConvertFrom-Json
        if ($success.state -ne 'succeeded') { throw "Unexpected server update state: $($success.state)" }
        if ((Get-Sha256 $targetBinary) -ne (Get-Sha256 $releaseStage)) { throw 'Server update did not install the candidate binary.' }
        $afterSuccess = Invoke-ServerInspect $targetBinary
        if ($afterSuccess.observed_schema -ne $candidate.target_schema -or
            $afterSuccess.ledger_sha256 -ne $candidate.migration_contract_sha256) {
            throw 'The candidate server did not preserve the expected migration contract after update.'
        }

        & $targetBinary update rollback --yes --state-dir $stateRoot --data-dir $dataRoot | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'The server manual rollback command could not be scheduled.' }
        $null = Wait-ServerUpdateState -ExpectedState 'rolled_back' -ExpectedOperation 'rollback'
        if ((Get-Sha256 $targetBinary) -ne $originalBinarySha256) {
            throw 'Server manual rollback did not restore the original binary.'
        }
        $afterManualRollback = Invoke-ServerInspect $targetBinary
        if ($afterManualRollback.observed_schema -ne $before.observed_schema -or
            $afterManualRollback.ledger_sha256 -ne $before.ledger_sha256) {
            throw 'Server manual rollback did not retain the source database migration contract.'
        }

        Copy-Item -LiteralPath $debugBinary -Destination $targetBinary -Force
        $beforeFailure = Invoke-ServerInspect $targetBinary
        $candidateFailure = Invoke-ServerInspect $releaseStage
        $failurePlan = Write-ServerApplyPlan $beforeFailure $candidateFailure
        $env:LINKLAKE_UPDATE_TEST_FAIL_SERVICE_RECOVERY = '1'
        try {
            Invoke-ServerHelper $failurePlan -ExpectFailure | Out-Null
        }
        finally {
            Remove-Item Env:LINKLAKE_UPDATE_TEST_FAIL_SERVICE_RECOVERY -ErrorAction SilentlyContinue
        }
        $failure = Get-Content -Raw -LiteralPath (Join-Path $stateRoot 'status.json') | ConvertFrom-Json
        if ($failure.state -ne 'rolled_back' -or $failure.error -notmatch 'service recovery failure') {
            throw 'Server candidate startup failure did not trigger a verified automatic rollback.'
        }
        if ((Get-Sha256 $targetBinary) -ne $originalBinarySha256) {
            throw 'Server automatic rollback did not restore the original binary.'
        }
        $afterFailure = Invoke-ServerInspect $targetBinary
        if ($afterFailure.observed_schema -ne $beforeFailure.observed_schema -or
            $afterFailure.ledger_sha256 -ne $beforeFailure.ledger_sha256) {
            throw 'Server automatic rollback did not restore the original database schema and migration ledger.'
        }

        $result = [ordered]@{
            ok = $true
            schema = $afterFailure.observed_schema
            successful_server_update = $true
            manual_server_rollback = $true
            database_preflight = $true
            automatic_database_then_binary_rollback = $true
            unsafe_data_directory_rejected = if ($env:OS -eq 'Windows_NT') { $unsafeDataDirectoryRejected } else { $null }
            windows_protected_acl_e2e = if ($env:OS -eq 'Windows_NT') { 'passed' } else { 'not_applicable' }
            test_state_cleaned = $true
        }
    }
}
finally {
    if ($null -eq $previousServerUpdateTestAuthKey) {
        Remove-Item Env:LINKLAKE_UPDATE_TEST_SERVER_AUTH_KEY_HEX -ErrorAction SilentlyContinue
    }
    else {
        Set-Item Env:LINKLAKE_UPDATE_TEST_SERVER_AUTH_KEY_HEX $previousServerUpdateTestAuthKey
    }
    Remove-TestRoot
}

$result | ConvertTo-Json
