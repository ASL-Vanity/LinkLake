param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath 'Variable:PSNativeCommandUseErrorActionPreference') {
    $PSNativeCommandUseErrorActionPreference = $false
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$root = Join-Path $projectRoot 'target\manager-update-e2e'
$state = Join-Path $root 'state'
$install = Join-Path $root 'installed-manager'
$helper = Join-Path $root 'linklake-client.exe'
$built = Join-Path $projectRoot 'target\debug\linklake-client.exe'

function Add-HashBytes {
    param(
        [Security.Cryptography.HashAlgorithm]$Hash,
        [byte[]]$Bytes
    )
    if ($Bytes.Length -gt 0) {
        $null = $Hash.TransformBlock($Bytes, 0, $Bytes.Length, $Bytes, 0)
    }
}

function Get-BigEndianBytes {
    param([UInt64]$Value, [int]$Width)
    $bytes = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    if ($Width -eq 8) { return $bytes }
    return $bytes[4..7]
}

function Convert-HexToBytes([string]$Value) {
    $bytes = [byte[]]::new($Value.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Value.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function Get-ManagerTreeSha256([string]$Path) {
    $rootPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $files = Get-ChildItem -LiteralPath $rootPath -File -Recurse | ForEach-Object {
        [pscustomobject]@{
            Path = $_.FullName
            Relative = $_.FullName.Substring($rootPath.Length + 1).Replace('\', '/')
            Length = [UInt64]$_.Length
        }
    } | Sort-Object Relative
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        Add-HashBytes $hash ([Text.Encoding]::ASCII.GetBytes("linklake-manager-tree-v1`0"))
        foreach ($file in $files) {
            $relative = [Text.Encoding]::UTF8.GetBytes($file.Relative)
            Add-HashBytes $hash (Get-BigEndianBytes ([UInt64]$relative.Length) 8)
            Add-HashBytes $hash $relative
            Add-HashBytes $hash (Get-BigEndianBytes $file.Length 8)
            Add-HashBytes $hash ([byte[]](0, 0, 0, 0))
            Add-HashBytes $hash (Convert-HexToBytes (Get-FileHash -LiteralPath $file.Path -Algorithm SHA256).Hash)
        }
        $null = $hash.TransformFinalBlock([byte[]]::new(0), 0, 0)
        return (($hash.Hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally { $hash.Dispose() }
}

function Write-ManagerPayload([string]$Path, [string]$Version) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    [IO.File]::WriteAllText((Join-Path $Path 'linklake_manager.exe'), "manager-$Version")
    [IO.File]::WriteAllText((Join-Path $Path 'runtime.dat'), "runtime-$Version")
    $manifest = [ordered]@{
        product = 'LinkLake Manager'
        component = 'manager'
        version = $Version
        target = 'windows-x86_64'
        built_unix_seconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    } | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $Path 'release.json'), $manifest, [Text.UTF8Encoding]::new($false))
}

function Write-StagedMetadata([string]$Version, [string]$CurrentVersion) {
    $versionRoot = Join-Path $state "staging\$Version"
    $payload = Join-Path $versionRoot 'manager'
    $metadata = [ordered]@{
        schema_version = 2
        current_version = $CurrentVersion
        version = $Version
        target = 'windows-x86_64'
        archive_name = "linklake-manager-$Version-windows-x86_64.zip"
        archive_sha256 = 'a' * 64
        signature_key_id = 'e2e-fixture'
        staged_directory = $payload
        staged_manifest = Join-Path $payload 'release.json'
        payload_sha256 = Get-ManagerTreeSha256 $payload
        downloaded_unix_seconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    } | ConvertTo-Json
    [IO.File]::WriteAllText(
        (Join-Path $versionRoot 'manager-staged.json'),
        $metadata,
        [Text.UTF8Encoding]::new($false)
    )
}

function Start-ManagerLock {
    $lock = [IO.File]::Open(
        (Join-Path $install 'linklake_manager.exe'),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $process = Start-Process -FilePath $env:ComSpec -ArgumentList @(
        '/d', '/c', 'ping 127.0.0.1 -n 121 >nul'
    ) -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 500
    if ($process.HasExited) {
        $lock.Dispose()
        throw 'Manager handshake process exited unexpectedly.'
    }
    return [pscustomobject]@{ Process = $process; Lock = $lock }
}

function Stop-ManagerLock($Manager) {
    $Manager.Lock.Dispose()
    if (-not $Manager.Process.HasExited) {
        & taskkill.exe /pid $Manager.Process.Id /f /t | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not terminate Manager handshake process $($Manager.Process.Id)."
        }
    }
    if (-not $Manager.Process.WaitForExit(10000)) {
        throw "Manager handshake process $($Manager.Process.Id) did not exit."
    }
    Start-Sleep -Milliseconds 100
    if (Get-Process -Id $Manager.Process.Id -ErrorAction SilentlyContinue) {
        throw "Manager handshake PID $($Manager.Process.Id) is still present after termination."
    }
}

function Invoke-ManagerApply($Manager) {
    $json = (& $helper manager-update apply --install-dir $install --manager-pid $Manager.Process.Id --state-dir $state --yes) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Manager apply was not scheduled.' }
    $schedule = $json | ConvertFrom-Json
    if ($schedule.schema_version -ne 2 -or -not $schedule.requires_manager_exit) {
        throw 'Manager schedule JSON contract is invalid.'
    }
    if ($schedule.manager_process_id -ne $Manager.Process.Id -or -not $schedule.status_file -or -not $schedule.manager_process_identity) {
        throw 'Manager exit handshake fields are invalid.'
    }
    return $schedule
}

function Wait-ManagerStatus([string[]]$ExpectedStates) {
    $path = Join-Path $state 'manager-status.json'
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        if (Test-Path -LiteralPath $path) {
            $status = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
            if ($ExpectedStates -contains $status.state) { return $status }
            if (@('succeeded', 'rolled_back', 'failed') -contains $status.state) {
                throw "Manager reached unexpected terminal state $($status.state): $($status.error)"
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for Manager state: $($ExpectedStates -join ', ')."
}

function Assert-InstalledVersion([string]$Version) {
    $actual = (Get-Content -Raw -LiteralPath (Join-Path $install 'release.json') | ConvertFrom-Json).version
    if ($actual -ne $Version) { throw "Expected Manager $Version, found $actual." }
}

if (-not $SkipBuild) {
    & cargo build -p linklake-client
    if ($LASTEXITCODE -ne 0) { throw 'Could not build LinkLake client helper.' }
}
if (-not (Test-Path -LiteralPath $built)) { throw "Missing updater helper: $built" }

if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
New-Item -ItemType Directory -Force -Path $state, $install | Out-Null
Copy-Item -LiteralPath $built -Destination $helper
Write-ManagerPayload -Path $install -Version '0.8.0-rc.1'

$success = Join-Path $state 'staging\0.8.0\manager'
Write-ManagerPayload -Path $success -Version '0.8.0'
Write-StagedMetadata -Version '0.8.0' -CurrentVersion '0.8.0-rc.1'
$manager = Start-ManagerLock
$schedule = Invoke-ManagerApply $manager
Write-Host "Manager E2E scheduled PID $($manager.Process.Id)"
$null = Wait-ManagerStatus @('waiting_for_exit')
Write-Host "Manager E2E observed waiting_for_exit"
Stop-ManagerLock $manager
Write-Host "Manager E2E terminated PID $($manager.Process.Id)"
$successStatus = Wait-ManagerStatus @('succeeded')
Write-Host "Manager E2E observed succeeded"
Assert-InstalledVersion '0.8.0'
if ($successStatus.requires_manager_exit) { throw 'Succeeded status still requests Manager exit.' }

$manager = Start-ManagerLock
$json = (& $helper manager-update rollback --install-dir $install --manager-pid $manager.Process.Id --state-dir $state --yes) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Manager rollback was not scheduled.' }
if (-not (($json | ConvertFrom-Json).requires_manager_exit)) { throw 'Rollback did not request Manager exit.' }
$null = Wait-ManagerStatus @('waiting_for_exit')
Stop-ManagerLock $manager
$null = Wait-ManagerStatus @('rolled_back')
Assert-InstalledVersion '0.8.0-rc.1'

$failure = Join-Path $state 'staging\0.8.1\manager'
Write-ManagerPayload -Path $failure -Version '0.8.1'
Write-StagedMetadata -Version '0.8.1' -CurrentVersion '0.8.0-rc.1'
$env:LINKLAKE_MANAGER_UPDATE_TEST_FAIL_AFTER_SWITCH = '1'
$manager = Start-ManagerLock
$null = Invoke-ManagerApply $manager
$null = Wait-ManagerStatus @('waiting_for_exit')
Remove-Item Env:LINKLAKE_MANAGER_UPDATE_TEST_FAIL_AFTER_SWITCH
Stop-ManagerLock $manager
$failureStatus = Wait-ManagerStatus @('rolled_back')
if (-not $failureStatus.error) { throw 'Automatic rollback did not record the failure.' }
Assert-InstalledVersion '0.8.0-rc.1'

$tampered = Join-Path $state 'staging\0.8.2\manager'
Write-ManagerPayload -Path $tampered -Version '0.8.2'
Write-StagedMetadata -Version '0.8.2' -CurrentVersion '0.8.0-rc.1'
$manager = Start-ManagerLock
$null = Invoke-ManagerApply $manager
$null = Wait-ManagerStatus @('waiting_for_exit')
[IO.File]::AppendAllText((Join-Path $tampered 'runtime.dat'), '-tampered')
Stop-ManagerLock $manager
$tamperStatus = Wait-ManagerStatus @('failed')
if ($tamperStatus.error -notmatch 'staged Manager payload changed') { throw 'Staged tamper was not diagnosed.' }
Assert-InstalledVersion '0.8.0-rc.1'

$concurrent = Join-Path $state 'staging\0.8.3\manager'
Write-ManagerPayload -Path $concurrent -Version '0.8.3'
Write-StagedMetadata -Version '0.8.3' -CurrentVersion '0.8.0-rc.1'
$manager = Start-ManagerLock
$null = Invoke-ManagerApply $manager
$null = Wait-ManagerStatus @('waiting_for_exit')
[IO.File]::WriteAllText((Join-Path $install 'concurrent-change.txt'), 'changed')
Stop-ManagerLock $manager
$targetStatus = Wait-ManagerStatus @('failed')
if ($targetStatus.error -notmatch 'installed Manager changed') { throw 'Concurrent target change was not diagnosed.' }
Remove-Item -LiteralPath (Join-Path $install 'concurrent-change.txt') -Force
Assert-InstalledVersion '0.8.0-rc.1'

$locked = Join-Path $state 'staging\0.8.4\manager'
Write-ManagerPayload -Path $locked -Version '0.8.4'
Write-StagedMetadata -Version '0.8.4' -CurrentVersion '0.8.0-rc.1'
$env:LINKLAKE_MANAGER_UPDATE_TEST_EXIT_TIMEOUT_SECONDS = '1'
$manager = Start-ManagerLock
$null = Invoke-ManagerApply $manager
Remove-Item Env:LINKLAKE_MANAGER_UPDATE_TEST_EXIT_TIMEOUT_SECONDS
$timeoutStatus = Wait-ManagerStatus @('failed')
Stop-ManagerLock $manager
if ($timeoutStatus.error -notmatch 'did not exit within 1 seconds') { throw 'Manager exit timeout was not diagnosed.' }
Assert-InstalledVersion '0.8.0-rc.1'

[ordered]@{
    ok = $true
    schema_version = 2
    atomic_install = $true
    manual_rollback = $true
    automatic_rollback = $true
    staged_tamper_rejected = $true
    concurrent_target_change_rejected = $true
    locked_directory_timeout = $true
    status_file = Join-Path $state 'manager-status.json'
} | ConvertTo-Json
