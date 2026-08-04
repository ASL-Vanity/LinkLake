param(
    [string]$ConfigPath,
    [string]$InstallDirectory = "$env:ProgramFiles\LinkLake",
    [string]$ConfigDirectory = "$env:ProgramData\LinkLake",
    [string]$StateDirectory = "$env:ProgramData\LinkLake\client-state",
    [string]$LogDirectory = "$env:ProgramData\LinkLake\client-logs",
    [switch]$ReplaceConfig,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$installerBoundParameters = @{} + $PSBoundParameters
. (Join-Path $PSScriptRoot 'installer-common.ps1')

Assert-LinkLakeAdministrator
$installerLock = $null
try {
$installerLock = Enter-LinkLakeInstallerLock
$serviceName = 'LinkLakeClient'
$packageRoot = Resolve-LinkLakeSafePath (Split-Path -Parent $PSScriptRoot) 'package root'
$InstallDirectory = Resolve-LinkLakeSafePath $InstallDirectory 'install directory' -RequireLocalDrive
$ConfigDirectory = Resolve-LinkLakeSafePath $ConfigDirectory 'config directory' -RequireLocalDrive
$StateDirectory = Resolve-LinkLakeSafePath $StateDirectory 'state directory' -RequireLocalDrive
$LogDirectory = Resolve-LinkLakeSafePath $LogDirectory 'log directory' -RequireLocalDrive
$sourceBinary = Resolve-LinkLakeSafePath (Join-Path $packageRoot 'bin\linklake-client.exe') 'source binary'
$destinationBinary = Resolve-LinkLakeSafePath (Join-Path $InstallDirectory 'linklake-client.exe') 'destination binary' -RequireLocalDrive
$destinationConfig = Resolve-LinkLakeSafePath (Join-Path $ConfigDirectory 'client.toml') 'destination config' -RequireLocalDrive
$null = Assert-LinkLakePackageChecksums $packageRoot
$release = Read-LinkLakeReleaseIdentity $packageRoot 'windows-x86_64'
$null = Assert-LinkLakePackageBinary $sourceBinary 'LinkLake Client' $release
$sourceBinarySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceBinary).Hash.ToLowerInvariant()
Assert-LinkLakeNotDowngrade $destinationBinary $release.version

$snapshot = Get-LinkLakeServiceSnapshot $serviceName
Assert-LinkLakeServiceSnapshotSupported $snapshot
Assert-LinkLakeServiceOwnsBinary $snapshot $destinationBinary $serviceName
$serviceArguments = Get-LinkLakeServiceCommandArguments $snapshot
if ($snapshot.Exists) {
    if ($serviceArguments.Count -ne 3 -or $serviceArguments[1] -cne '--windows-service') {
        throw 'Existing LinkLakeClient service has an unsupported command line.'
    }
    $existingConfigPath = Resolve-LinkLakeSafePath ([string]$serviceArguments[2]) 'existing client config' -RequireLocalDrive
    if (-not $installerBoundParameters.ContainsKey('ConfigDirectory')) {
        $ConfigDirectory = Resolve-LinkLakeSafePath (Split-Path -Parent $existingConfigPath) 'config directory' -RequireLocalDrive
        $destinationConfig = $existingConfigPath
    }
}
$existingEnvironment = ConvertFrom-LinkLakeEnvironment @($snapshot.Environment)
if (-not $installerBoundParameters.ContainsKey('StateDirectory') -and $existingEnvironment.Contains('LINKLAKE_STATE_DIR')) {
    $StateDirectory = Resolve-LinkLakeSafePath ([string]$existingEnvironment['LINKLAKE_STATE_DIR']) 'state directory' -RequireLocalDrive
}
if (-not $installerBoundParameters.ContainsKey('LogDirectory') -and $existingEnvironment.Contains('LINKLAKE_LOG_DIR')) {
    $LogDirectory = Resolve-LinkLakeSafePath ([string]$existingEnvironment['LINKLAKE_LOG_DIR']) 'log directory' -RequireLocalDrive
}

Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $ConfigDirectory 'config directory'
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $StateDirectory 'state directory'
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $LogDirectory 'log directory'
Assert-LinkLakePathsDoNotOverlap $StateDirectory 'state directory' $LogDirectory 'log directory'
if (Test-LinkLakePathAtOrBelow $ConfigDirectory $StateDirectory) {
    throw 'config directory must not be inside the writable state directory.'
}
if (Test-LinkLakePathAtOrBelow $ConfigDirectory $LogDirectory) {
    throw 'config directory must not be inside the writable log directory.'
}

$sourceConfig = $null
if ($ConfigPath) {
    $sourceConfig = Resolve-LinkLakeSafePath $ConfigPath 'source config'
    Assert-LinkLakeUtf8ConfigFile $sourceConfig 'client config'
    $sourceConfigSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceConfig).Hash.ToLowerInvariant()
}
if (-not (Test-Path -LiteralPath $destinationConfig -PathType Leaf) -and -not $sourceConfig) {
    throw 'ConfigPath is required for a new client installation.'
}
if ($ReplaceConfig -and -not $sourceConfig) { throw 'ReplaceConfig requires ConfigPath.' }
if ((Test-Path -LiteralPath $destinationConfig -PathType Leaf) -and
    -not ($sourceConfig -and ($ReplaceConfig -or -not (Test-Path -LiteralPath $destinationConfig -PathType Leaf)))) {
    Assert-LinkLakeUtf8ConfigFile $destinationConfig 'installed client config'
}

$environment = [ordered]@{}
foreach ($key in $existingEnvironment.Keys) { $environment[$key] = $existingEnvironment[$key] }
$environment['LINKLAKE_LOG_DIR'] = $LogDirectory
$environment['LINKLAKE_STATE_DIR'] = $StateDirectory

$replaceDestinationConfig = $sourceConfig -and ($ReplaceConfig -or -not (Test-Path -LiteralPath $destinationConfig -PathType Leaf))
$preservedConfigAclSddl = $null
if (-not $replaceDestinationConfig -and (Test-Path -LiteralPath $destinationConfig -PathType Leaf)) {
    $preservedConfigAclSddl = (Get-Acl -LiteralPath $destinationConfig).Sddl
}
$directoryPlans = @(
    New-LinkLakeDirectoryTransactionPlan $InstallDirectory
    New-LinkLakeDirectoryTransactionPlan $ConfigDirectory
    New-LinkLakeDirectoryTransactionPlan $StateDirectory -WritableByService
    New-LinkLakeDirectoryTransactionPlan $LogDirectory -WritableByService
)

$temporaryBinary = Join-Path $InstallDirectory ".linklake-client.new-$([guid]::NewGuid().ToString('N')).exe"
$backupBinary = Join-Path $InstallDirectory ".linklake-client.backup-$([guid]::NewGuid().ToString('N')).exe"
$temporaryConfig = Join-Path $ConfigDirectory ".client.new-$([guid]::NewGuid().ToString('N')).toml"
$backupConfig = Join-Path $ConfigDirectory ".client.backup-$([guid]::NewGuid().ToString('N')).toml"
$binaryBackedUp = $false
$binaryReplaced = $false
$configBackedUp = $false
$configReplaced = $false
$binaryPath = "`"$destinationBinary`" --windows-service `"$destinationConfig`""
$shouldStart = (-not $NoStart) -and ((-not $snapshot.Exists) -or $snapshot.WasActive)

$stop = { Stop-LinkLakeServiceChecked $serviceName }
$apply = {
    Install-LinkLakeDirectoryPlans $directoryPlans
    Copy-Item -LiteralPath $sourceBinary -Destination $temporaryBinary -Force
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $temporaryBinary).Hash.ToLowerInvariant() -ne $sourceBinarySha256) {
        throw 'Staged client binary changed after package verification.'
    }
    $null = Assert-LinkLakePackageBinary $temporaryBinary 'LinkLake Client' $release
    if (Test-Path -LiteralPath $destinationBinary) {
        Move-Item -LiteralPath $destinationBinary -Destination $backupBinary
        $script:binaryBackedUp = $true
    }
    Move-Item -LiteralPath $temporaryBinary -Destination $destinationBinary
    $script:binaryReplaced = $true
    Set-LinkLakeSecretFileAcl $destinationBinary -Executable

    if ($replaceDestinationConfig) {
        Copy-Item -LiteralPath $sourceConfig -Destination $temporaryConfig -Force
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $temporaryConfig).Hash.ToLowerInvariant() -ne $sourceConfigSha256) {
            throw 'Staged client config changed after input validation.'
        }
        Assert-LinkLakeUtf8ConfigFile $temporaryConfig 'staged client config'
        if (Test-Path -LiteralPath $destinationConfig) {
            Move-Item -LiteralPath $destinationConfig -Destination $backupConfig
            $script:configBackedUp = $true
        }
        Move-Item -LiteralPath $temporaryConfig -Destination $destinationConfig
        $script:configReplaced = $true
    }
    Set-LinkLakeSecretFileAcl $destinationConfig

    if (-not $snapshot.Exists) {
        New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName 'LinkLake Client' `
            -Description 'LinkLake secure tunnel client' -StartupType Automatic | Out-Null
    }
    Invoke-LinkLakeSc @('config', $serviceName, 'binPath=', $binaryPath, 'start=', 'auto', 'obj=', 'NT AUTHORITY\LocalService', 'password=', '')
    Invoke-LinkLakeSc @('sidtype', $serviceName, 'none')
    Invoke-LinkLakeSc @('privs', $serviceName, 'SeChangeNotifyPrivilege')
    Set-LinkLakeServiceEnvironment $serviceName (ConvertTo-LinkLakeEnvironment $environment)
    Invoke-LinkLakeSc @('failure', $serviceName, 'reset=', '86400', 'actions=', 'restart/3000/restart/10000/restart/30000')
}
$validate = {
    $null = Assert-LinkLakePackageBinary $destinationBinary 'LinkLake Client' $release
    Assert-LinkLakeUtf8ConfigFile $destinationConfig 'installed client config'
}
$start = {
    Start-LinkLakeServiceChecked $serviceName
    if ($snapshot.State -eq 'Paused') {
        Suspend-Service -Name $serviceName -ErrorAction Stop
        Wait-LinkLakeServiceStatus $serviceName ([ServiceProcess.ServiceControllerStatus]::Paused)
    }
}
$rollback = {
    $rollbackErrors = [Collections.Generic.List[string]]::new()
    try { Stop-LinkLakeServiceChecked $serviceName 10 }
    catch { $rollbackErrors.Add("stop replacement service: $($_.Exception.Message)") }
    try {
        if ($script:binaryReplaced -and (Test-Path -LiteralPath $destinationBinary)) {
            Remove-Item -LiteralPath $destinationBinary -Force
        }
        if ($script:binaryBackedUp -and (Test-Path -LiteralPath $backupBinary)) {
            Move-Item -LiteralPath $backupBinary -Destination $destinationBinary
        }
    }
    catch { $rollbackErrors.Add("restore binary: $($_.Exception.Message)") }
    try {
        if ($replaceDestinationConfig) {
            if ($script:configReplaced -and (Test-Path -LiteralPath $destinationConfig)) {
                Remove-Item -LiteralPath $destinationConfig -Force
            }
            if ($script:configBackedUp -and (Test-Path -LiteralPath $backupConfig)) {
                Move-Item -LiteralPath $backupConfig -Destination $destinationConfig
            }
        }
        elseif ($preservedConfigAclSddl -and (Test-Path -LiteralPath $destinationConfig)) {
            $acl = Get-Acl -LiteralPath $destinationConfig
            $acl.SetSecurityDescriptorSddlForm($preservedConfigAclSddl)
            Set-Acl -LiteralPath $destinationConfig -AclObject $acl
        }
    }
    catch { $rollbackErrors.Add("restore client config: $($_.Exception.Message)") }
    try { Restore-LinkLakeServiceSnapshot $serviceName $snapshot }
    catch { $rollbackErrors.Add("restore service configuration: $($_.Exception.Message)") }
    foreach ($path in @($temporaryBinary, $temporaryConfig)) {
        try {
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        }
        catch { $rollbackErrors.Add("remove staged artifact ${path}: $($_.Exception.Message)") }
    }
    try { Restore-LinkLakeDirectoryPlans $directoryPlans }
    catch { $rollbackErrors.Add("restore directory ACLs: $($_.Exception.Message)") }
    if ($rollbackErrors.Count -gt 0) { throw ($rollbackErrors -join '; ') }
}
$recover = { Restore-LinkLakeServiceRuntimeState $serviceName $snapshot }

Invoke-LinkLakeTransactionalChange -Stop $stop -Apply $apply -Validate $validate -Start $start `
    -Rollback $rollback -Recover $recover -WasRunning $snapshot.WasActive -ShouldStart $shouldStart

foreach ($path in @($backupBinary, $backupConfig, $temporaryBinary, $temporaryConfig)) {
    Remove-LinkLakeArtifactBestEffort $path
}
Write-Host "LinkLake Client $($release.version) installed. Existing config was preserved unless ReplaceConfig was requested."
}
finally {
    Exit-LinkLakeInstallerLock $installerLock
}
