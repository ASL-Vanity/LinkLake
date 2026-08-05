param(
    [string]$InstallDirectory = "$env:ProgramFiles\LinkLake",
    [string]$DataDirectory = "$env:ProgramData\LinkLake\data",
    [string]$LogDirectory = "$env:ProgramData\LinkLake\logs",
    [string]$SecretsDirectory = "$env:ProgramData\LinkLake\secrets",
    [string]$Bind = '127.0.0.1:32100',
    [string]$ControlBind = '127.0.0.1:32101',
    [string]$HttpBind,
    [string]$HttpsBind,
    [string]$TlsPassthroughBind,
    [string]$UdpRelayBind,
    [string]$UdpRelayEndpoint,
    [string]$UdpRelayServerName,
    [ValidateSet('auto', 'ipv4_only', 'dual_stack_required')][string]$UdpPublicBindMode,
    [SecureString]$EnrollmentToken,
    [string]$AdminUsername = 'admin',
    [SecureString]$AdminPassword,
    [string]$ManagementCertificate,
    [string]$ManagementKey,
    [string]$ControlCertificate,
    [string]$ControlKey,
    [string]$RecoverCandidateHandoffDirectory,
    [switch]$RestoreAfterCandidateHandoff,
    [switch]$ConfirmDataLoss,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$installerBoundParameters = @{} + $PSBoundParameters
. (Join-Path $PSScriptRoot 'installer-common.ps1')

function Get-LinkLakeServerInstallerSha256 {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Name was not found."
    }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-LinkLakeServerInstallerSha256 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Name
    )
    if ((Get-LinkLakeServerInstallerSha256 $Path $Name) -cne $Expected) {
        throw "$Name changed after it was verified."
    }
}

function Invoke-LinkLakeServerMaintenanceChecked {
    param(
        [Parameter(Mandatory)][string]$BinaryPath,
        [Parameter(Mandatory)][string[]]$CommandArguments,
        [Parameter(Mandatory)][string]$Operation
    )
    # 维护命令的标准输出和错误输出可能包含部署路径；安装器不转发它们，以免未来
    # 命令扩展时意外把环境或凭据细节写入安装日志。
    $output = @(& $BinaryPath @CommandArguments 2>&1)
    $exitCode = $LASTEXITCODE
    $output = $null
    if ($exitCode -ne 0) {
        throw "$Operation failed with exit code $exitCode."
    }
}

function Set-LinkLakeServerInstallerSnapshotAcl {
    param([Parameter(Mandatory)][string]$Path, [switch]$Directory)
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    if ($Directory) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
        $propagation = [Security.AccessControl.PropagationFlags]::None
        $acl.SetOwner($administrators)
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system, 'FullControl', $inheritance, $propagation, $allow))
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($administrators, 'FullControl', $inheritance, $propagation, $allow))
    }
    else {
        $acl = [Security.AccessControl.FileSecurity]::new()
        $acl.SetOwner($administrators)
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system, 'FullControl', $allow))
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($administrators, 'FullControl', $allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-LinkLakeServerCandidateHandoffPath {
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$Name)
    return Resolve-LinkLakeSafePath (Join-Path $Directory $Name) "candidate handoff $Name" -RequireLocalDrive
}

function Write-LinkLakeServerCandidateHandoffFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Record
    )
    if (Test-Path -LiteralPath $Path) {
        throw "Candidate handoff artifact already exists: $Path"
    }
    $json = $Record | ConvertTo-Json -Compress -Depth 5
    if ([Text.Encoding]::UTF8.GetByteCount($json) -le 0 -or [Text.Encoding]::UTF8.GetByteCount($json) -gt 16KB) {
        throw 'Candidate handoff artifact has an invalid size.'
    }
    $temporary = "$Path.new-$([guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText($temporary, $json, [Text.UTF8Encoding]::new($false))
        Set-LinkLakeServerInstallerSnapshotAcl $temporary
        Move-Item -LiteralPath $temporary -Destination $Path -ErrorAction Stop
        Set-LinkLakeServerInstallerSnapshotAcl $Path
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-LinkLakeArtifactBestEffort $temporary
        }
    }
}

function New-LinkLakeServerCandidateHandoffRecord {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$OperationId,
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$DataDirectory,
        [Parameter(Mandatory)][string]$InstallDirectory,
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][string]$SnapshotSha256,
        [Parameter(Mandatory)][string[]]$RollbackBinaryPaths,
        [Parameter(Mandatory)][string]$RollbackBinarySha256
    )
    $recordPath = Get-LinkLakeServerCandidateHandoffPath $Directory 'candidate-handoff.json'
    Write-LinkLakeServerCandidateHandoffFile $recordPath ([ordered]@{
            schema_version = 1
            kind = 'linklake-server-candidate-handoff'
            operation_id = $OperationId
            service_name = $ServiceName
            data_directory = $DataDirectory
            install_directory = $InstallDirectory
            snapshot_directory = $Directory
            snapshot_path = $SnapshotPath
            snapshot_sha256 = $SnapshotSha256
            rollback_binary_paths = @($RollbackBinaryPaths)
            rollback_binary_sha256 = $RollbackBinarySha256
            created_unix_seconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        })
    return $recordPath
}

function New-LinkLakeServerCandidateHandoffStage {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][ValidateSet('candidate-starting', 'restore-started', 'restore-complete')][string]$Stage,
        [Parameter(Mandatory)]$Record
    )
    $stageName = "candidate-handoff.$Stage.json"
    $stagePath = Get-LinkLakeServerCandidateHandoffPath $Directory $stageName
    Write-LinkLakeServerCandidateHandoffFile $stagePath ([ordered]@{
            schema_version = 1
            operation_id = $Record.OperationId
            snapshot_sha256 = $Record.SnapshotSha256
            stage = $Stage
        })
    return $stagePath
}

function Test-LinkLakeServerCandidateHandoffStage {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][ValidateSet('candidate-starting', 'restore-started', 'restore-complete')][string]$Stage,
        [Parameter(Mandatory)]$Record
    )
    $stagePath = Get-LinkLakeServerCandidateHandoffPath $Directory "candidate-handoff.$Stage.json"
    if (-not (Test-Path -LiteralPath $stagePath)) { return $false }
    if (-not (Test-Path -LiteralPath $stagePath -PathType Leaf)) {
        throw 'Candidate handoff stage is not a regular file.'
    }
    $item = Get-Item -Force -LiteralPath $stagePath
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -le 0 -or $item.Length -gt 4KB) {
        throw 'Candidate handoff stage is invalid.'
    }
    try { $value = [IO.File]::ReadAllText($stagePath, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Candidate handoff stage is not valid JSON.' }
    $expectedFields = @('schema_version', 'operation_id', 'snapshot_sha256', 'stage')
    if ($null -eq $value -or @(Compare-Object $expectedFields @($value.PSObject.Properties.Name)).Count -ne 0 -or
        $value.schema_version -is [string] -or [int]$value.schema_version -ne 1 -or
        $value.operation_id -cne $Record.OperationId -or
        $value.snapshot_sha256 -cne $Record.SnapshotSha256 -or $value.stage -cne $Stage) {
        throw 'Candidate handoff stage does not match its record.'
    }
    return $true
}

function Select-LinkLakeServerCandidateHandoffRollbackBinary {
    param([Parameter(Mandatory)]$Record)
    foreach ($path in @($Record.RollbackBinaryPaths)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        if ((Get-LinkLakeServerInstallerSha256 $path 'candidate handoff rollback binary') -ceq $Record.RollbackBinarySha256) {
            return $path
        }
    }
    throw 'No verified pre-candidate server binary is available for candidate handoff recovery.'
}

function Invoke-LinkLakeServerCandidateHandoffRecovery {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$DataDirectory,
        [Parameter(Mandatory)][string]$InstallDirectory,
        [Parameter(Mandatory)][string]$ServiceName,
        [switch]$RestoreAfterCandidateHandoff,
        [switch]$ConfirmDataLoss
    )
    $record = Read-LinkLakeServerCandidateHandoffRecord `
        -HandoffDirectory $Directory -ExpectedDataDirectory $DataDirectory `
        -ExpectedInstallDirectory $InstallDirectory -ExpectedServiceName $ServiceName
    if (-not (Test-LinkLakeServerCandidateHandoffStage $record.HandoffDirectory 'candidate-starting' $record)) {
        throw 'Candidate handoff recovery record was not marked before the candidate service start.'
    }
    if (Test-LinkLakeServerCandidateHandoffStage $record.HandoffDirectory 'restore-complete' $record) {
        throw 'Candidate handoff database recovery was already completed; refusing to restore its old snapshot again.'
    }
    if (Test-LinkLakeServerCandidateHandoffStage $record.HandoffDirectory 'restore-started' $record) {
        throw 'Candidate handoff database recovery was interrupted after confirmation; refusing to retry an uncertain restore automatically.'
    }
    if ((Get-LinkLakeCandidateHandoffRecoveryDecision $true $RestoreAfterCandidateHandoff $ConfirmDataLoss) -ne 'restore_snapshot') {
        throw 'Candidate handoff recovery requires both -RestoreAfterCandidateHandoff and -ConfirmDataLoss because restoring the snapshot discards candidate writes.'
    }
    Assert-LinkLakeServerInstallerSha256 $record.SnapshotPath $record.SnapshotSha256 'candidate handoff database snapshot'
    $rollbackBinary = Select-LinkLakeServerCandidateHandoffRollbackBinary $record
    New-LinkLakeServerCandidateHandoffStage $record.HandoffDirectory 'restore-started' $record | Out-Null
    Stop-LinkLakeServiceChecked $ServiceName 10
    Assert-LinkLakeServerInstallerSha256 $record.SnapshotPath $record.SnapshotSha256 'candidate handoff database snapshot'
    Assert-LinkLakeServerInstallerSha256 $rollbackBinary $record.RollbackBinarySha256 'candidate handoff rollback binary'
    Invoke-LinkLakeServerMaintenanceChecked -BinaryPath $rollbackBinary `
        -CommandArguments @('restore', '--data-dir', $record.DataDirectory, '--input', $record.SnapshotPath) `
        -Operation 'candidate handoff server database restore'
    Assert-LinkLakeServerInstallerSha256 $record.SnapshotPath $record.SnapshotSha256 'candidate handoff database snapshot'
    Assert-LinkLakeServerInstallerSha256 $rollbackBinary $record.RollbackBinarySha256 'candidate handoff rollback binary'
    $verificationPath = Get-LinkLakeServerCandidateHandoffPath $record.HandoffDirectory (
        ".server-restored-$([guid]::NewGuid().ToString('N')).sqlite3"
    )
    Invoke-LinkLakeServerMaintenanceChecked -BinaryPath $rollbackBinary `
        -CommandArguments @('backup', '--data-dir', $record.DataDirectory, '--output', $verificationPath) `
        -Operation 'candidate handoff restored database verification backup'
    Set-LinkLakeServerInstallerSnapshotAcl $verificationPath
    $null = Get-LinkLakeServerInstallerSha256 $verificationPath 'candidate handoff restored database verification backup'
    New-LinkLakeServerCandidateHandoffStage $record.HandoffDirectory 'restore-complete' $record | Out-Null
    # 先保留完成标记，再移除可执行的 pending record；若清理被中断，后续运行只会
    # 拒绝重复恢复，不会把已经产生的新写入再次覆盖。
    Remove-LinkLakeArtifactBestEffort $record.RecordPath
    Remove-LinkLakeArtifactBestEffort $record.HandoffDirectory
    Write-Host 'Candidate handoff database snapshot was restored after explicit data-loss confirmation. The LinkLake service remains stopped; inspect it before starting the restored server.'
}

Assert-LinkLakeAdministrator
$installerLock = $null
$enrollmentPointer = [IntPtr]::Zero
$passwordPointer = [IntPtr]::Zero
$plainEnrollmentToken = $null
$plainPassword = $null
try {
$installerLock = Enter-LinkLakeInstallerLock
$serviceName = 'LinkLakeServer'
$packageRoot = Resolve-LinkLakeSafePath (Split-Path -Parent $PSScriptRoot) 'package root'
$InstallDirectory = Resolve-LinkLakeSafePath $InstallDirectory 'install directory' -RequireLocalDrive
$DataDirectory = Resolve-LinkLakeSafePath $DataDirectory 'data directory' -RequireLocalDrive
$LogDirectory = Resolve-LinkLakeSafePath $LogDirectory 'log directory' -RequireLocalDrive
$SecretsDirectory = Resolve-LinkLakeSafePath $SecretsDirectory 'secrets directory' -RequireLocalDrive
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $DataDirectory 'data directory'
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $LogDirectory 'log directory'
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $SecretsDirectory 'secrets directory'
Assert-LinkLakePathsDoNotOverlap $DataDirectory 'data directory' $LogDirectory 'log directory'
Assert-LinkLakePathsDoNotOverlap $DataDirectory 'data directory' $SecretsDirectory 'secrets directory'
Assert-LinkLakePathsDoNotOverlap $LogDirectory 'log directory' $SecretsDirectory 'secrets directory'
$sourceBinary = Resolve-LinkLakeSafePath (Join-Path $packageRoot 'bin\linklake-server.exe') 'source binary'
$destinationBinary = Resolve-LinkLakeSafePath (Join-Path $InstallDirectory 'linklake-server.exe') 'destination binary' -RequireLocalDrive
$null = Assert-LinkLakePackageChecksums $packageRoot
$release = Read-LinkLakeReleaseIdentity $packageRoot 'windows-x86_64'
$null = Assert-LinkLakePackageBinary $sourceBinary 'LinkLake Server' $release
$sourceBinarySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceBinary).Hash.ToLowerInvariant()
Assert-LinkLakeNotDowngrade $destinationBinary $release.version

foreach ($entry in @{
        Bind = $Bind; ControlBind = $ControlBind; HttpBind = $HttpBind; HttpsBind = $HttpsBind
        TlsPassthroughBind = $TlsPassthroughBind; UdpRelayBind = $UdpRelayBind
        UdpRelayEndpoint = $UdpRelayEndpoint; UdpRelayServerName = $UdpRelayServerName
        UdpPublicBindMode = $UdpPublicBindMode
        AdminUsername = $AdminUsername
    }.GetEnumerator()) {
    Assert-LinkLakeSafeValue ([string]$entry.Value) $entry.Key
}
$snapshot = Get-LinkLakeServiceSnapshot $serviceName
Assert-LinkLakeServiceSnapshotSupported $snapshot
Assert-LinkLakeServiceOwnsBinary $snapshot $destinationBinary $serviceName
if ($snapshot.Exists) {
    $serviceArguments = Get-LinkLakeServiceCommandArguments $snapshot
    if ($serviceArguments.Count -ne 2 -or $serviceArguments[1] -cne '--windows-service') {
        throw 'Existing LinkLakeServer service has an unsupported command line.'
    }
}
$existingEnvironment = ConvertFrom-LinkLakeEnvironment @($snapshot.Environment)

function Resolve-EnvironmentSetting {
    param([string]$ParameterName, [string]$EnvironmentName, [AllowEmptyString()][string]$Value)
    if ($installerBoundParameters.ContainsKey($ParameterName)) { return $Value }
    if ($existingEnvironment.Contains($EnvironmentName)) { return [string]$existingEnvironment[$EnvironmentName] }
    return $Value
}

$DataDirectory = Resolve-LinkLakeSafePath (Resolve-EnvironmentSetting 'DataDirectory' 'LINKLAKE_DATA_DIR' $DataDirectory) 'data directory' -RequireLocalDrive
$LogDirectory = Resolve-LinkLakeSafePath (Resolve-EnvironmentSetting 'LogDirectory' 'LINKLAKE_LOG_DIR' $LogDirectory) 'log directory' -RequireLocalDrive
$databaseSnapshotParent = Split-Path -Parent $DataDirectory
if ([string]::IsNullOrWhiteSpace($databaseSnapshotParent)) {
    throw 'Could not derive a parent directory for the server database snapshot.'
}
$databaseSnapshotDirectory = Resolve-LinkLakeSafePath (
    (Join-Path $databaseSnapshotParent ".linklake-server-upgrade-$([guid]::NewGuid().ToString('N'))")
) 'server database snapshot directory' -RequireLocalDrive
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $DataDirectory 'data directory'
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $LogDirectory 'log directory'
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $SecretsDirectory 'secrets directory'
Assert-LinkLakePathsDoNotOverlap $DataDirectory 'data directory' $LogDirectory 'log directory'
Assert-LinkLakePathsDoNotOverlap $DataDirectory 'data directory' $SecretsDirectory 'secrets directory'
Assert-LinkLakePathsDoNotOverlap $LogDirectory 'log directory' $SecretsDirectory 'secrets directory'
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $databaseSnapshotDirectory 'server database snapshot directory'
Assert-LinkLakePathsDoNotOverlap $DataDirectory 'data directory' $databaseSnapshotDirectory 'server database snapshot directory'
Assert-LinkLakePathsDoNotOverlap $LogDirectory 'log directory' $databaseSnapshotDirectory 'server database snapshot directory'
Assert-LinkLakePathsDoNotOverlap $SecretsDirectory 'secrets directory' $databaseSnapshotDirectory 'server database snapshot directory'
if ([string]::IsNullOrWhiteSpace($RecoverCandidateHandoffDirectory)) {
    if ($RestoreAfterCandidateHandoff -or $ConfirmDataLoss) {
        throw '-RestoreAfterCandidateHandoff and -ConfirmDataLoss are only valid together with -RecoverCandidateHandoffDirectory.'
    }
}
else {
    if ($NoStart) {
        throw 'Candidate handoff recovery cannot be combined with -NoStart.'
    }
    Invoke-LinkLakeServerCandidateHandoffRecovery -Directory $RecoverCandidateHandoffDirectory `
        -DataDirectory $DataDirectory -InstallDirectory $InstallDirectory -ServiceName $serviceName `
        -RestoreAfterCandidateHandoff:$RestoreAfterCandidateHandoff -ConfirmDataLoss:$ConfirmDataLoss
    return
}
$Bind = Resolve-EnvironmentSetting 'Bind' 'LINKLAKE_BIND' $Bind
$ControlBind = Resolve-EnvironmentSetting 'ControlBind' 'LINKLAKE_CONTROL_BIND' $ControlBind

$environment = [ordered]@{}
foreach ($key in $existingEnvironment.Keys) { $environment[$key] = $existingEnvironment[$key] }
$environment['LINKLAKE_BIND'] = $Bind
$environment['LINKLAKE_CONTROL_BIND'] = $ControlBind
$environment['LINKLAKE_DATA_DIR'] = $DataDirectory
$environment['LINKLAKE_LOG_DIR'] = $LogDirectory

foreach ($mapping in @(
        @('HttpBind', 'LINKLAKE_HTTP_BIND', $HttpBind),
        @('HttpsBind', 'LINKLAKE_HTTPS_BIND', $HttpsBind),
        @('TlsPassthroughBind', 'LINKLAKE_TLS_PASSTHROUGH_BIND', $TlsPassthroughBind),
        @('UdpRelayBind', 'LINKLAKE_UDP_RELAY_BIND', $UdpRelayBind),
        @('UdpRelayEndpoint', 'LINKLAKE_UDP_RELAY_ENDPOINT', $UdpRelayEndpoint),
        @('UdpRelayServerName', 'LINKLAKE_UDP_RELAY_SERVER_NAME', $UdpRelayServerName),
        @('UdpPublicBindMode', 'LINKLAKE_UDP_PUBLIC_BIND_MODE', $UdpPublicBindMode),
        @('ManagementCertificate', 'LINKLAKE_MANAGEMENT_CERT_PATH', $ManagementCertificate),
        @('ManagementKey', 'LINKLAKE_MANAGEMENT_KEY_PATH', $ManagementKey),
        @('ControlCertificate', 'LINKLAKE_CONTROL_CERT_PATH', $ControlCertificate),
        @('ControlKey', 'LINKLAKE_CONTROL_KEY_PATH', $ControlKey)
    )) {
    $parameterName, $environmentName, $value = $mapping
    if ($installerBoundParameters.ContainsKey($parameterName)) {
        if ($value) { $environment[$environmentName] = $value } else { $environment.Remove($environmentName) }
    }
}

foreach ($name in @(
        'LINKLAKE_HTTP_BIND', 'LINKLAKE_HTTPS_BIND', 'LINKLAKE_TLS_PASSTHROUGH_BIND',
        'LINKLAKE_UDP_RELAY_BIND', 'LINKLAKE_UDP_RELAY_ENDPOINT', 'LINKLAKE_UDP_RELAY_SERVER_NAME',
        'LINKLAKE_MANAGEMENT_CERT_PATH', 'LINKLAKE_MANAGEMENT_KEY_PATH',
        'LINKLAKE_CONTROL_CERT_PATH', 'LINKLAKE_CONTROL_KEY_PATH'
    )) {
    if ($environment.Contains($name) -and [string]::IsNullOrWhiteSpace([string]$environment[$name])) {
        $environment.Remove($name)
    }
}

$managementEndpoint = ConvertFrom-LinkLakeSocketAddress ([string]$environment['LINKLAKE_BIND']) 'Bind'
$controlEndpoint = ConvertFrom-LinkLakeSocketAddress ([string]$environment['LINKLAKE_CONTROL_BIND']) 'ControlBind'
$optionalEndpoints = @{}
foreach ($name in @('LINKLAKE_HTTP_BIND', 'LINKLAKE_HTTPS_BIND', 'LINKLAKE_TLS_PASSTHROUGH_BIND', 'LINKLAKE_UDP_RELAY_BIND')) {
    if ($environment.Contains($name)) {
        $optionalEndpoints[$name] = ConvertFrom-LinkLakeSocketAddress ([string]$environment[$name]) $name
    }
}
$tcpListeners = [Collections.Generic.List[object]]::new()
$tcpListeners.Add([pscustomobject]@{ Name = 'Bind'; Endpoint = $managementEndpoint })
$tcpListeners.Add([pscustomobject]@{ Name = 'ControlBind'; Endpoint = $controlEndpoint })
foreach ($name in @('LINKLAKE_HTTP_BIND', 'LINKLAKE_HTTPS_BIND', 'LINKLAKE_TLS_PASSTHROUGH_BIND')) {
    if ($optionalEndpoints.ContainsKey($name)) {
        $tcpListeners.Add([pscustomobject]@{ Name = $name; Endpoint = $optionalEndpoints[$name] })
    }
}
for ($left = 0; $left -lt $tcpListeners.Count; $left++) {
    for ($right = $left + 1; $right -lt $tcpListeners.Count; $right++) {
        $leftEndpoint = $tcpListeners[$left].Endpoint
        $rightEndpoint = $tcpListeners[$right].Endpoint
        if ($leftEndpoint.Port -eq $rightEndpoint.Port -and $leftEndpoint.Address.Equals($rightEndpoint.Address)) {
            throw "$($tcpListeners[$left].Name) and $($tcpListeners[$right].Name) must not bind the same TCP address."
        }
    }
}
if ($optionalEndpoints.ContainsKey('LINKLAKE_HTTPS_BIND') -and
    $optionalEndpoints.ContainsKey('LINKLAKE_TLS_PASSTHROUGH_BIND')) {
    $httpsEndpoint = $optionalEndpoints['LINKLAKE_HTTPS_BIND']
    $sniEndpoint = $optionalEndpoints['LINKLAKE_TLS_PASSTHROUGH_BIND']
    if ($httpsEndpoint.Port -eq $sniEndpoint.Port -and $httpsEndpoint.Address.Equals($sniEndpoint.Address)) {
        throw 'HttpsBind and TlsPassthroughBind must not be identical.'
    }
}

$udpConfigured = @(
    $environment.Contains('LINKLAKE_UDP_RELAY_BIND'),
    $environment.Contains('LINKLAKE_UDP_RELAY_ENDPOINT'),
    $environment.Contains('LINKLAKE_UDP_RELAY_SERVER_NAME')
)
if (@($udpConfigured | Where-Object { $_ }).Count -notin @(0, 3)) {
    throw 'UdpRelayBind, UdpRelayEndpoint, and UdpRelayServerName must be configured together.'
}
if ($udpConfigured[0]) {
    Assert-LinkLakeHostPort ([string]$environment['LINKLAKE_UDP_RELAY_ENDPOINT']) 'UdpRelayEndpoint'
    Assert-LinkLakeServerName ([string]$environment['LINKLAKE_UDP_RELAY_SERVER_NAME']) 'UdpRelayServerName'
}
if ($environment.Contains('LINKLAKE_UDP_PUBLIC_BIND_MODE') -and
    [string]$environment['LINKLAKE_UDP_PUBLIC_BIND_MODE'] -notin @('auto', 'ipv4_only', 'dual_stack_required')) {
    throw 'UdpPublicBindMode must be auto, ipv4_only, or dual_stack_required.'
}

$managementTls = $environment.Contains('LINKLAKE_MANAGEMENT_CERT_PATH') -and $environment.Contains('LINKLAKE_MANAGEMENT_KEY_PATH')
if ($environment.Contains('LINKLAKE_MANAGEMENT_CERT_PATH') -ne $environment.Contains('LINKLAKE_MANAGEMENT_KEY_PATH')) {
    throw 'ManagementCertificate and ManagementKey must be configured together.'
}
$controlTls = $environment.Contains('LINKLAKE_CONTROL_CERT_PATH') -and $environment.Contains('LINKLAKE_CONTROL_KEY_PATH')
if ($environment.Contains('LINKLAKE_CONTROL_CERT_PATH') -ne $environment.Contains('LINKLAKE_CONTROL_KEY_PATH')) {
    throw 'ControlCertificate and ControlKey must be configured together.'
}
if (-not [Net.IPAddress]::IsLoopback($managementEndpoint.Address) -and -not $managementTls) {
    throw 'Remote Bind requires ManagementCertificate and ManagementKey.'
}
if (-not [Net.IPAddress]::IsLoopback($controlEndpoint.Address) -and -not $controlTls) {
    throw 'Remote ControlBind requires ControlCertificate and ControlKey.'
}
if ($udpConfigured[0] -and -not $controlTls) {
    throw 'UDP relay requires ControlCertificate and ControlKey.'
}

$secretPlans = [Collections.Generic.List[object]]::new()
foreach ($specification in @(
        @('LINKLAKE_MANAGEMENT_CERT_PATH', 'management-cert.pem', 'certificate'),
        @('LINKLAKE_MANAGEMENT_KEY_PATH', 'management-key.pem', 'private-key'),
        @('LINKLAKE_CONTROL_CERT_PATH', 'control-cert.pem', 'certificate'),
        @('LINKLAKE_CONTROL_KEY_PATH', 'control-key.pem', 'private-key')
    )) {
    $environmentName, $destinationName, $kind = $specification
    if (-not $environment.Contains($environmentName)) { continue }
    $source = Resolve-LinkLakeSafePath ([string]$environment[$environmentName]) $environmentName -RequireLocalDrive
    Assert-LinkLakePemFile $source $kind $environmentName
    $destination = Resolve-LinkLakeSafePath (Join-Path $SecretsDirectory $destinationName) "$environmentName destination" -RequireLocalDrive
    $samePath = $source.Equals($destination, [StringComparison]::OrdinalIgnoreCase)
    $originalAclSddl = $null
    if ($samePath -and (Test-Path -LiteralPath $destination -PathType Leaf)) {
        $originalAclSddl = (Get-Acl -LiteralPath $destination).Sddl
    }
    $secretPlans.Add([pscustomobject]@{
            Source = $source
            Destination = $destination
            Kind = $kind
            SamePath = $samePath
            Temporary = Join-Path $SecretsDirectory ".secret.new-$([guid]::NewGuid().ToString('N'))"
            Backup = Join-Path $SecretsDirectory ".secret.backup-$([guid]::NewGuid().ToString('N'))"
            BackedUp = $false
            Replaced = $false
            OriginalAclSddl = $originalAclSddl
            SourceSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLowerInvariant()
        })
    $environment[$environmentName] = $destination
}

    if ($EnrollmentToken) {
        $enrollmentPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($EnrollmentToken)
        $plainEnrollmentToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($enrollmentPointer)
        Assert-LinkLakeSafeValue $plainEnrollmentToken 'EnrollmentToken' 4096
        if ([string]::IsNullOrWhiteSpace($plainEnrollmentToken)) { throw 'EnrollmentToken must not be blank.' }
        $environment['LINKLAKE_ENROLLMENT_TOKEN'] = $plainEnrollmentToken
    }
    elseif (-not $environment.Contains('LINKLAKE_ENROLLMENT_TOKEN')) {
        throw 'EnrollmentToken is required for a new installation.'
    }
    else {
        Assert-LinkLakeSafeValue ([string]$environment['LINKLAKE_ENROLLMENT_TOKEN']) 'EnrollmentToken' 4096
        if ([string]::IsNullOrWhiteSpace([string]$environment['LINKLAKE_ENROLLMENT_TOKEN'])) {
            throw 'EnrollmentToken must not be blank.'
        }
    }

    $databasePath = Join-Path $DataDirectory 'linklake.sqlite3'
    $needsBootstrap = -not (Test-Path -LiteralPath $databasePath -PathType Leaf)
    $requiresDatabaseSnapshot = $snapshot.Exists -and -not $needsBootstrap
    if ($requiresDatabaseSnapshot) {
        if ($NoStart) {
            throw 'An existing server database upgrade must start the candidate service so its migration can be verified and rolled back safely.'
        }
        if (-not (Test-Path -LiteralPath $destinationBinary -PathType Leaf)) {
            throw 'An existing LinkLakeServer service has no installed server binary for a database-safe upgrade.'
        }
    }
    if ($needsBootstrap) {
        if ($NoStart) { throw 'A fresh server installation must start once so bootstrap credentials can be removed.' }
        if (-not $AdminPassword) { throw 'AdminPassword is required until the administrator database exists.' }
        $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword)
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
        Assert-LinkLakeSafeValue $plainPassword 'AdminPassword' 1024
        if ($AdminUsername -notmatch '^[A-Za-z0-9_-]{3,64}$') {
            throw 'AdminUsername must contain 3-64 ASCII letters, digits, underscores, or hyphens.'
        }
        if ([Text.Encoding]::UTF8.GetByteCount($plainPassword) -lt 12) {
            throw 'AdminPassword must contain at least 12 UTF-8 bytes.'
        }
        $environment['LINKLAKE_ADMIN_USERNAME'] = $AdminUsername
        $environment['LINKLAKE_ADMIN_PASSWORD'] = $plainPassword
    }
    else {
        if ($AdminPassword) { throw 'AdminPassword is only used for first-run bootstrap; change an existing password in the Web UI.' }
        $environment.Remove('LINKLAKE_ADMIN_USERNAME')
        $environment.Remove('LINKLAKE_ADMIN_PASSWORD')
    }

    $databaseSnapshotPath = $null
    $databaseRestoreVerificationPath = $null
    if ($requiresDatabaseSnapshot) {
        $databaseSnapshotPath = Resolve-LinkLakeSafePath (
            (Join-Path $databaseSnapshotDirectory ".server-before-upgrade-$([guid]::NewGuid().ToString('N')).sqlite3")
        ) 'server database snapshot path' -RequireLocalDrive
        $databaseRestoreVerificationPath = Resolve-LinkLakeSafePath (
            (Join-Path $databaseSnapshotDirectory ".server-restored-$([guid]::NewGuid().ToString('N')).sqlite3")
        ) 'server database restore verification path' -RequireLocalDrive
        if ((Test-LinkLakePathAtOrBelow $databaseSnapshotPath $DataDirectory) -or
            (Test-LinkLakePathAtOrBelow $databaseRestoreVerificationPath $DataDirectory)) {
            throw 'Server database snapshots must remain outside the live data directory.'
        }
    }
    $script:databaseSnapshotCreated = $false
    $script:databaseSnapshotSha256 = $null
    $script:databaseRestoreVerificationSha256 = $null
    $databaseHandoffOperationId = [guid]::NewGuid().ToString('N')
    $script:databaseHandoffRecordPath = $null
    $script:databaseCandidateStarted = $false
    $script:databaseRestoreVerified = $false
    $script:rollbackServerBinarySha256 = $null
    $script:serviceRecoveryAllowed = $true

    $directoryPlans = @(
        New-LinkLakeDirectoryTransactionPlan $InstallDirectory
        New-LinkLakeDirectoryTransactionPlan $DataDirectory -WritableByService
        New-LinkLakeDirectoryTransactionPlan $LogDirectory -WritableByService
        New-LinkLakeDirectoryTransactionPlan $SecretsDirectory
    )
    if ($requiresDatabaseSnapshot) {
        $directoryPlans += New-LinkLakeDirectoryTransactionPlan $databaseSnapshotDirectory
    }
    $directoryPlansWithoutSnapshot = @($directoryPlans | Where-Object {
            $_.Path -ine $databaseSnapshotDirectory
        })
    $temporaryBinary = Join-Path $InstallDirectory ".linklake-server.new-$([guid]::NewGuid().ToString('N')).exe"
    $backupBinary = Join-Path $InstallDirectory ".linklake-server.backup-$([guid]::NewGuid().ToString('N')).exe"
    $script:binaryBackedUp = $false
    $script:binaryReplaced = $false
    $binaryPath = "`"$destinationBinary`" --windows-service"
    $shouldStart = (-not $NoStart) -and (
        (-not $snapshot.Exists) -or $snapshot.WasActive -or $needsBootstrap -or $requiresDatabaseSnapshot
    )

    $stop = { Stop-LinkLakeServiceChecked $serviceName }
    $apply = {
        Install-LinkLakeDirectoryPlans $directoryPlans
        if ($requiresDatabaseSnapshot) {
            Set-LinkLakeServerInstallerSnapshotAcl $databaseSnapshotDirectory -Directory
            $rollbackIdentity = Read-LinkLakeBinaryIdentity $destinationBinary
            if ($rollbackIdentity.product -ne 'LinkLake Server' -or $rollbackIdentity.target -ne $release.target) {
                throw 'The installed server binary is not a compatible LinkLake Server rollback binary.'
            }
            $script:rollbackServerBinarySha256 = Get-LinkLakeServerInstallerSha256 $destinationBinary 'installed server binary'
            if (Test-Path -LiteralPath $databaseSnapshotPath) {
                throw 'The transaction database snapshot path already exists.'
            }
            Invoke-LinkLakeServerMaintenanceChecked -BinaryPath $destinationBinary `
                -CommandArguments @('backup', '--data-dir', $DataDirectory, '--output', $databaseSnapshotPath) `
                -Operation 'installed server database snapshot'
            $resolvedSnapshotPath = Resolve-LinkLakeSafePath $databaseSnapshotPath 'server database snapshot path' -RequireLocalDrive
            if (-not $resolvedSnapshotPath.Equals($databaseSnapshotPath, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'The transaction database snapshot path changed while it was created.'
            }
            Set-LinkLakeServerInstallerSnapshotAcl $databaseSnapshotPath
            $script:databaseSnapshotSha256 = Get-LinkLakeServerInstallerSha256 $databaseSnapshotPath 'server database snapshot'
            Assert-LinkLakeServerInstallerSha256 $destinationBinary $script:rollbackServerBinarySha256 'installed server binary'
            $script:databaseSnapshotCreated = $true
            $script:databaseHandoffRecordPath = New-LinkLakeServerCandidateHandoffRecord `
                -Directory $databaseSnapshotDirectory -OperationId $databaseHandoffOperationId `
                -ServiceName $serviceName -DataDirectory $DataDirectory -InstallDirectory $InstallDirectory `
                -SnapshotPath $databaseSnapshotPath -SnapshotSha256 $script:databaseSnapshotSha256 `
                -RollbackBinaryPaths @($destinationBinary, $backupBinary) `
                -RollbackBinarySha256 $script:rollbackServerBinarySha256
        }
        Copy-Item -LiteralPath $sourceBinary -Destination $temporaryBinary -Force
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $temporaryBinary).Hash.ToLowerInvariant() -ne $sourceBinarySha256) {
            throw 'Staged server binary changed after package verification.'
        }
        $null = Assert-LinkLakePackageBinary $temporaryBinary 'LinkLake Server' $release
        if (Test-Path -LiteralPath $destinationBinary) {
            Move-Item -LiteralPath $destinationBinary -Destination $backupBinary
            $script:binaryBackedUp = $true
        }
        Move-Item -LiteralPath $temporaryBinary -Destination $destinationBinary
        $script:binaryReplaced = $true
        Set-LinkLakeSecretFileAcl $destinationBinary -Executable
        foreach ($plan in $secretPlans) {
            if ($plan.SamePath) {
                if ((Get-FileHash -Algorithm SHA256 -LiteralPath $plan.Destination).Hash.ToLowerInvariant() -ne $plan.SourceSha256) {
                    throw 'Managed TLS secret changed after input validation.'
                }
                Assert-LinkLakePemFile $plan.Destination $plan.Kind 'managed TLS secret'
                Set-LinkLakeSecretFileAcl $plan.Destination
                continue
            }
            Copy-Item -LiteralPath $plan.Source -Destination $plan.Temporary -Force
            if ((Get-FileHash -Algorithm SHA256 -LiteralPath $plan.Temporary).Hash.ToLowerInvariant() -ne $plan.SourceSha256) {
                throw 'Staged TLS secret changed after input validation.'
            }
            Assert-LinkLakePemFile $plan.Temporary $plan.Kind 'staged TLS secret'
            if (Test-Path -LiteralPath $plan.Destination -PathType Leaf) {
                Move-Item -LiteralPath $plan.Destination -Destination $plan.Backup
                $plan.BackedUp = $true
            }
            Move-Item -LiteralPath $plan.Temporary -Destination $plan.Destination
            $plan.Replaced = $true
            Set-LinkLakeSecretFileAcl $plan.Destination
        }
        if (-not $snapshot.Exists) {
            New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName 'LinkLake Server' `
                -Description 'LinkLake secure tunnel server' -StartupType Automatic | Out-Null
        }
        Invoke-LinkLakeSc @('config', $serviceName, 'binPath=', $binaryPath, 'start=', 'auto', 'obj=', 'NT AUTHORITY\LocalService', 'password=', '')
        Invoke-LinkLakeSc @('sidtype', $serviceName, 'none')
        Invoke-LinkLakeSc @('privs', $serviceName, 'SeChangeNotifyPrivilege')
        Set-LinkLakeServiceEnvironment $serviceName (ConvertTo-LinkLakeEnvironment $environment)
        Invoke-LinkLakeSc @('failure', $serviceName, 'reset=', '86400', 'actions=', 'restart/3000/restart/10000/restart/30000')
    }
    $validate = {
        $null = Assert-LinkLakePackageBinary $destinationBinary 'LinkLake Server' $release
        if ($requiresDatabaseSnapshot) {
            if (-not $script:databaseSnapshotCreated -or [string]::IsNullOrWhiteSpace($script:databaseSnapshotSha256)) {
                throw 'The server database snapshot was not completed before binary replacement.'
            }
            Assert-LinkLakeServerInstallerSha256 $databaseSnapshotPath $script:databaseSnapshotSha256 'server database snapshot'
        }
        foreach ($plan in $secretPlans) {
            Assert-LinkLakePemFile $plan.Destination $plan.Kind 'installed TLS secret'
        }
    }
    $start = {
        if ($requiresDatabaseSnapshot) {
            Assert-LinkLakeServerInstallerSha256 $databaseSnapshotPath $script:databaseSnapshotSha256 'server database snapshot'
            if ([string]::IsNullOrWhiteSpace($script:databaseHandoffRecordPath)) {
                throw 'The candidate handoff record was not completed before service start.'
            }
            # 先持久化“即将交接”标记，再允许候选进程启动；从这里起即使启动检查
            # 失败，也必须按可能已接受写入处理，不能自动覆盖旧数据库快照。
            $record = Read-LinkLakeServerCandidateHandoffRecord `
                -HandoffDirectory $databaseSnapshotDirectory -ExpectedDataDirectory $DataDirectory `
                -ExpectedInstallDirectory $InstallDirectory -ExpectedServiceName $serviceName
            New-LinkLakeServerCandidateHandoffStage $record.HandoffDirectory 'candidate-starting' $record | Out-Null
            $script:databaseCandidateStarted = $true
        }
        Start-LinkLakeServiceChecked $serviceName
        if ($needsBootstrap) {
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $databasePath -PathType Leaf)) {
                Start-Sleep -Milliseconds 250
            }
            if (-not (Test-Path -LiteralPath $databasePath -PathType Leaf)) {
                throw 'LinkLake Server did not create its administrator database.'
            }
            $environment.Remove('LINKLAKE_ADMIN_USERNAME')
            $environment.Remove('LINKLAKE_ADMIN_PASSWORD')
            Set-LinkLakeServiceEnvironment $serviceName (ConvertTo-LinkLakeEnvironment $environment)
            # 首次初始化后重启一次，确保运行中进程也不再持有明文引导密码。
            Stop-LinkLakeServiceChecked $serviceName
            Start-LinkLakeServiceChecked $serviceName
        }
        if ($snapshot.State -eq 'Paused') {
            Suspend-Service -Name $serviceName -ErrorAction Stop
            Wait-LinkLakeServiceStatus $serviceName ([ServiceProcess.ServiceControllerStatus]::Paused)
        }
        elseif ($snapshot.Exists -and -not $snapshot.WasActive -and ($needsBootstrap -or $requiresDatabaseSnapshot)) {
            Stop-LinkLakeServiceChecked $serviceName
        }
    }
    $rollback = {
        # 只有这一段完全成功后，事务框架才可恢复原服务运行状态。任一失败均保留
        # 停止状态和受 ACL 保护的恢复证据，避免新旧 schema 与二进制混合运行。
        if ($script:databaseCandidateStarted) {
            throw 'Candidate service handoff has started; database rollback must use the explicit handoff recovery path.'
        }
        $script:serviceRecoveryAllowed = $false
        Stop-LinkLakeServiceChecked $serviceName 10

        if ($script:databaseSnapshotCreated) {
            if ([string]::IsNullOrWhiteSpace($script:databaseSnapshotSha256) -or
                [string]::IsNullOrWhiteSpace($script:rollbackServerBinarySha256)) {
                throw 'Cannot roll back the server database because its verified snapshot or rollback binary is unavailable.'
            }
            $rollbackMaintenanceBinary = if ($script:binaryBackedUp) { $backupBinary } else { $destinationBinary }
            Assert-LinkLakeServerInstallerSha256 $rollbackMaintenanceBinary $script:rollbackServerBinarySha256 'rollback server binary'
            Assert-LinkLakeServerInstallerSha256 $databaseSnapshotPath $script:databaseSnapshotSha256 'server database snapshot'
            Invoke-LinkLakeServerMaintenanceChecked -BinaryPath $rollbackMaintenanceBinary `
                -CommandArguments @('restore', '--data-dir', $DataDirectory, '--input', $databaseSnapshotPath) `
                -Operation 'server database restore'
            Assert-LinkLakeServerInstallerSha256 $rollbackMaintenanceBinary $script:rollbackServerBinarySha256 'rollback server binary'
            Assert-LinkLakeServerInstallerSha256 $databaseSnapshotPath $script:databaseSnapshotSha256 'server database snapshot'
            if (Test-Path -LiteralPath $databaseRestoreVerificationPath) {
                throw 'The server database restore verification path already exists.'
            }
            Invoke-LinkLakeServerMaintenanceChecked -BinaryPath $rollbackMaintenanceBinary `
                -CommandArguments @('backup', '--data-dir', $DataDirectory, '--output', $databaseRestoreVerificationPath) `
                -Operation 'restored server database verification backup'
            $resolvedVerificationPath = Resolve-LinkLakeSafePath $databaseRestoreVerificationPath 'server database restore verification path' -RequireLocalDrive
            if (-not $resolvedVerificationPath.Equals($databaseRestoreVerificationPath, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'The server database restore verification path changed while it was created.'
            }
            Set-LinkLakeServerInstallerSnapshotAcl $databaseRestoreVerificationPath
            $script:databaseRestoreVerificationSha256 = Get-LinkLakeServerInstallerSha256 $databaseRestoreVerificationPath 'restored server database verification backup'
            if ([string]::IsNullOrWhiteSpace($script:databaseRestoreVerificationSha256)) {
                throw 'The restored server database verification backup has no SHA-256 digest.'
            }
            $script:databaseRestoreVerified = $true
        }
        elseif ($requiresDatabaseSnapshot -and
            ($script:databaseCandidateStarted -or $script:binaryBackedUp -or $script:binaryReplaced)) {
            throw 'Cannot roll back the server binary because its required verified database snapshot is unavailable.'
        }
        if ($script:databaseSnapshotCreated -and -not $script:databaseRestoreVerified) {
            throw 'Cannot roll back the server binary before database snapshot restoration was verified.'
        }

        if ($script:binaryReplaced -and (Test-Path -LiteralPath $destinationBinary)) {
            Remove-Item -LiteralPath $destinationBinary -Force
        }
        if ($script:binaryBackedUp -and (Test-Path -LiteralPath $backupBinary)) {
            Move-Item -LiteralPath $backupBinary -Destination $destinationBinary
            if ($requiresDatabaseSnapshot) {
                Assert-LinkLakeServerInstallerSha256 $destinationBinary $script:rollbackServerBinarySha256 'restored server binary'
            }
        }
        for ($index = $secretPlans.Count - 1; $index -ge 0; $index--) {
            $plan = $secretPlans[$index]
            if ($plan.Replaced -and (Test-Path -LiteralPath $plan.Destination)) {
                Remove-Item -LiteralPath $plan.Destination -Force
            }
            if ($plan.BackedUp -and (Test-Path -LiteralPath $plan.Backup)) {
                Move-Item -LiteralPath $plan.Backup -Destination $plan.Destination
            }
            elseif ($plan.SamePath -and $plan.OriginalAclSddl -and (Test-Path -LiteralPath $plan.Destination)) {
                $acl = Get-Acl -LiteralPath $plan.Destination
                $acl.SetSecurityDescriptorSddlForm($plan.OriginalAclSddl)
                Set-Acl -LiteralPath $plan.Destination -AclObject $acl
            }
            if (Test-Path -LiteralPath $plan.Temporary) { Remove-Item -LiteralPath $plan.Temporary -Force }
        }
        Restore-LinkLakeServiceSnapshot $serviceName $snapshot
        if (Test-Path -LiteralPath $temporaryBinary) { Remove-Item -LiteralPath $temporaryBinary -Force }
        if ($requiresDatabaseSnapshot) {
            Remove-LinkLakeArtifactBestEffort $databaseSnapshotDirectory
        }
        Restore-LinkLakeDirectoryPlans $directoryPlans
        $script:serviceRecoveryAllowed = $true
    }
    $handoff = {
        # `candidate-starting` 已在调用 Start-Service 前持久化。此后任何失败都可能
        # 发生在候选服务接受写入之后：停止候选、保留快照和记录，但绝不能恢复旧库。
        $script:serviceRecoveryAllowed = $false
        Stop-LinkLakeServiceChecked $serviceName 10
        if (-not $script:databaseSnapshotCreated -or
            [string]::IsNullOrWhiteSpace($script:databaseSnapshotSha256) -or
            [string]::IsNullOrWhiteSpace($script:rollbackServerBinarySha256) -or
            [string]::IsNullOrWhiteSpace($script:databaseHandoffRecordPath)) {
            throw 'Candidate handoff cannot be preserved because its verified database snapshot or record is unavailable.'
        }
        $record = Read-LinkLakeServerCandidateHandoffRecord `
            -HandoffDirectory $databaseSnapshotDirectory -ExpectedDataDirectory $DataDirectory `
            -ExpectedInstallDirectory $InstallDirectory -ExpectedServiceName $serviceName
        if ($record.RecordPath -ine $script:databaseHandoffRecordPath -or
            -not (Test-LinkLakeServerCandidateHandoffStage $record.HandoffDirectory 'candidate-starting' $record)) {
            throw 'Candidate handoff record was changed or was not marked before candidate service start.'
        }
        Assert-LinkLakeServerInstallerSha256 $record.SnapshotPath $record.SnapshotSha256 'candidate handoff database snapshot'
        $rollbackMaintenanceBinary = Select-LinkLakeServerCandidateHandoffRollbackBinary $record
        Assert-LinkLakeServerInstallerSha256 $rollbackMaintenanceBinary $record.RollbackBinarySha256 'candidate handoff rollback binary'

        # 将可执行文件、密钥和服务配置尽力还原到旧版本，但故意不启动服务；旧二进制
        # 在候选 schema 上运行并不安全，数据库快照只能通过显式双确认恢复。
        if (-not $script:binaryBackedUp -or -not (Test-Path -LiteralPath $backupBinary -PathType Leaf)) {
            throw 'Candidate handoff rollback binary is no longer available.'
        }
        if ($script:binaryReplaced -and (Test-Path -LiteralPath $destinationBinary)) {
            Remove-Item -LiteralPath $destinationBinary -Force
        }
        Move-Item -LiteralPath $backupBinary -Destination $destinationBinary
        Assert-LinkLakeServerInstallerSha256 $destinationBinary $record.RollbackBinarySha256 'restored server binary after candidate handoff'
        for ($index = $secretPlans.Count - 1; $index -ge 0; $index--) {
            $plan = $secretPlans[$index]
            if ($plan.Replaced -and (Test-Path -LiteralPath $plan.Destination)) {
                Remove-Item -LiteralPath $plan.Destination -Force
            }
            if ($plan.BackedUp -and (Test-Path -LiteralPath $plan.Backup)) {
                Move-Item -LiteralPath $plan.Backup -Destination $plan.Destination
            }
            elseif ($plan.SamePath -and $plan.OriginalAclSddl -and (Test-Path -LiteralPath $plan.Destination)) {
                $acl = Get-Acl -LiteralPath $plan.Destination
                $acl.SetSecurityDescriptorSddlForm($plan.OriginalAclSddl)
                Set-Acl -LiteralPath $plan.Destination -AclObject $acl
            }
            if (Test-Path -LiteralPath $plan.Temporary) { Remove-Item -LiteralPath $plan.Temporary -Force }
        }
        Restore-LinkLakeServiceSnapshot $serviceName $snapshot
        if (Test-Path -LiteralPath $temporaryBinary) { Remove-Item -LiteralPath $temporaryBinary -Force }
        Restore-LinkLakeDirectoryPlans $directoryPlansWithoutSnapshot
    }
    $recover = {
        if (-not $script:serviceRecoveryAllowed) {
            throw 'Runtime service recovery was skipped because database or binary rollback did not complete.'
        }
        Restore-LinkLakeServiceRuntimeState $serviceName $snapshot
    }

    Invoke-LinkLakeTransactionalChange -Stop $stop -Apply $apply -Validate $validate -Start $start `
        -Rollback $rollback -Recover $recover -CandidateHandoffStarted { $script:databaseCandidateStarted } `
        -Handoff $handoff -WasRunning $snapshot.WasActive -ShouldStart $shouldStart

    Remove-LinkLakeArtifactBestEffort $backupBinary
    Remove-LinkLakeArtifactBestEffort $temporaryBinary
    if ($requiresDatabaseSnapshot) {
        Remove-LinkLakeArtifactBestEffort $databaseSnapshotDirectory
    }
    foreach ($plan in $secretPlans) {
        Remove-LinkLakeArtifactBestEffort $plan.Backup
        Remove-LinkLakeArtifactBestEffort $plan.Temporary
    }
    Write-Host "LinkLake Server $($release.version) installed. Service account: NT AUTHORITY\LocalService. Data preserved at $DataDirectory"
}
finally {
    if ($enrollmentPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($enrollmentPointer) }
    if ($passwordPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer) }
    $plainEnrollmentToken = $null
    $plainPassword = $null
    Exit-LinkLakeInstallerLock $installerLock
}
