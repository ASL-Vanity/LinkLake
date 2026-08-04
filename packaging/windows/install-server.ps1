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
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$installerBoundParameters = @{} + $PSBoundParameters
. (Join-Path $PSScriptRoot 'installer-common.ps1')

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
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $DataDirectory 'data directory'
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $LogDirectory 'log directory'
Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $SecretsDirectory 'secrets directory'
Assert-LinkLakePathsDoNotOverlap $DataDirectory 'data directory' $LogDirectory 'log directory'
Assert-LinkLakePathsDoNotOverlap $DataDirectory 'data directory' $SecretsDirectory 'secrets directory'
Assert-LinkLakePathsDoNotOverlap $LogDirectory 'log directory' $SecretsDirectory 'secrets directory'
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

    $directoryPlans = @(
        New-LinkLakeDirectoryTransactionPlan $InstallDirectory
        New-LinkLakeDirectoryTransactionPlan $DataDirectory -WritableByService
        New-LinkLakeDirectoryTransactionPlan $LogDirectory -WritableByService
        New-LinkLakeDirectoryTransactionPlan $SecretsDirectory
    )
    $temporaryBinary = Join-Path $InstallDirectory ".linklake-server.new-$([guid]::NewGuid().ToString('N')).exe"
    $backupBinary = Join-Path $InstallDirectory ".linklake-server.backup-$([guid]::NewGuid().ToString('N')).exe"
    $binaryBackedUp = $false
    $binaryReplaced = $false
    $binaryPath = "`"$destinationBinary`" --windows-service"
    $shouldStart = (-not $NoStart) -and ((-not $snapshot.Exists) -or $snapshot.WasActive -or $needsBootstrap)

    $stop = { Stop-LinkLakeServiceChecked $serviceName }
    $apply = {
        Install-LinkLakeDirectoryPlans $directoryPlans
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
        foreach ($plan in $secretPlans) {
            Assert-LinkLakePemFile $plan.Destination $plan.Kind 'installed TLS secret'
        }
    }
    $start = {
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
        elseif ($needsBootstrap -and $snapshot.Exists -and -not $snapshot.WasActive) {
            Stop-LinkLakeServiceChecked $serviceName
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
        for ($index = $secretPlans.Count - 1; $index -ge 0; $index--) {
            $plan = $secretPlans[$index]
            try {
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
            catch { $rollbackErrors.Add("restore TLS secret $($plan.Destination): $($_.Exception.Message)") }
        }
        try { Restore-LinkLakeServiceSnapshot $serviceName $snapshot }
        catch { $rollbackErrors.Add("restore service configuration: $($_.Exception.Message)") }
        try {
            if (Test-Path -LiteralPath $temporaryBinary) { Remove-Item -LiteralPath $temporaryBinary -Force }
        }
        catch { $rollbackErrors.Add("remove staged binary: $($_.Exception.Message)") }
        try { Restore-LinkLakeDirectoryPlans $directoryPlans }
        catch { $rollbackErrors.Add("restore directory ACLs: $($_.Exception.Message)") }
        if ($rollbackErrors.Count -gt 0) { throw ($rollbackErrors -join '; ') }
    }
    $recover = { Restore-LinkLakeServiceRuntimeState $serviceName $snapshot }

    Invoke-LinkLakeTransactionalChange -Stop $stop -Apply $apply -Validate $validate -Start $start `
        -Rollback $rollback -Recover $recover -WasRunning $snapshot.WasActive -ShouldStart $shouldStart

    Remove-LinkLakeArtifactBestEffort $backupBinary
    Remove-LinkLakeArtifactBestEffort $temporaryBinary
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
