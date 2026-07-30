param(
    [string]$InstallDirectory = "$env:ProgramFiles\LinkLake",
    [string]$DataDirectory = "$env:ProgramData\LinkLake\data",
    [string]$LogDirectory = "$env:ProgramData\LinkLake\logs",
    [string]$Bind = "127.0.0.1:32100",
    [string]$ControlBind = "127.0.0.1:32101",
    [string]$HttpBind,
    [string]$HttpsBind,
    [Parameter(Mandatory)][string]$EnrollmentToken,
    [string]$AdminUsername = "admin",
    [Parameter(Mandatory)][SecureString]$AdminPassword,
    [string]$ManagementCertificate,
    [string]$ManagementKey,
    [string]$ControlCertificate,
    [string]$ControlKey
)

$ErrorActionPreference = 'Stop'
$serviceName = 'LinkLakeServer'
$packageRoot = Split-Path -Parent $PSScriptRoot
$sourceBinary = Join-Path $packageRoot 'bin\linklake-server.exe'
$destinationBinary = Join-Path $InstallDirectory 'linklake-server.exe'

if (-not (Test-Path -LiteralPath $sourceBinary)) {
    throw "Server binary was not found: $sourceBinary"
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell window.'
}

New-Item -ItemType Directory -Force -Path $InstallDirectory, $DataDirectory, $LogDirectory | Out-Null
$dataAcl = Get-Acl -LiteralPath $DataDirectory
$dataAcl.SetAccessRuleProtection($true, $false)
$dataAcl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    'SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
))
$dataAcl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
))
Set-Acl -LiteralPath $DataDirectory -AclObject $dataAcl
Copy-Item -LiteralPath $sourceBinary -Destination $destinationBinary -Force

$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword)
try {
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    $serviceEnvironment = @(
        "LINKLAKE_BIND=$Bind",
        "LINKLAKE_CONTROL_BIND=$ControlBind",
        "LINKLAKE_DATA_DIR=$DataDirectory",
        "LINKLAKE_LOG_DIR=$LogDirectory",
        "LINKLAKE_ENROLLMENT_TOKEN=$EnrollmentToken",
        "LINKLAKE_ADMIN_USERNAME=$AdminUsername",
        "LINKLAKE_ADMIN_PASSWORD=$plainPassword"
    )
    if ($HttpBind) { $serviceEnvironment += "LINKLAKE_HTTP_BIND=$HttpBind" }
    if ($HttpsBind) { $serviceEnvironment += "LINKLAKE_HTTPS_BIND=$HttpsBind" }
    if ($ManagementCertificate) { $serviceEnvironment += "LINKLAKE_MANAGEMENT_CERT_PATH=$ManagementCertificate" }
    if ($ManagementKey) { $serviceEnvironment += "LINKLAKE_MANAGEMENT_KEY_PATH=$ManagementKey" }
    if ($ControlCertificate) { $serviceEnvironment += "LINKLAKE_CONTROL_CERT_PATH=$ControlCertificate" }
    if ($ControlKey) { $serviceEnvironment += "LINKLAKE_CONTROL_KEY_PATH=$ControlKey" }

    $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existing) {
        if ($existing.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
        & sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 1
    }
    $binaryPath = "`"$destinationBinary`" --windows-service"
    New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName 'LinkLake Server' `
        -Description 'LinkLake TCP, HTTP, and HTTPS tunnel server' -StartupType Automatic | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" `
        -Name Environment -PropertyType MultiString -Value $serviceEnvironment -Force | Out-Null
    & sc.exe failure $serviceName reset= 86400 actions= restart/3000/restart/10000/restart/30000 | Out-Null
    Start-Service -Name $serviceName
    Start-Sleep -Seconds 2
    $running = Get-Service -Name $serviceName
    if ($running.Status -ne 'Running' -or -not (Test-Path -LiteralPath (Join-Path $DataDirectory 'linklake.sqlite3'))) {
        throw "LinkLake Server did not initialize successfully. Check $LogDirectory."
    }
    # 首次启动后移除明文管理员引导凭据，后续登录使用 SQLite 中的密码哈希。
    $persistentEnvironment = $serviceEnvironment | Where-Object { ($_ -notlike 'LINKLAKE_ADMIN_USERNAME=*') -and ($_ -notlike 'LINKLAKE_ADMIN_PASSWORD=*') }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" `
        -Name Environment -PropertyType MultiString -Value $persistentEnvironment -Force | Out-Null
    Write-Host "LinkLake Server installed and started. Data: $DataDirectory"
} finally {
    if ($passwordPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
    $plainPassword = $null
}
