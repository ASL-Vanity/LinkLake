param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [string]$InstallDirectory = "$env:ProgramFiles\LinkLake",
    [string]$ConfigDirectory = "$env:ProgramData\LinkLake",
    [string]$LogDirectory = "$env:ProgramData\LinkLake\client-logs"
)

$ErrorActionPreference = 'Stop'
$serviceName = 'LinkLakeClient'
$packageRoot = Split-Path -Parent $PSScriptRoot
$sourceBinary = Join-Path $packageRoot 'bin\linklake-client.exe'
$destinationBinary = Join-Path $InstallDirectory 'linklake-client.exe'
$destinationConfig = Join-Path $ConfigDirectory 'client.toml'

if (-not (Test-Path -LiteralPath $sourceBinary)) { throw "Client binary was not found: $sourceBinary" }
if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Client config was not found: $ConfigPath" }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell window.'
}

New-Item -ItemType Directory -Force -Path $InstallDirectory, $ConfigDirectory, $LogDirectory | Out-Null
Copy-Item -LiteralPath $sourceBinary -Destination $destinationBinary -Force
Copy-Item -LiteralPath $ConfigPath -Destination $destinationConfig -Force
& icacls.exe $destinationConfig /inheritance:r /grant:r 'SYSTEM:(R)' 'Administrators:(R)' | Out-Null

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
}
$binaryPath = "`"$destinationBinary`" --windows-service `"$destinationConfig`""
New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName 'LinkLake Client' `
    -Description 'LinkLake TCP tunnel client' -StartupType Automatic | Out-Null
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" `
    -Name Environment -PropertyType MultiString -Value @("LINKLAKE_LOG_DIR=$LogDirectory") -Force | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/3000/restart/10000/restart/30000 | Out-Null
Start-Service -Name $serviceName
Write-Host "LinkLake Client installed and started. Config: $destinationConfig"
