param(
    [ValidateSet('server', 'client', 'all')][string]$Mode = 'all'
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this uninstaller from an elevated PowerShell window.'
}

$services = switch ($Mode) {
    'server' { @('LinkLakeServer') }
    'client' { @('LinkLakeClient') }
    default { @('LinkLakeServer', 'LinkLakeClient') }
}
foreach ($serviceName in $services) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
        & sc.exe delete $serviceName | Out-Null
        Write-Host "Removed Windows service: $serviceName"
    }
}
Write-Host 'Program files and data were preserved intentionally.'
