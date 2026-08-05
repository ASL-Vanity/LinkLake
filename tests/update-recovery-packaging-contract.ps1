$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot

function Read-ProjectFile([string]$RelativePath) {
    $path = Join-Path $projectRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required update-recovery package file is missing: $RelativePath"
    }
    return Get-Content -LiteralPath $path -Raw -Encoding utf8
}

function Assert-Contains([string]$Text, [string]$Expected, [string]$Context) {
    if (-not $Text.Contains($Expected)) {
        throw "$Context is missing: $Expected"
    }
}

$serverUnit = Read-ProjectFile 'packaging\systemd\linklake-server.service'
$resumeUnit = Read-ProjectFile 'packaging\systemd\linklake-update-resume.service'
Assert-Contains $serverUnit 'Requires=linklake-update-resume.service' 'systemd server dependency'
Assert-Contains $serverUnit 'After=network-online.target linklake-update-resume.service' 'systemd ordering'
Assert-Contains $resumeUnit 'Before=linklake-server.service' 'systemd recovery ordering'
Assert-Contains $resumeUnit 'ConditionPathExists=/var/lib/linklake-updater/server/active.json' 'systemd recovery condition'
Assert-Contains $resumeUnit 'update recover --yes --state-dir /var/lib/linklake-updater/server --data-dir /var/lib/linklake' 'systemd recovery command'
Assert-Contains $resumeUnit 'User=root' 'systemd recovery privilege boundary'
Assert-Contains $resumeUnit 'ProtectSystem=strict' 'systemd recovery hardening'

$linuxInstaller = Read-ProjectFile 'packaging\systemd\install-linux.sh'
Assert-Contains $linuxInstaller 'linklake-update-resume.service' 'Linux installer recovery unit'
Assert-Contains $linuxInstaller 'install -d -o root -g root -m 0700 /var/lib/linklake-updater /var/lib/linklake-updater/server' 'Linux updater state permissions'
foreach ($script in @(
        'scripts\package-linux.sh',
        'scripts\verify-linux-package.sh',
        'scripts\package-native-linux.sh',
        'scripts\verify-native-linux-packages.sh'
    )) {
    Assert-Contains (Read-ProjectFile $script) 'linklake-update-resume.service' "$script recovery asset"
}

$launchdText = Read-ProjectFile 'packaging\launchd\com.linklake.update-resume.plist'
try { $launchd = [xml]$launchdText } catch { throw 'launchd update recovery plist is not valid XML.' }
Assert-Contains $launchdText '<string>com.linklake.update-resume</string>' 'launchd recovery label'
Assert-Contains $launchdText '<string>recover</string>' 'launchd recovery command'
Assert-Contains $launchdText '<string>/Library/Application Support/LinkLake/updates/server</string>' 'launchd machine state path'
Assert-Contains $launchdText '<key>SuccessfulExit</key><false/>' 'launchd failed recovery retry'
$macInstaller = Read-ProjectFile 'packaging\launchd\install-macos.sh'
Assert-Contains $macInstaller 'com.linklake.update-resume.plist' 'macOS installer recovery job'
Assert-Contains $macInstaller '-o root -g wheel -m 0700' 'macOS updater state permissions'
Assert-Contains (Read-ProjectFile 'scripts\package-macos.sh') 'com.linklake.update-resume.plist' 'macOS package recovery asset'
Assert-Contains (Read-ProjectFile 'scripts\verify-macos-package.sh') 'com.linklake.update-resume.plist' 'macOS package verification'

[ordered]@{
    ok = $true
    systemd = $true
    launchd = $true
    machine_state_permissions = $true
} | ConvertTo-Json
