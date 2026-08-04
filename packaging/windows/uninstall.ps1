param(
    [ValidateSet('server', 'client', 'all')][string]$Mode = 'all',
    [string]$InstallDirectory = "$env:ProgramFiles\LinkLake",
    [string]$DataDirectory = "$env:ProgramData\LinkLake\data",
    [string]$LogDirectory = "$env:ProgramData\LinkLake\logs",
    [string]$SecretsDirectory = "$env:ProgramData\LinkLake\secrets",
    [string]$ConfigDirectory = "$env:ProgramData\LinkLake",
    [string]$StateDirectory = "$env:ProgramData\LinkLake\client-state",
    [string]$ClientLogDirectory = "$env:ProgramData\LinkLake\client-logs",
    [switch]$PurgeData,
    [string]$ConfirmPurge
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'installer-common.ps1')

Assert-LinkLakeAdministrator
$installerLock = $null
try {
    $installerLock = Enter-LinkLakeInstallerLock
    $InstallDirectory = Resolve-LinkLakeSafePath $InstallDirectory 'install directory' -RequireLocalDrive
    $DataDirectory = Resolve-LinkLakeSafePath $DataDirectory 'data directory' -RequireLocalDrive
    $LogDirectory = Resolve-LinkLakeSafePath $LogDirectory 'log directory' -RequireLocalDrive
    $SecretsDirectory = Resolve-LinkLakeSafePath $SecretsDirectory 'secrets directory' -RequireLocalDrive
    $ConfigDirectory = Resolve-LinkLakeSafePath $ConfigDirectory 'config directory' -RequireLocalDrive
    $StateDirectory = Resolve-LinkLakeSafePath $StateDirectory 'state directory' -RequireLocalDrive
    $ClientLogDirectory = Resolve-LinkLakeSafePath $ClientLogDirectory 'client log directory' -RequireLocalDrive
    if ($PurgeData -and $ConfirmPurge -ne 'LINKLAKE-PURGE') {
        throw 'PurgeData requires -ConfirmPurge LINKLAKE-PURGE.'
    }

    $targetDefinitions = switch ($Mode) {
        'server' { @([pscustomobject]@{ Service = 'LinkLakeServer'; BinaryName = 'linklake-server.exe' }) }
        'client' { @([pscustomobject]@{ Service = 'LinkLakeClient'; BinaryName = 'linklake-client.exe' }) }
        default {
            @(
                [pscustomobject]@{ Service = 'LinkLakeServer'; BinaryName = 'linklake-server.exe' },
                [pscustomobject]@{ Service = 'LinkLakeClient'; BinaryName = 'linklake-client.exe' }
            )
        }
    }
    $targets = [Collections.Generic.List[object]]::new()
    foreach ($definition in $targetDefinitions) {
        $snapshot = Get-LinkLakeServiceSnapshot $definition.Service
        Assert-LinkLakeServiceSnapshotSupported $snapshot
        $binary = Resolve-LinkLakeSafePath (Join-Path $InstallDirectory $definition.BinaryName) "$($definition.Service) binary" -RequireLocalDrive
        Assert-LinkLakeServiceOwnsBinary $snapshot $binary $definition.Service
        $targets.Add([pscustomobject]@{
                Service = $definition.Service
                Binary = $binary
                Backup = Join-Path $InstallDirectory ".$($definition.BinaryName).uninstall-$([guid]::NewGuid().ToString('N'))"
                Snapshot = $snapshot
                Stopped = $false
                BinaryBackedUp = $false
                DeleteRequested = $false
                DeleteConfirmed = $false
            })
    }

    $purgePlans = [Collections.Generic.List[object]]::new()
    if ($PurgeData) {
        $purgePaths = [Collections.Generic.List[string]]::new()
        if ($Mode -in @('server', 'all')) {
            $purgePaths.Add($DataDirectory)
            $purgePaths.Add($LogDirectory)
            $purgePaths.Add($SecretsDirectory)
        }
        if ($Mode -in @('client', 'all')) {
            $purgePaths.Add($StateDirectory)
            $purgePaths.Add($ClientLogDirectory)
            $purgePaths.Add((Resolve-LinkLakeSafePath (Join-Path $ConfigDirectory 'client.toml') 'client config' -RequireLocalDrive))
        }
        $uniquePaths = [Collections.Generic.List[string]]::new()
        foreach ($path in $purgePaths) {
            if ($uniquePaths -notcontains $path) { $uniquePaths.Add($path) }
        }
        for ($left = 0; $left -lt $uniquePaths.Count; $left++) {
            Assert-LinkLakePathsDoNotOverlap $InstallDirectory 'install directory' $uniquePaths[$left] 'purge path'
            for ($right = $left + 1; $right -lt $uniquePaths.Count; $right++) {
                Assert-LinkLakePathsDoNotOverlap $uniquePaths[$left] 'purge path' $uniquePaths[$right] 'purge path'
            }
        }
        foreach ($path in $uniquePaths) {
            $parent = Split-Path -Parent $path
            $purgePlans.Add([pscustomobject]@{
                    Original = $path
                    Staged = Join-Path $parent ".linklake-purge-$([guid]::NewGuid().ToString('N'))"
                    Moved = $false
                })
        }
    }

    $stop = {
        foreach ($target in $targets) {
            if ($target.Snapshot.WasActive) {
                Stop-LinkLakeServiceChecked $target.Service
                $target.Stopped = $true
            }
        }
    }
    $stage = {
        foreach ($target in $targets) {
            if (Test-Path -LiteralPath $target.Binary -PathType Leaf) {
                Move-Item -LiteralPath $target.Binary -Destination $target.Backup
                $target.BinaryBackedUp = $true
            }
        }
        foreach ($plan in $purgePlans) {
            if (Test-Path -LiteralPath $plan.Original) {
                Move-Item -LiteralPath $plan.Original -Destination $plan.Staged
                $plan.Moved = $true
            }
        }
    }
    $remove = {
        foreach ($target in $targets) {
            if (-not $target.Snapshot.Exists) { continue }
            Invoke-LinkLakeSc @('delete', $target.Service)
            $target.DeleteRequested = $true
            Wait-LinkLakeServiceDeleted $target.Service
            $target.DeleteConfirmed = $true
        }
    }
    $rollback = {
        $recoveryErrors = [Collections.Generic.List[string]]::new()
        for ($index = $purgePlans.Count - 1; $index -ge 0; $index--) {
            $plan = $purgePlans[$index]
            if (-not $plan.Moved -or -not (Test-Path -LiteralPath $plan.Staged)) { continue }
            try { Move-Item -LiteralPath $plan.Staged -Destination $plan.Original }
            catch { $recoveryErrors.Add("data restore: $($_.Exception.Message)") }
        }
        for ($index = $targets.Count - 1; $index -ge 0; $index--) {
            $target = $targets[$index]
            if ($target.BinaryBackedUp -and (Test-Path -LiteralPath $target.Backup)) {
                try { Move-Item -LiteralPath $target.Backup -Destination $target.Binary }
                catch { $recoveryErrors.Add("binary restore for $($target.Service): $($_.Exception.Message)") }
            }
            if ($target.DeleteRequested) {
                try {
                    if (-not $target.DeleteConfirmed) { Wait-LinkLakeServiceDeleted $target.Service }
                    Restore-LinkLakeServiceSnapshot $target.Service $target.Snapshot
                }
                catch { $recoveryErrors.Add("service restore for $($target.Service): $($_.Exception.Message)") }
            }
        }
        if ($recoveryErrors.Count -gt 0) {
            throw ($recoveryErrors -join '; ')
        }
    }
    $recover = {
        $recoveryErrors = [Collections.Generic.List[string]]::new()
        foreach ($target in $targets) {
            if (-not $target.Stopped) { continue }
            try { Restore-LinkLakeServiceRuntimeState $target.Service $target.Snapshot }
            catch { $recoveryErrors.Add("$($target.Service): $($_.Exception.Message)") }
        }
        if ($recoveryErrors.Count -gt 0) { throw ($recoveryErrors -join '; ') }
    }
    $commit = {
        $residualPaths = [Collections.Generic.List[string]]::new()
        foreach ($target in $targets) {
            Remove-LinkLakeArtifactReportingResidual $target.Backup $residualPaths
            Write-Host "Removed $($target.Service); persistent configuration and data were preserved unless PurgeData was requested."
        }
        foreach ($plan in $purgePlans) {
            Remove-LinkLakeArtifactReportingResidual $plan.Staged $residualPaths
        }
        if ($residualPaths.Count -gt 0) {
            throw "Uninstall committed, but cleanup left residual paths: $($residualPaths -join '; ')"
        }
        if ($PurgeData) { Write-Host 'Requested LinkLake persistent data was permanently removed.' }
    }

    Invoke-LinkLakeTransactionalUninstall -Stop $stop -Stage $stage -Remove $remove -Commit $commit `
        -Rollback $rollback -Recover $recover

    if ((Test-Path -LiteralPath $InstallDirectory -PathType Container) -and
        -not (Get-ChildItem -Force -LiteralPath $InstallDirectory | Select-Object -First 1)) {
        $installResiduals = [Collections.Generic.List[string]]::new()
        Remove-LinkLakeArtifactReportingResidual $InstallDirectory $installResiduals
        if ($installResiduals.Count -gt 0) {
            throw "Uninstall committed, but cleanup left residual paths: $($installResiduals -join '; ')"
        }
    }
}
finally {
    Exit-LinkLakeInstallerLock $installerLock
}
