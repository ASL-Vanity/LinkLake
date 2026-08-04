param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$windowsRoot = Join-Path $projectRoot 'packaging\windows'
. (Join-Path $windowsRoot 'installer-common.ps1')

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Pattern)
    try { & $Action }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "Expected error matching '$Pattern', received '$($_.Exception.Message)'."
        }
        return
    }
    throw "Expected an error matching '$Pattern'."
}

function Assert-Sequence {
    param([Collections.Generic.List[string]]$Actual, [string[]]$Expected, [string]$Name)
    $joinedActual = $Actual -join ','
    $joinedExpected = $Expected -join ','
    if ($joinedActual -ne $joinedExpected) {
        throw "$Name sequence mismatch: $joinedActual != $joinedExpected"
    }
}

function Assert-RegistrySnapshotEqual {
    param($Expected, $Actual, [string]$Name)
    Assert-True ($Expected.Exists -eq $Actual.Exists) "$Name existence was not restored exactly."
    if (-not $Expected.Exists) { return }
    Assert-True ($Expected.Kind -eq $Actual.Kind) "$Name registry kind was not restored exactly."
    $expectedValues = @($Expected.Value)
    $actualValues = @($Actual.Value)
    Assert-True (($expectedValues -join "`0") -ceq ($actualValues -join "`0")) "$Name value was not restored exactly."
}

function Write-TestChecksumManifest {
    param([string]$Root)
    $lines = Get-ChildItem -LiteralPath $Root -Recurse -File |
        Where-Object { $_.Name -ne 'checksums.sha256' } |
        Sort-Object FullName |
        ForEach-Object {
            $relative = $_.FullName.Substring($Root.Length).TrimStart([char]92, [char]47).Replace([char]92, [char]47)
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
            "$hash  $relative"
        }
    [IO.File]::WriteAllLines((Join-Path $Root 'checksums.sha256'), [string[]]$lines, [Text.Encoding]::ASCII)
}

function Write-TestZipArchive {
    param([string]$Path, [object[]]$Entries)
    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew)
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        foreach ($item in $Entries) {
            $entry = $archive.CreateEntry([string]$item.Name)
            if ([string]$item.Name -notmatch '/$') {
                $destination = $entry.Open()
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$item.Content)
                    $destination.Write($bytes, 0, $bytes.Length)
                }
                finally { $destination.Dispose() }
            }
        }
    }
    finally {
        $archive.Dispose()
        $stream.Dispose()
    }
}

$parseErrors = [Collections.Generic.List[string]]::new()
$windowsScripts = @(Get-ChildItem -LiteralPath $windowsRoot -Filter *.ps1)
$windowsScripts | ForEach-Object {
    $tokens = $null
    $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    foreach ($error in $errors) { $parseErrors.Add("$($_.Name):$($error.Extent.StartLineNumber): $($error.Message)") }
}
Assert-True ($parseErrors.Count -eq 0) "PowerShell parse errors: $($parseErrors -join '; ')"

foreach ($case in @(
        @('0.8.0-rc.1', '0.8.0', -1),
        @('0.8.0', '0.8.0-rc.9', 1),
        @('1.2.3-alpha.2', '1.2.3-alpha.10', -1),
        @('184467440737095516160.0.0', '184467440737095516159.999.999', 1),
        @('1.2.3', '1.2.3', 0),
        @('2.0.0', '1.99.99', 1)
    )) {
    $actual = Compare-LinkLakeSemVer $case[0] $case[1]
    Assert-True ($actual -eq $case[2]) "Semantic-version comparison failed for $($case[0]) and $($case[1])."
}
Assert-Throws { Compare-LinkLakeSemVer '1.0' '1.0.0' } 'invalid semantic version'
Assert-Throws { Compare-LinkLakeSemVer '1.0.0-alpha.01' '1.0.0' } 'invalid semantic version'

Initialize-LinkLakeServiceNative
Assert-True ([bool]('LinkLakeServiceNative' -as [type])) 'Native service snapshot helper did not compile.'
$commandArguments = [LinkLakeServiceNative]::SplitCommandLine(
    '"C:\Program Files\LinkLake\linklake-client.exe" --windows-service "C:\ProgramData\LinkLake\client.toml"'
)
Assert-True ($commandArguments.Count -eq 3 -and $commandArguments[1] -eq '--windows-service') 'Windows service command-line parsing failed.'
$eventLogFailureActions = [LinkLakeServiceNative]::Capture('EventLog')
Assert-True ($null -ne $eventLogFailureActions.ActionTypes) 'Native service failure-action snapshot failed.'
$eventLogPrivileges = [LinkLakeServiceNative]::CaptureRequiredPrivileges('EventLog')
Assert-True ($null -ne $eventLogPrivileges.Privileges) 'Native required-privilege snapshot failed.'
$eventLogSddl = Get-LinkLakeServiceSecurityDescriptor 'EventLog'
Assert-True ($eventLogSddl -match 'D:') 'Service security descriptor snapshot failed.'

$testRoot = Join-Path $env:TEMP "linklake-windows-installer-$([guid]::NewGuid().ToString('N'))"
$reparseTested = $false
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $safe = Resolve-LinkLakeSafePath (Join-Path $testRoot 'safe path') 'safe path'
    Assert-True ([IO.Path]::IsPathRooted($safe)) 'Safe path was not normalized to an absolute path.'
    Assert-Throws { Resolve-LinkLakeSafePath 'relative\path' 'relative path' } 'fully qualified absolute path'
    Assert-Throws { Resolve-LinkLakeSafePath ([IO.Path]::GetPathRoot($testRoot)) 'root path' } 'filesystem root'
    Assert-Throws { Resolve-LinkLakeSafePath (Join-Path $testRoot 'bad"path') 'quoted path' } 'unsafe'
    Assert-Throws { Resolve-LinkLakeSafePath "${testRoot}:stream" 'alternate stream' } 'alternate data stream'
    Assert-Throws { Resolve-LinkLakeSafePath (Join-Path $testRoot 'NUL.txt') 'reserved path' } 'reserved or ambiguous'
    Assert-Throws { Resolve-LinkLakeSafePath '\\server\share\path' 'remote path' -RequireLocalDrive } 'local drive'
    Assert-Throws { Assert-LinkLakeSafeValue "line`nbreak" 'value' } 'unsafe control'
    Assert-Throws {
        Assert-LinkLakePathsDoNotOverlap (Join-Path $testRoot 'program') 'program' (Join-Path $testRoot 'program\data') 'data'
    } 'must not overlap'

    $ipv4 = ConvertFrom-LinkLakeSocketAddress '127.0.0.1:32100' 'socket'
    $ipv6 = ConvertFrom-LinkLakeSocketAddress '[::1]:32100' 'socket'
    Assert-True ([Net.IPAddress]::IsLoopback($ipv4.Address)) 'IPv4 loopback parsing failed.'
    Assert-True ([Net.IPAddress]::IsLoopback($ipv6.Address)) 'IPv6 loopback parsing failed.'
    Assert-Throws { ConvertFrom-LinkLakeSocketAddress 'localhost:32100' 'socket' } 'numeric IPv4 or IPv6'
    Assert-Throws { ConvertFrom-LinkLakeSocketAddress '127.0.0.1:0' 'socket' } 'invalid port'
    Assert-Throws { Assert-LinkLakeHostPort 'bad host:443' 'endpoint' } 'host:port|invalid host'
    Assert-LinkLakeHostPort 'relay.example.com:32104' 'endpoint'
    Assert-LinkLakeServerName 'relay.example.com' 'server name'

    $parsedEnvironment = ConvertFrom-LinkLakeEnvironment @('LINKLAKE_A=1', 'LINKLAKE_B=two=parts')
    Assert-True ($parsedEnvironment['LINKLAKE_B'] -eq 'two=parts') 'Environment values containing equals were not preserved.'
    Assert-Throws { ConvertFrom-LinkLakeEnvironment @('malformed') } 'malformed'
    Assert-Throws { ConvertFrom-LinkLakeEnvironment @('LINKLAKE_A=1', 'LINKLAKE_A=2') } 'repeats variable'
    Assert-Throws { ConvertFrom-LinkLakeEnvironment @('lowercase=1') } 'invalid variable name'

    $realDirectory = Join-Path $testRoot 'real'
    $junction = Join-Path $testRoot 'junction'
    New-Item -ItemType Directory -Path $realDirectory | Out-Null
    try {
        New-Item -ItemType Junction -Path $junction -Target $realDirectory -ErrorAction Stop | Out-Null
        $reparseTested = $true
        Assert-Throws { Resolve-LinkLakeSafePath (Join-Path $junction 'payload') 'junction path' } 'reparse point'
    }
    catch {
        if ($reparseTested) { throw }
    }

    $registryPath = "HKCU:\Software\LinkLakeInstallerContract\$([guid]::NewGuid().ToString('N'))"
    New-Item -Path $registryPath -Force | Out-Null
    try {
        $missingValue = Get-LinkLakeRegistryValueSnapshot $registryPath 'Environment'
        Assert-True (-not $missingValue.Exists) 'Missing registry values were not represented exactly.'
        New-ItemProperty -LiteralPath $registryPath -Name Environment -PropertyType MultiString `
            -Value ([string[]]@('LINKLAKE_A=1', 'LINKLAKE_B=2')) | Out-Null
        $environmentSnapshot = Get-LinkLakeRegistryValueSnapshot $registryPath 'Environment'
        Remove-ItemProperty -LiteralPath $registryPath -Name Environment
        Restore-LinkLakeRegistryValueSnapshot $registryPath 'Environment' $environmentSnapshot
        $restoredEnvironment = @((Get-Item -LiteralPath $registryPath).GetValue('Environment'))
        Assert-True (($restoredEnvironment -join ',') -eq 'LINKLAKE_A=1,LINKLAKE_B=2') 'MultiString registry restore was not exact.'
        Restore-LinkLakeRegistryValueSnapshot $registryPath 'Environment' $missingValue
        Assert-True ((Get-Item -LiteralPath $registryPath).GetValueNames() -notcontains 'Environment') 'Absent registry value was recreated during rollback.'

        $triStateCases = @(
            [pscustomobject]@{ Name = 'MissingPrivileges'; Kind = $null; Value = $null; Exists = $false },
            [pscustomobject]@{ Name = 'EmptyPrivileges'; Kind = 'MultiString'; Value = [string[]]@(); Exists = $true },
            [pscustomobject]@{ Name = 'RequiredPrivileges'; Kind = 'MultiString'; Value = [string[]]@('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege'); Exists = $true },
            [pscustomobject]@{ Name = 'FailureActions'; Kind = 'Binary'; Value = [byte[]]@(1, 2, 3, 4); Exists = $true },
            [pscustomobject]@{ Name = 'DelayedAutoStart'; Kind = 'DWord'; Value = 1; Exists = $true }
        )
        foreach ($case in $triStateCases) {
            if ($case.Exists) {
                New-ItemProperty -LiteralPath $registryPath -Name $case.Name -PropertyType $case.Kind -Value $case.Value -Force | Out-Null
            }
            $expectedSnapshot = Get-LinkLakeRegistryValueSnapshot $registryPath $case.Name
            New-ItemProperty -LiteralPath $registryPath -Name $case.Name -PropertyType String -Value 'mutated' -Force | Out-Null
            Restore-LinkLakeRegistryValueSnapshot $registryPath $case.Name $expectedSnapshot
            $actualSnapshot = Get-LinkLakeRegistryValueSnapshot $registryPath $case.Name
            Assert-RegistrySnapshotEqual $expectedSnapshot $actualSnapshot $case.Name
        }

        if (-not (Test-Path -LiteralPath $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $registryPath -Name AclFixture -PropertyType String -Value 'fixture' -Force | Out-Null
        $originalRegistrySddl = Get-LinkLakeRegistrySecurityDescriptor $registryPath
        Assert-True ($originalRegistrySddl -match 'D:') 'Registry security descriptor snapshot failed.'
        Assert-Throws { Get-LinkLakeRegistrySecurityDescriptor 'HKCU:\Software\unsafe*' } 'safe absolute registry path'
    }
    finally {
        Remove-Item -LiteralPath $registryPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    $validConfig = Join-Path $testRoot 'client.toml'
    [IO.File]::WriteAllText($validConfig, "[server]`naddress = '127.0.0.1:32101'`n", [Text.UTF8Encoding]::new($false))
    Assert-LinkLakeUtf8ConfigFile $validConfig 'client config'
    $invalidConfig = Join-Path $testRoot 'invalid.toml'
    [IO.File]::WriteAllBytes($invalidConfig, [byte[]]@(0xC3, 0x28))
    Assert-Throws { Assert-LinkLakeUtf8ConfigFile $invalidConfig 'client config' } 'valid UTF-8'

    $certificate = Join-Path $testRoot 'certificate.pem'
    $privateKey = Join-Path $testRoot 'private-key.pem'
    Copy-Item -LiteralPath (Join-Path $projectRoot 'tests\pebble\pebble.minica.pem') -Destination $certificate
    [IO.File]::WriteAllText($privateKey, "-----BEGIN PRIVATE KEY-----`nZml4dHVyZQ==`n-----END PRIVATE KEY-----`n", [Text.Encoding]::ASCII)
    Assert-LinkLakePemFile $certificate 'certificate' 'certificate'
    Assert-LinkLakePemFile $privateKey 'private-key' 'private key'
    Assert-Throws { Assert-LinkLakePemFile $certificate 'private-key' 'private key' } 'exactly one unencrypted PEM private key'

    $downloadFixture = Join-Path $testRoot 'download.zip'
    [IO.File]::WriteAllText($downloadFixture, 'archive fixture', [Text.Encoding]::ASCII)
    $downloadHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $downloadFixture).Hash.ToLowerInvariant()
    $downloadSidecar = "$downloadFixture.sha256"
    [IO.File]::WriteAllText($downloadSidecar, "$downloadHash  download.zip`n", [Text.Encoding]::ASCII)
    Assert-True ((Read-LinkLakeSha256Sidecar $downloadSidecar 'download.zip') -eq $downloadHash) 'Strict SHA-256 sidecar parsing failed.'
    [IO.File]::WriteAllText($downloadSidecar, "$downloadHash  another.zip`n", [Text.Encoding]::ASCII)
    Assert-Throws { Read-LinkLakeSha256Sidecar $downloadSidecar 'download.zip' } 'invalid or mismatched'

    $safeZip = Join-Path $testRoot 'safe.zip'
    Write-TestZipArchive $safeZip @(
        [pscustomobject]@{ Name = 'folder/'; Content = '' },
        [pscustomobject]@{ Name = 'folder/file.txt'; Content = 'safe' }
    )
    $safeExtract = Join-Path $testRoot 'safe-extract'
    $zipInspection = Expand-LinkLakeZipArchiveSafely $safeZip $safeExtract
    Assert-True ($zipInspection.Entries -contains 'folder/file.txt') 'Safe ZIP entry was not returned.'
    Assert-True ([IO.File]::ReadAllText((Join-Path $safeExtract 'folder\file.txt')) -eq 'safe') 'Safe ZIP content was not extracted.'
    Remove-Item -LiteralPath $safeExtract -Recurse -Force

    $escapeZip = Join-Path $testRoot 'escape.zip'
    Write-TestZipArchive $escapeZip @([pscustomobject]@{ Name = '../escape.txt'; Content = 'escape' })
    Assert-Throws { Expand-LinkLakeZipArchiveSafely $escapeZip (Join-Path $testRoot 'escape-extract') } 'unsafe entry'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $testRoot 'escape.txt'))) 'ZIP traversal wrote outside the destination.'

    $duplicateZip = Join-Path $testRoot 'duplicate.zip'
    Write-TestZipArchive $duplicateZip @(
        [pscustomobject]@{ Name = 'file.txt'; Content = 'one' },
        [pscustomobject]@{ Name = 'FILE.txt'; Content = 'two' }
    )
    Assert-Throws { Expand-LinkLakeZipArchiveSafely $duplicateZip (Join-Path $testRoot 'duplicate-extract') } 'repeats entry'

    $adsZip = Join-Path $testRoot 'ads.zip'
    Write-TestZipArchive $adsZip @([pscustomobject]@{ Name = 'file.txt:payload'; Content = 'ads' })
    Assert-Throws { Expand-LinkLakeZipArchiveSafely $adsZip (Join-Path $testRoot 'ads-extract') } 'unsafe entry'

    $packageRoot = Join-Path $testRoot 'package'
    New-Item -ItemType Directory -Path (Join-Path $packageRoot 'bin'), (Join-Path $packageRoot 'windows') | Out-Null
    foreach ($file in @(
            'bin\linklake-server.exe', 'bin\linklake-client.exe',
            'windows\installer-common.ps1', 'windows\install-server.ps1',
            'windows\install-client.ps1', 'windows\uninstall.ps1'
        )) {
        [IO.File]::WriteAllText((Join-Path $packageRoot $file), "fixture:$file", [Text.Encoding]::UTF8)
    }
    $release = [ordered]@{
        product = 'LinkLake'
        version = '0.8.0-rc.1'
        target = 'windows-x86_64'
        built_unix_seconds = 1785686400
        commit = '0123456789ab'
    }
    [IO.File]::WriteAllText(
        (Join-Path $packageRoot 'release.json'),
        ($release | ConvertTo-Json -Compress) + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    Write-TestChecksumManifest $packageRoot
    Assert-LinkLakePackageChecksums $packageRoot
    $identity = Read-LinkLakeReleaseIdentity $packageRoot 'windows-x86_64'
    Assert-True ($identity.version -eq '0.8.0-rc.1') 'Release identity version was not read.'

    Add-Content -LiteralPath (Join-Path $packageRoot 'bin\linklake-server.exe') -Value 'tampered'
    Assert-Throws { Assert-LinkLakePackageChecksums $packageRoot } 'failed SHA-256 validation'
    [IO.File]::WriteAllText((Join-Path $packageRoot 'bin\linklake-server.exe'), 'fixture:bin\linklake-server.exe', [Text.Encoding]::UTF8)
    Write-TestChecksumManifest $packageRoot

    $manifestPath = Join-Path $packageRoot 'checksums.sha256'
    $originalManifest = [IO.File]::ReadAllText($manifestPath, [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText($manifestPath, $originalManifest + ('0' * 64) + "  ../escape`n", [Text.Encoding]::ASCII)
    Assert-Throws { Assert-LinkLakePackageChecksums $packageRoot } 'invalid line|unsafe path'
    [IO.File]::WriteAllText($manifestPath, $originalManifest, [Text.Encoding]::ASCII)

    $unexpectedFile = Join-Path $packageRoot 'unexpected.txt'
    [IO.File]::WriteAllText($unexpectedFile, 'not covered by the manifest', [Text.Encoding]::ASCII)
    Assert-Throws { Assert-LinkLakePackageChecksums $packageRoot } 'not covered by checksums'
    Remove-Item -LiteralPath $unexpectedFile -Force

    $residualFixture = Join-Path $testRoot 'residual-fixture.txt'
    [IO.File]::WriteAllText($residualFixture, 'fixture', [Text.Encoding]::ASCII)
    $residualPaths = [Collections.Generic.List[string]]::new()
    Remove-LinkLakeArtifactReportingResidual $residualFixture $residualPaths
    Assert-True (-not (Test-Path -LiteralPath $residualFixture)) 'Committed artifact cleanup did not remove the fixture.'
    Assert-True ($residualPaths.Count -eq 0) 'Successful committed artifact cleanup reported a residual path.'
    $lockedResidual = Join-Path $testRoot 'locked-residual.txt'
    [IO.File]::WriteAllText($lockedResidual, 'locked', [Text.Encoding]::ASCII)
    $lockedStream = [IO.File]::Open($lockedResidual, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        Remove-LinkLakeArtifactReportingResidual $lockedResidual $residualPaths -WarningAction SilentlyContinue
        Assert-True ($residualPaths -contains $lockedResidual) 'Failed cleanup did not report the exact residual path.'
    }
    finally {
        $lockedStream.Dispose()
        Remove-Item -LiteralPath $lockedResidual -Force -ErrorAction SilentlyContinue
    }

    $withoutUninstaller = @($originalManifest -split "`r?`n" | Where-Object { $_ -and $_ -notmatch 'windows/uninstall\.ps1$' }) -join "`n"
    [IO.File]::WriteAllText($manifestPath, $withoutUninstaller + "`n", [Text.Encoding]::ASCII)
    Assert-Throws { Assert-LinkLakePackageChecksums $packageRoot } 'missing windows/uninstall.ps1'
    [IO.File]::WriteAllText($manifestPath, $originalManifest, [Text.Encoding]::ASCII)

    $releasePath = Join-Path $packageRoot 'release.json'
    $originalRelease = [IO.File]::ReadAllText($releasePath, [Text.Encoding]::UTF8)
    $futureRelease = [ordered]@{} + $release
    $futureRelease['built_unix_seconds'] = [DateTimeOffset]::UtcNow.AddDays(2).ToUnixTimeSeconds()
    [IO.File]::WriteAllText($releasePath, ($futureRelease | ConvertTo-Json -Compress) + "`n", [Text.UTF8Encoding]::new($false))
    Assert-Throws { Read-LinkLakeReleaseIdentity $packageRoot 'windows-x86_64' } 'invalid build time'
    $unknownRelease = [ordered]@{} + $release
    $unknownRelease['unexpected'] = $true
    [IO.File]::WriteAllText($releasePath, ($unknownRelease | ConvertTo-Json -Compress) + "`n", [Text.UTF8Encoding]::new($false))
    Assert-Throws { Read-LinkLakeReleaseIdentity $packageRoot 'windows-x86_64' } 'missing or unknown fields'
    [IO.File]::WriteAllText($releasePath, $originalRelease, [Text.UTF8Encoding]::new($false))

    $fakeServer = Join-Path $testRoot 'fake-server.cmd'
    [IO.File]::WriteAllLines($fakeServer, @(
            '@echo off',
            'echo {"product":"LinkLake Server","version":"0.8.0-rc.1","target":"windows-x86_64","commit":"0123456789ab"}'
        ), [Text.Encoding]::ASCII)
    $null = Assert-LinkLakePackageBinary $fakeServer 'LinkLake Server' $identity
    Assert-Throws { Assert-LinkLakePackageBinary $fakeServer 'LinkLake Client' $identity } 'does not match'

    $readAcl = New-LinkLakeDirectoryAcl
    $writeAcl = New-LinkLakeDirectoryAcl -WritableByService
    $localService = 'S-1-5-19'
    $readRule = @($readAcl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $localService })[0]
    $writeRule = @($writeAcl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $localService })[0]
    Assert-True (($readRule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -ne 0) 'LocalService lacks read/execute access to program files.'
    Assert-True (($writeRule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -ne 0) 'LocalService lacks write access to state directories.'

    $script:events = [Collections.Generic.List[string]]::new()
    Invoke-LinkLakeTransactionalChange `
        -Stop { $script:events.Add('stop') } `
        -Apply { $script:events.Add('apply') } `
        -Validate { $script:events.Add('validate') } `
        -Start { $script:events.Add('start') } `
        -Rollback { $script:events.Add('rollback') } `
        -Recover { $script:events.Add('recover') } `
        -WasRunning $true -ShouldStart $true
    Assert-Sequence $script:events @('stop', 'apply', 'validate', 'start') 'successful transaction'

    $script:events.Clear()
    Assert-Throws {
        Invoke-LinkLakeTransactionalChange `
            -Stop { $script:events.Add('stop'); throw 'stop-failed' } `
            -Apply { $script:events.Add('apply') } `
            -Validate { $script:events.Add('validate') } `
            -Start { $script:events.Add('start') } `
            -Rollback { $script:events.Add('rollback') } `
            -Recover { $script:events.Add('recover') } `
            -WasRunning $true -ShouldStart $true
    } 'stop-failed'
    Assert-Sequence $script:events @('stop', 'recover') 'failed stop'

    $script:events.Clear()
    Assert-Throws {
        Invoke-LinkLakeTransactionalChange `
            -Stop { $script:events.Add('stop') } `
            -Apply { $script:events.Add('apply'); throw 'apply-failed' } `
            -Validate { $script:events.Add('validate') } `
            -Start { $script:events.Add('start') } `
            -Rollback { $script:events.Add('rollback') } `
            -Recover { $script:events.Add('recover') } `
            -WasRunning $true -ShouldStart $true
    } 'previous installation was restored'
    Assert-Sequence $script:events @('stop', 'apply', 'rollback', 'recover') 'failed apply'

    $script:events.Clear()
    Assert-Throws {
        Invoke-LinkLakeTransactionalChange `
            -Stop { $script:events.Add('stop') } `
            -Apply { $script:events.Add('apply') } `
            -Validate { $script:events.Add('validate') } `
            -Start { $script:events.Add('start'); throw 'start-failed' } `
            -Rollback { $script:events.Add('rollback') } `
            -Recover { $script:events.Add('recover') } `
            -WasRunning $true -ShouldStart $true
    } 'previous installation was restored'
    Assert-Sequence $script:events @('stop', 'apply', 'validate', 'start', 'rollback', 'recover') 'failed start'

    $script:events.Clear()
    Invoke-LinkLakeTransactionalUninstall `
        -Stop { $script:events.Add('stop') } `
        -Stage { $script:events.Add('stage') } `
        -Remove { $script:events.Add('remove') } `
        -Commit { $script:events.Add('commit') } `
        -Rollback { $script:events.Add('rollback') } `
        -Recover { $script:events.Add('recover') }
    Assert-Sequence $script:events @('stop', 'stage', 'remove', 'commit') 'successful uninstall transaction'

    $script:events.Clear()
    Assert-Throws {
        Invoke-LinkLakeTransactionalUninstall `
            -Stop { $script:events.Add('stop'); throw 'stop-failed' } `
            -Stage { $script:events.Add('stage') } `
            -Remove { $script:events.Add('remove') } `
            -Commit { $script:events.Add('commit') } `
            -Rollback { $script:events.Add('rollback') } `
            -Recover { $script:events.Add('recover') }
    } 'previous installation and requested data were restored'
    Assert-Sequence $script:events @('stop', 'recover') 'failed uninstall stop'

    $script:events.Clear()
    Assert-Throws {
        Invoke-LinkLakeTransactionalUninstall `
            -Stop { $script:events.Add('stop') } `
            -Stage { $script:events.Add('stage'); throw 'stage-failed' } `
            -Remove { $script:events.Add('remove') } `
            -Commit { $script:events.Add('commit') } `
            -Rollback { $script:events.Add('rollback') } `
            -Recover { $script:events.Add('recover') }
    } 'previous installation and requested data were restored'
    Assert-Sequence $script:events @('stop', 'stage', 'rollback', 'recover') 'failed uninstall staging'

    $script:events.Clear()
    Assert-Throws {
        Invoke-LinkLakeTransactionalUninstall `
            -Stop { $script:events.Add('stop') } `
            -Stage { $script:events.Add('stage') } `
            -Remove { $script:events.Add('remove'); throw 'remove-failed' } `
            -Commit { $script:events.Add('commit') } `
            -Rollback { $script:events.Add('rollback') } `
            -Recover { $script:events.Add('recover') }
    } 'previous installation and requested data were restored'
    Assert-Sequence $script:events @('stop', 'stage', 'remove', 'rollback', 'recover') 'failed uninstall removal'

    $serverInstaller = [IO.File]::ReadAllText((Join-Path $windowsRoot 'install-server.ps1'))
    $clientInstaller = [IO.File]::ReadAllText((Join-Path $windowsRoot 'install-client.ps1'))
    $uninstaller = [IO.File]::ReadAllText((Join-Path $windowsRoot 'uninstall.ps1'))
    foreach ($installer in @($serverInstaller, $clientInstaller)) {
        Assert-True ($installer.Contains('NT AUTHORITY\LocalService')) 'Installer does not configure LocalService.'
        Assert-True ($installer.Contains('Invoke-LinkLakeTransactionalChange')) 'Installer does not use the transaction boundary.'
        Assert-True ($installer.Contains('Assert-LinkLakePackageChecksums')) 'Installer does not verify package checksums.'
        Assert-True ($installer.Contains('Enter-LinkLakeInstallerLock')) 'Installer does not serialize concurrent lifecycle changes.'
        Assert-True ($installer.Contains('$snapshot.WasActive')) 'Installer does not preserve active service state.'
        Assert-True (-not $installer.Contains("Invoke-LinkLakeSc @('delete'")) 'Installer deletes an existing service instead of updating it in place.'
        $accountIndex = $installer.IndexOf("'obj=', 'NT AUTHORITY\LocalService'")
        $sidIndex = $installer.IndexOf("Invoke-LinkLakeSc @('sidtype', `$serviceName, 'none')")
        $privilegeIndex = $installer.IndexOf("Invoke-LinkLakeSc @('privs', `$serviceName, 'SeChangeNotifyPrivilege')")
        Assert-True ($accountIndex -ge 0 -and $sidIndex -gt $accountIndex -and $privilegeIndex -gt $sidIndex) `
            'Installer does not apply the LocalService least-privilege boundary in a deterministic order.'
    }
    Assert-True ($clientInstaller.Contains('$ReplaceConfig')) 'Client installer lacks explicit config replacement semantics.'
    Assert-True ($clientInstaller.Contains('Assert-LinkLakeUtf8ConfigFile')) 'Client installer does not validate staged and installed config text.'
    Assert-True ($serverInstaller.Contains("Remove('LINKLAKE_ADMIN_PASSWORD')")) 'Server installer does not remove bootstrap credentials.'
    Assert-True ($serverInstaller.Contains('$SecretsDirectory')) 'Server installer does not isolate managed TLS secrets.'
    Assert-True ($serverInstaller.Contains('Assert-LinkLakePemFile')) 'Server installer does not validate TLS secret inputs.'
    Assert-True ($uninstaller.Contains('LINKLAKE-PURGE')) 'Uninstaller lacks explicit purge confirmation.'
    Assert-True ($uninstaller.Contains('Invoke-LinkLakeTransactionalUninstall')) 'Uninstaller does not use the tested transaction boundary.'
    Assert-True ($uninstaller.Contains('Enter-LinkLakeInstallerLock')) 'Uninstaller does not serialize concurrent lifecycle changes.'
    Assert-True ($uninstaller.Contains('persistent configuration and data were preserved')) 'Uninstaller does not preserve data by default.'
    Assert-True ($uninstaller.Contains('cleanup left residual paths')) 'Uninstaller does not explicitly report cleanup residuals.'
    $commonScript = [IO.File]::ReadAllText((Join-Path $windowsRoot 'installer-common.ps1'))
    $environmentRestoreIndex = $commonScript.IndexOf("Restore-LinkLakeRegistryValueSnapshot `$registryPath 'Environment'")
    $nativeRestoreIndex = $commonScript.IndexOf("[LinkLakeServiceNative]::Restore(`$ServiceName, `$Snapshot.NativeConfig)")
    $exactFailureActionsIndex = $commonScript.IndexOf("@('FailureActions', `$Snapshot.FailureActions)")
    $registryAclIndex = $commonScript.IndexOf('Restore-LinkLakeRegistrySecurityDescriptor $registryPath $Snapshot.RegistrySddl')
    $serviceAclIndex = $commonScript.IndexOf("Invoke-LinkLakeSc @('sdset', `$ServiceName, `$Snapshot.ServiceSddl)")
    Assert-True ($environmentRestoreIndex -ge 0 -and $environmentRestoreIndex -lt $nativeRestoreIndex) `
        'Service Environment is not restored before advanced service settings.'
    Assert-True ($nativeRestoreIndex -lt $exactFailureActionsIndex) `
        'Advanced native service settings are not restored before exact registry presence/value snapshots.'
    Assert-True ($exactFailureActionsIndex -lt $registryAclIndex -and $registryAclIndex -lt $serviceAclIndex) `
        'Registry values and security descriptors are not restored in least-privilege order.'
    Assert-True (-not $commonScript.Contains("if (-not `$Snapshot.RequiredPrivileges.Exists -and (Test-LinkLakeServiceExists `$ServiceName))")) `
        'Missing RequiredPrivileges still causes destructive service recreation.'
}
finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
    Remove-Variable events -Scope Script -ErrorAction SilentlyContinue
}

[ordered]@{
    ok = $true
    scripts_parsed = $windowsScripts.Count
    checksum_tamper_rejected = $true
    unsafe_inputs_rejected = $true
    reparse_point_tested = $reparseTested
    transaction_rollback_tested = $true
    uninstall_rollback_tested = $true
    registry_snapshot_tested = $true
    registry_tristate_snapshot_tested = $true
    native_service_snapshot_compiled = $true
    native_required_privileges_snapshot_tested = $true
    local_service_acl_tested = $true
    registry_acl_restore_tested = $true
    uninstall_residual_reporting_tested = $true
} | ConvertTo-Json
