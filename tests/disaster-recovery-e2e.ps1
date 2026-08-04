param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath 'Variable:PSNativeCommandUseErrorActionPreference') {
    $PSNativeCommandUseErrorActionPreference = $false
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$serverPath = Join-Path $projectRoot 'target\debug\linklake-server.exe'
$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('linklake-disaster-recovery-e2e-' + [guid]::NewGuid())
$dataDir = Join-Path $runRoot 'data'
$archiveDir = Join-Path $runRoot 'archives'
$archivePath = Join-Path $archiveDir 'server.llb'
$passwordFile = Join-Path $runRoot 'backup-password.txt'
$password = 'LinkLake-Disaster-Recovery-E2E-Password!'
$serverProcess = $null

function ConvertTo-NativeArguments([string[]]$Arguments) {
    return (($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"' + $_.Replace('\', '\').Replace('"', '\"') + '"'
        } else {
            $_
        }
    }) -join ' ')
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Start-TestServer {
    $managementPort = Get-FreeTcpPort
    $controlPort = Get-FreeTcpPort
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $serverPath
    $info.WorkingDirectory = $projectRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.EnvironmentVariables['LINKLAKE_DATA_DIR'] = $dataDir
    $info.EnvironmentVariables['LINKLAKE_LOG_DIR'] = (Join-Path $runRoot 'logs')
    $info.EnvironmentVariables['LINKLAKE_BIND'] = "127.0.0.1:$managementPort"
    $info.EnvironmentVariables['LINKLAKE_CONTROL_BIND'] = "127.0.0.1:$controlPort"
    $info.EnvironmentVariables['LINKLAKE_ADMIN_USERNAME'] = 'admin'
    $info.EnvironmentVariables['LINKLAKE_ADMIN_PASSWORD'] = 'LinkLake-Disaster-E2E-Admin!'
    $process = [Diagnostics.Process]::Start($info)
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($process.HasExited) {
            throw "LinkLake server exited during startup with code $($process.ExitCode)."
        }
        if (Test-Path -LiteralPath (Join-Path $dataDir 'linklake.sqlite3')) {
            $probe = [Net.Sockets.TcpClient]::new()
            try {
                $probe.Connect('127.0.0.1', $managementPort)
                return $process
            }
            catch {
                # 服务端可能仍在恢复 journal 或执行迁移，继续等待。
                $null = $_
            }
            finally {
                $probe.Dispose()
            }
        }
        Start-Sleep -Milliseconds 150
    }
    if (-not $process.HasExited) { $process.Kill() }
    throw 'Timed out waiting for the LinkLake database.'
}

function Stop-TestServer([Diagnostics.Process]$Process) {
    if ($null -eq $Process) { return }
    if (-not $Process.HasExited) {
        $Process.Kill()
        if (-not $Process.WaitForExit(10000)) {
            throw "LinkLake server PID $($Process.Id) did not stop."
        }
    }
    $Process.Dispose()
}

function Invoke-LinkLake {
    param(
        [string[]]$Arguments,
        [AllowNull()][string]$StandardInput,
        [int]$ExpectedExitCode = 0,
        [hashtable]$Environment = @{}
    )
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $serverPath
    $info.Arguments = ConvertTo-NativeArguments $Arguments
    $info.WorkingDirectory = $projectRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $null -ne $StandardInput
    foreach ($entry in $Environment.GetEnumerator()) {
        $info.EnvironmentVariables[[string]$entry.Key] = [string]$entry.Value
    }
    $process = [Diagnostics.Process]::Start($info)
    if ($null -ne $StandardInput) {
        $process.StandardInput.WriteLine($StandardInput)
        $process.StandardInput.Close()
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    if (-not $process.WaitForExit(30000)) {
        $process.Kill()
        throw "LinkLake command timed out: $($Arguments[0])"
    }
    $exitCode = $process.ExitCode
    $process.Dispose()
    if ($exitCode -ne $ExpectedExitCode) {
        throw "LinkLake command $($Arguments[0]) returned $exitCode, expected $ExpectedExitCode. stdout=$stdout stderr=$stderr"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Stdout = $stdout; Stderr = $stderr }
}

function Get-OpenSslPath {
    $command = Get-Command openssl.exe -ErrorAction SilentlyContinue
    $candidates = @(
        $(if ($null -ne $command) { $command.Source }),
        'C:\Program Files\Git\usr\bin\openssl.exe',
        'C:\Program Files\Git\mingw64\bin\openssl.exe'
    )
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and
            (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }
    throw 'OpenSSL is required to create the disaster-recovery E2E certificate pair.'
}

function Test-ByteSequence([byte[]]$Haystack, [byte[]]$Needle) {
    if ($Needle.Length -eq 0) { return $true }
    for ($offset = 0; $offset -le $Haystack.Length - $Needle.Length; $offset++) {
        $match = $true
        for ($index = 0; $index -lt $Needle.Length; $index++) {
            if ($Haystack[$offset + $index] -ne $Needle[$index]) {
                $match = $false
                break
            }
        }
        if ($match) { return $true }
    }
    return $false
}

New-Item -ItemType Directory -Path $runRoot | Out-Null
New-Item -ItemType Directory -Path $archiveDir | Out-Null
try {
    if (-not $SkipBuild) {
        & cargo build -p linklake-server --locked
        if ($LASTEXITCODE -ne 0) { throw 'Could not build linklake-server.' }
    }
    if (-not (Test-Path -LiteralPath $serverPath)) {
        throw "Missing LinkLake server binary: $serverPath"
    }

    $serverProcess = Start-TestServer
    Stop-TestServer $serverProcess
    $serverProcess = $null

    New-Item -ItemType Directory -Path (Join-Path $dataDir 'acme\empty') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $dataDir 'certificates\example.test') | Out-Null
    $certificatePath = Join-Path $runRoot 'example.test.crt.pem'
    $privateKeyPath = Join-Path $runRoot 'example.test.key.pem'
    $openSslPath = Get-OpenSslPath
    $oldArgConversion = $env:MSYS2_ARG_CONV_EXCL
    try {
        $env:MSYS2_ARG_CONV_EXCL = '*'
        $openSslInfo = [Diagnostics.ProcessStartInfo]::new()
        $openSslInfo.FileName = $openSslPath
        $openSslInfo.Arguments = ConvertTo-NativeArguments @(
            'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
            '-subj', '/CN=example.test', '-addext', 'subjectAltName=DNS:example.test',
            '-keyout', $privateKeyPath, '-out', $certificatePath
        )
        $openSslInfo.WorkingDirectory = $projectRoot
        $openSslInfo.UseShellExecute = $false
        $openSslInfo.CreateNoWindow = $true
        $openSslInfo.RedirectStandardOutput = $true
        $openSslInfo.RedirectStandardError = $true
        $openSslProcess = [Diagnostics.Process]::Start($openSslInfo)
        $openSslStdout = $openSslProcess.StandardOutput.ReadToEnd()
        $openSslStderr = $openSslProcess.StandardError.ReadToEnd()
        $openSslProcess.WaitForExit()
        $openSslExitCode = $openSslProcess.ExitCode
        $openSslProcess.Dispose()
        if ($openSslExitCode -ne 0) {
            throw "OpenSSL could not create the E2E certificate pair: $openSslStdout $openSslStderr"
        }
    }
    finally {
        $env:MSYS2_ARG_CONV_EXCL = $oldArgConversion
    }
    $certificateText = [IO.File]::ReadAllText($certificatePath)
    $privateKeyText = [IO.File]::ReadAllText($privateKeyPath)
    $privateKeyProbe = @($privateKeyText -split '\r?\n' | Where-Object {
        $_ -and $_ -notmatch '^-----'
    })[0]
    [IO.File]::WriteAllText(
        (Join-Path $dataDir 'acme\account.json'),
        'e2e-original-acme-secret',
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $dataDir 'certificates\example.test\fullchain.pem'),
        $certificateText,
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $dataDir 'certificates\example.test\private-key.pem'),
        $privateKeyText,
        [Text.UTF8Encoding]::new($false)
    )

    $backup = Invoke-LinkLake -Arguments @(
        'backup-full', '--data-dir', $dataDir, '--output', $archivePath, '--password-stdin'
    ) -StandardInput $password
    if ($backup.Stdout -notmatch 'encrypted full backup created') {
        throw 'backup-full did not report successful completion.'
    }
    if (-not (Test-Path -LiteralPath $archivePath)) { throw 'Encrypted backup was not created.' }
    $archiveBytes = [IO.File]::ReadAllBytes($archivePath)
    foreach ($secret in @('e2e-original-acme-secret', $privateKeyProbe)) {
        if (Test-ByteSequence $archiveBytes ([Text.Encoding]::UTF8.GetBytes($secret))) {
            throw "Encrypted archive disclosed plaintext marker $secret."
        }
    }

    $plaintextArgument = Invoke-LinkLake -Arguments @(
        'backup-full', '--data-dir', $dataDir, '--output', (Join-Path $archiveDir 'forbidden.llb'),
        '--password', $password
    ) -StandardInput $null -ExpectedExitCode 2
    if ($plaintextArgument.Stderr -notmatch "unexpected argument '--password'") {
        throw 'Plaintext password argument was not rejected by the typed CLI.'
    }
    if ($plaintextArgument.Stderr.Contains($password)) {
        throw 'Typed CLI error output disclosed the plaintext password argument.'
    }

    [IO.File]::WriteAllText(
        (Join-Path $dataDir 'acme\account.json'),
        'e2e-mutated-acme-secret',
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $dataDir 'acme\extra.json'),
        'must disappear after restore',
        [Text.UTF8Encoding]::new($false)
    )

    $wrong = Invoke-LinkLake -Arguments @(
        'restore-full', '--data-dir', $dataDir, '--input', $archivePath, '--password-stdin'
    ) -StandardInput 'LinkLake-Wrong-Password-For-E2E!' -ExpectedExitCode 1
    if ($wrong.Stderr -notmatch 'authentication failed') {
        throw 'Wrong password did not fail authentication.'
    }
    if ((Get-Content -Raw -LiteralPath (Join-Path $dataDir 'acme\account.json')) -ne 'e2e-mutated-acme-secret') {
        throw 'Failed authentication modified managed state.'
    }

    $tamperedPath = Join-Path $archiveDir 'tampered.llb'
    $tampered = [IO.File]::ReadAllBytes($archivePath)
    $tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 0x80
    [IO.File]::WriteAllBytes($tamperedPath, $tampered)
    $tamperedResult = Invoke-LinkLake -Arguments @(
        'restore-full', '--data-dir', $dataDir, '--input', $tamperedPath, '--password-stdin'
    ) -StandardInput $password -ExpectedExitCode 1
    if ($tamperedResult.Stderr -notmatch 'authentication failed') {
        throw 'Tampered backup was not rejected by authentication.'
    }

    $serverProcess = Start-TestServer
    $locked = Invoke-LinkLake -Arguments @(
        'restore-full', '--data-dir', $dataDir, '--input', $archivePath, '--password-stdin'
    ) -StandardInput $password -ExpectedExitCode 1
    if ($locked.Stderr -notmatch 'must be stopped') {
        throw 'restore-full did not reject a running LinkLake server.'
    }
    Stop-TestServer $serverProcess
    $serverProcess = $null

    [IO.File]::WriteAllBytes($passwordFile, [Text.Encoding]::UTF8.GetBytes($password))
    $restore = Invoke-LinkLake -Arguments @(
        'restore-full', '--data-dir', $dataDir, '--input', $archivePath,
        '--password-file', $passwordFile
    ) -StandardInput $null
    if ($restore.Stdout -notmatch 'full backup restored') {
        throw 'restore-full did not report successful completion.'
    }
    if ((Get-Content -Raw -LiteralPath (Join-Path $dataDir 'acme\account.json')) -ne 'e2e-original-acme-secret') {
        throw 'ACME state was not restored.'
    }
    if ((Get-Content -Raw -LiteralPath (Join-Path $dataDir 'certificates\example.test\private-key.pem')) -ne $privateKeyText) {
        throw 'Certificate private key was not restored.'
    }
    if (Test-Path -LiteralPath (Join-Path $dataDir 'acme\extra.json')) {
        throw 'Restore retained a file that was absent from the authenticated backup.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $dataDir 'acme\empty'))) {
        throw 'Restore did not preserve an authenticated empty directory.'
    }
    $preserved = @(Get-ChildItem -LiteralPath $dataDir -Directory -Filter '.pre-restore-*')
    if ($preserved.Count -ne 1) { throw 'Restore did not preserve exactly one previous state directory.' }
    if ((Get-Content -Raw -LiteralPath (Join-Path $preserved[0].FullName 'acme\account.json')) -ne 'e2e-mutated-acme-secret') {
        throw 'The pre-restore directory does not contain the prior ACME state.'
    }

    $serverProcess = Start-TestServer
    Stop-TestServer $serverProcess
    $serverProcess = $null
    if (Test-Path -LiteralPath (Join-Path $dataDir 'linklake.restore-journal')) {
        throw 'Server startup did not finalize the committed restore journal.'
    }

    [IO.File]::WriteAllText(
        (Join-Path $dataDir 'acme\account.json'),
        'e2e-before-uncertain-commit',
        [Text.UTF8Encoding]::new($false)
    )
    $uncertain = Invoke-LinkLake -Arguments @(
        'restore-full', '--data-dir', $dataDir, '--input', $archivePath,
        '--password-file', $passwordFile
    ) -StandardInput $null -ExpectedExitCode 1 -Environment @{
        LINKLAKE_TEST_RESTORE_FAILPOINT = 'commit-after-sync-error'
    }
    if ($uncertain.Stderr -notmatch 'durable commit result is uncertain') {
        throw 'Injected post-sync commit uncertainty did not fail closed.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $dataDir 'linklake.restore-journal'))) {
        throw 'Commit uncertainty did not retain the restore journal.'
    }
    if ((Get-Content -Raw -LiteralPath (Join-Path $dataDir 'acme\account.json')) -ne 'e2e-original-acme-secret') {
        throw 'Commit uncertainty actively rolled back a durably committed restore.'
    }

    $serverProcess = Start-TestServer
    Stop-TestServer $serverProcess
    $serverProcess = $null
    if (Test-Path -LiteralPath (Join-Path $dataDir 'linklake.restore-journal')) {
        throw 'Startup recovery did not finalize the uncertain committed journal.'
    }
    if ((Get-Content -Raw -LiteralPath (Join-Path $dataDir 'acme\account.json')) -ne 'e2e-original-acme-secret') {
        throw 'Startup recovery did not retain the durably committed restored state.'
    }
    $uncertainPreserved = @(Get-ChildItem -LiteralPath $dataDir -Directory -Filter '.pre-restore-*' |
        Where-Object {
            $candidate = Join-Path $_.FullName 'acme\account.json'
            (Test-Path -LiteralPath $candidate) -and
                ((Get-Content -Raw -LiteralPath $candidate) -eq 'e2e-before-uncertain-commit')
        })
    if ($uncertainPreserved.Count -ne 1) {
        throw 'Uncertain commit recovery did not preserve exactly one prior managed state.'
    }
    Write-Host 'LinkLake encrypted disaster-recovery E2E passed.'
}
finally {
    if ($null -ne $serverProcess) {
        try { Stop-TestServer $serverProcess } catch { Write-Warning $_ }
    }
    if (Test-Path -LiteralPath $runRoot) {
        $resolvedRunRoot = [IO.Path]::GetFullPath($runRoot)
        $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $resolvedRunRoot.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove unexpected E2E path: $resolvedRunRoot"
        }
        Remove-Item -LiteralPath $resolvedRunRoot -Recurse -Force
    }
}
