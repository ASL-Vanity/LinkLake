param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath 'Variable:PSNativeCommandUseErrorActionPreference') {
    $PSNativeCommandUseErrorActionPreference = $false
}
$env:NO_PROXY = '*'
$env:no_proxy = '*'

$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target/udp-e2e'
$binarySuffix = if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' }
$serverPath = Join-Path $targetRoot "debug/linklake-server$binarySuffix"
$clientPath = Join-Path $targetRoot "debug/linklake-client$binarySuffix"
$echoScriptPath = Join-Path $PSScriptRoot 'udp-echo-service.ps1'
$probeScriptPath = Join-Path $PSScriptRoot 'udp-probe.ps1'
$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('linklake-udp-e2e-' + [guid]::NewGuid())
$observationPath = Join-Path $runRoot 'udp-observations.jsonl'
$processSequence = 0
$serverProcess = $null
$clientProcess = $null
$udpEchoProcess = $null
$tcpEchoProcess = $null

function ConvertTo-ProcessArgument {
    param([AllowEmptyString()][string]$Argument)
    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') { return $Argument }
    $builder = [Text.StringBuilder]::new()
    $null = $builder.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            $null = $builder.Append(('\' * ($backslashes * 2 + 1)))
            $null = $builder.Append('"')
        } else {
            if ($backslashes -gt 0) { $null = $builder.Append(('\' * $backslashes)) }
            $null = $builder.Append($character)
        }
        $backslashes = 0
    }
    if ($backslashes -gt 0) { $null = $builder.Append(('\' * ($backslashes * 2))) }
    $null = $builder.Append('"')
    return $builder.ToString()
}

function Start-LoggedProcess {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [hashtable]$Environment = @{}
    )
    $script:processSequence++
    $stdoutPath = Join-Path $runRoot ("$Name-$($script:processSequence).stdout.log")
    $stderrPath = Join-Path $runRoot ("$Name-$($script:processSequence).stderr.log")
    $savedEnvironment = @{}
    try {
        foreach ($entry in $Environment.GetEnumerator()) {
            $savedEnvironment[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
            [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process')
        }
        $startArguments = @($Arguments | ForEach-Object { ConvertTo-ProcessArgument ([string]$_) }) -join ' '
        $parameters = @{
            FilePath = $FilePath
            WorkingDirectory = $projectRoot
            RedirectStandardOutput = $stdoutPath
            RedirectStandardError = $stderrPath
            PassThru = $true
        }
        if ($Arguments.Count -gt 0) { $parameters.ArgumentList = $startArguments }
        if ($env:OS -eq 'Windows_NT') { $parameters.WindowStyle = 'Hidden' }
        $process = Start-Process @parameters
        return [pscustomobject]@{
            Name = $Name
            Process = $process
            StdoutPath = $stdoutPath
            StderrPath = $stderrPath
        }
    } finally {
        foreach ($entry in $savedEnvironment.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
        }
    }
}

function Stop-LoggedProcess {
    param($Handle, [switch]$Verify)
    if ($null -eq $Handle) { return }
    try {
        if (-not $Handle.Process.HasExited) {
            Stop-Process -Id $Handle.Process.Id -Force -ErrorAction SilentlyContinue
            $exited = $Handle.Process.WaitForExit(10000)
            if ($Verify -and -not $exited) {
                throw "Process $($Handle.Name) did not exit after termination."
            }
        }
    } catch {
        if ($Verify) { throw }
        # Cleanup tolerates a process that has already exited.
    } finally {
        $Handle.Process.Dispose()
    }
}

function Write-FailureDiagnostics {
    Write-Warning "UDP E2E diagnostics are stored in $runRoot"
    foreach ($handle in @($serverProcess, $clientProcess, $udpEchoProcess, $tcpEchoProcess)) {
        if ($null -eq $handle) { continue }
        try {
            $handle.Process.Refresh()
            if ($handle.Process.HasExited) {
                Write-Warning "Process $($handle.Name) exited with code $($handle.Process.ExitCode)."
            } else {
                Write-Warning "Process $($handle.Name) is still running with PID $($handle.Process.Id)."
            }
        } catch {
            Write-Warning "Could not inspect process $($handle.Name): $($_.Exception.Message)"
        }
    }
    Get-ChildItem -LiteralPath $runRoot -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*.log*' -or $_.Name -like '*.jsonl' } |
        ForEach-Object {
            Write-Warning "--- $($_.FullName) ---"
            Get-Content -LiteralPath $_.FullName -Tail 120 -ErrorAction SilentlyContinue |
                ForEach-Object { Write-Warning $_ }
        }
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Get-FreeUdpPort {
    $socket = [System.Net.Sockets.UdpClient]::new(
        [System.Net.Sockets.AddressFamily]::InterNetwork
    )
    try {
        $socket.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0))
        return ([System.Net.IPEndPoint]$socket.Client.LocalEndPoint).Port
    } finally { $socket.Dispose() }
}

function Get-FreeTunnelPort {
    param([Collections.Generic.HashSet[int]]$UsedPorts)
    foreach ($candidate in (32000..32999 | Sort-Object { Get-Random })) {
        if ($UsedPorts.Contains($candidate)) { continue }
        $tcp = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $candidate)
        $udp = [System.Net.Sockets.UdpClient]::new(
            [System.Net.Sockets.AddressFamily]::InterNetwork
        )
        try {
            $tcp.Start()
            $udp.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, $candidate))
            $null = $UsedPorts.Add($candidate)
            return $candidate
        } catch {
            continue
        } finally {
            $tcp.Stop()
            $udp.Dispose()
        }
    }
    throw 'No TCP/UDP tunnel port is free in 32000-32999.'
}

function Wait-HttpHealth {
    param([string]$BaseUrl, [int]$Seconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri "$BaseUrl/api/v1/health" -TimeoutSec 2
            if ($health.status -eq 'ok') { return }
        } catch { Start-Sleep -Milliseconds 200 }
    }
    throw 'The LinkLake management endpoint did not become healthy.'
}

function Wait-TcpPort {
    param([int]$Port, [int]$Seconds = 20)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $Port)
            return
        } catch { Start-Sleep -Milliseconds 200 }
        finally { $client.Dispose() }
    }
    throw "TCP port $Port did not become reachable."
}

function Wait-EchoReady {
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $observationPath) {
            $ready = Get-Content -LiteralPath $observationPath -ErrorAction SilentlyContinue |
                Select-String -SimpleMatch '"event":"ready"'
            if ($ready) { return }
        }
        Start-Sleep -Milliseconds 100
    }
    throw 'The UDP echo service did not become ready.'
}

function Get-UdpTunnel {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$PolicyId
    )
    # Windows PowerShell 5.1 会把顶层 JSON 数组作为一个 Object[] 管道对象返回；
    # 再套 @() 会形成嵌套数组，使 $policy.id 变成整组 ID。只预置为 $null，
    # 直接赋值后交给 foreach 统一处理空数组、单项和多项结果。
    $policies = $null
    $policies = Invoke-RestMethod -Uri "$BaseUrl/api/v1/udp-tunnels" -WebSession $Session
    $current = $null
    foreach ($policy in $policies) {
        if ($null -ne $policy -and [string]$policy.id -eq $PolicyId) {
            $current = $policy
            break
        }
    }
    return $current
}

function Get-TcpTunnel {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$PolicyId
    )
    # 与 UDP 查询保持相同的 PowerShell 5.1 数组展开语义。
    $policies = $null
    $policies = Invoke-RestMethod -Uri "$BaseUrl/api/v1/tcp-tunnels" -WebSession $Session
    $current = $null
    foreach ($policy in $policies) {
        if ($null -ne $policy -and [string]$policy.id -eq $PolicyId) {
            $current = $policy
            break
        }
    }
    return $current
}

function Wait-UdpTunnelState {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$PolicyId,
        [bool]$Online,
        [bool]$Present = $true,
        [int]$Seconds = 60
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $current = Get-UdpTunnel -BaseUrl $BaseUrl -Session $Session -PolicyId $PolicyId
        if (-not $Present) {
            if ($null -eq $current) { return }
        } elseif ($null -ne $current -and [Convert]::ToBoolean($current.online) -eq $Online) {
            return
        }
        Start-Sleep -Milliseconds 200
    }
    try {
        $snapshot = Invoke-RestMethod -Uri "$BaseUrl/api/v1/udp-tunnels" -WebSession $Session
        Write-Warning ("Last UDP policy snapshot: " + ($snapshot | ConvertTo-Json -Depth 8 -Compress))
    } catch {
        Write-Warning "Could not read the last UDP policy snapshot: $($_.Exception.Message)"
    }
    throw "UDP policy $PolicyId did not reach present=$Present online=$Online."
}

function Wait-TcpTunnelOnline {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$PolicyId,
        [bool]$Online,
        [int]$Seconds = 60
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $current = Get-TcpTunnel -BaseUrl $BaseUrl -Session $Session -PolicyId $PolicyId
        if ($null -ne $current -and [Convert]::ToBoolean($current.online) -eq $Online) { return }
        Start-Sleep -Milliseconds 200
    }
    throw "TCP policy $PolicyId did not reach online=$Online."
}

function Wait-UdpPortAvailable {
    param([int]$Port, [int]$Seconds = 20)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $socket = [System.Net.Sockets.UdpClient]::new(
            [System.Net.Sockets.AddressFamily]::InterNetwork
        )
        try {
            $socket.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, $Port))
            return
        } catch { Start-Sleep -Milliseconds 100 }
        finally { $socket.Dispose() }
    }
    throw "UDP port $Port was not released."
}

function Wait-MetricAtLeast {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$Name,
        [uint64]$Minimum,
        [int]$Seconds = 45
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $metrics = Invoke-RestMethod -Uri "$BaseUrl/api/v1/metrics" -WebSession $Session
        if ([uint64]$metrics.$Name -ge $Minimum) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "Metric $Name did not reach $Minimum."
}

function Wait-UdpPolicyMetricAtLeast {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$PolicyId,
        [string]$Name,
        [uint64]$Minimum,
        [int]$Seconds = 45
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $policy = Get-UdpTunnel -BaseUrl $BaseUrl -Session $Session -PolicyId $PolicyId
        if ($null -ne $policy) {
            $property = $policy.PSObject.Properties[$Name]
            if ($null -ne $property -and [Convert]::ToUInt64($property.Value) -ge $Minimum) {
                return
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw "UDP policy metric $Name did not reach $Minimum."
}

function New-UdpSocket {
    $socket = [System.Net.Sockets.UdpClient]::new(
        [System.Net.Sockets.AddressFamily]::InterNetwork
    )
    $socket.Client.ReceiveBufferSize = 4 * 1024 * 1024
    $socket.Client.SendBufferSize = 4 * 1024 * 1024
    $socket.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0))
    return $socket
}

function Get-ByteHash {
    param([byte[]]$Payload)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha256.ComputeHash($Payload)).Replace('-', '') }
    finally { $sha256.Dispose() }
}

function Assert-BytesEqual {
    param([byte[]]$Expected, [byte[]]$Actual, [string]$Context)
    if ($Expected.Length -ne $Actual.Length -or
        (Get-ByteHash $Expected) -ne (Get-ByteHash $Actual)) {
        throw "$Context returned a corrupted or truncated UDP datagram."
    }
}

function Send-UdpAndReceive {
    param(
        [System.Net.Sockets.UdpClient]$Socket,
        [int]$Port,
        [byte[]]$Payload,
        [int]$TimeoutMilliseconds = 15000
    )
    $receive = $Socket.ReceiveAsync()
    $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $Port)
    $sent = $Socket.Send($Payload, $Payload.Length, $remote)
    if ($sent -ne $Payload.Length) { throw "UDP socket sent only $sent of $($Payload.Length) bytes." }
    if (-not $receive.Wait($TimeoutMilliseconds)) {
        throw "UDP echo timed out for a $($Payload.Length)-byte datagram."
    }
    return ,$receive.Result.Buffer
}

function Assert-NoUdpResponse {
    param([int]$Port, [byte[]]$Payload, [int]$TimeoutMilliseconds = 1500)
    $socket = New-UdpSocket
    try {
        $receive = $socket.ReceiveAsync()
        $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $Port)
        $null = $socket.Send($Payload, $Payload.Length, $remote)
        $completed = $false
        try {
            $completed = $receive.Wait($TimeoutMilliseconds)
        } catch [AggregateException] {
            # Windows maps ICMP Port Unreachable from a closed UDP port to
            # WSAECONNRESET/WSAECONNREFUSED, which means no application reply.
            $unexpected = @($_.Exception.Flatten().InnerExceptions | Where-Object {
                if ($_ -isnot [System.Net.Sockets.SocketException]) { return $true }
                return ($_.SocketErrorCode -ne [System.Net.Sockets.SocketError]::ConnectionReset -and $_.SocketErrorCode -ne [System.Net.Sockets.SocketError]::ConnectionRefused)
            })
            if ($unexpected.Count -ne 0) { throw }
            return
        }
        if ($completed) {
            throw "UDP port $Port unexpectedly returned a datagram."
        }
    } finally { $socket.Dispose() }
}

function Wait-Observation {
    param([string]$Hash, [int]$MinimumCount = 1, [int]$Seconds = 10)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $records = @(Get-Content -LiteralPath $observationPath -ErrorAction SilentlyContinue |
            ForEach-Object {
                try { $_ | ConvertFrom-Json } catch { $null }
            } | Where-Object { $_.event -eq 'datagram' -and $_.sha256 -eq $Hash })
        if ($records.Count -ge $MinimumCount) { return $records }
        Start-Sleep -Milliseconds 100
    }
    throw "UDP echo observation $Hash did not reach count $MinimumCount."
}

function New-TestPayload {
    param([int]$Length, [int]$Seed)
    $payload = [byte[]]::new($Length)
    [Random]::new($Seed).NextBytes($payload)
    return ,$payload
}

function New-TestCertificates {
    # Use the locked rcgen dependency so the test does not require system OpenSSL.
    $local:generatorRoot = [IO.Path]::Combine($script:runRoot, 'cert-generator')
    $local:sourceRoot = [IO.Path]::Combine($local:generatorRoot, 'src')
    New-Item -ItemType Directory -Force -Path $local:sourceRoot | Out-Null
    [IO.File]::WriteAllText(([IO.Path]::Combine($local:generatorRoot, 'Cargo.toml')), @"
[package]
name = "linklake-udp-e2e-cert-generator"
version = "0.0.0"
edition = "2021"

[dependencies]
rcgen = "=0.14.8"
"@, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(([IO.Path]::Combine($local:sourceRoot, 'main.rs')), @'
use rcgen::generate_simple_self_signed;
use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let output = PathBuf::from(env::args().nth(1).ok_or("missing output directory")?);
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()])?;
    fs::write(output.join("udp-e2e.cert.pem"), certified.cert.pem())?;
    fs::write(
        output.join("udp-e2e.key.pem"),
        certified.signing_key.serialize_pem(),
    )?;
    Ok(())
}
'@, [Text.UTF8Encoding]::new($false))
    & cargo run --quiet --offline --manifest-path `
        ([IO.Path]::Combine($local:generatorRoot, 'Cargo.toml')) `
        --target-dir ([IO.Path]::Combine($script:targetRoot, 'cert-generator')) -- $script:runRoot
    if ($LASTEXITCODE -ne 0) { throw 'The rcgen UDP E2E certificate generator failed.' }
    $local:certificate = [IO.Path]::Combine($script:runRoot, 'udp-e2e.cert.pem')
    $local:privateKey = [IO.Path]::Combine($script:runRoot, 'udp-e2e.key.pem')
    if (-not (Test-Path -LiteralPath $certificate) -or -not (Test-Path -LiteralPath $privateKey)) {
        throw 'The UDP E2E certificate generator did not write its output.'
    }
    return [pscustomobject]@{
        Root = $local:certificate
        Chain = $local:certificate
        Key = $local:privateKey
    }
}

New-Item -ItemType Directory -Path $runRoot | Out-Null
$testFailed = $false
try {
    if (-not $SkipBuild) {
        $previousTarget = $env:CARGO_TARGET_DIR
        try {
            $env:CARGO_TARGET_DIR = $targetRoot
            & cargo build --workspace
            if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
        } finally { $env:CARGO_TARGET_DIR = $previousTarget }
    }
    if (-not (Test-Path -LiteralPath $serverPath) -or -not (Test-Path -LiteralPath $clientPath)) {
        throw 'UDP E2E binaries do not exist. Run without -SkipBuild first.'
    }
    $shellPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $certificates = New-TestCertificates

    $managementPort = Get-FreeTcpPort
    $controlPort = Get-FreeTcpPort
    $relayPort = Get-FreeUdpPort
    $targetUdpPort = Get-FreeUdpPort
    $targetTcpPort = Get-FreeTcpPort
    $usedTunnelPorts = [Collections.Generic.HashSet[int]]::new()
    $sharedPublicPort = Get-FreeTunnelPort -UsedPorts $usedTunnelPorts
    $limitedPublicPort = Get-FreeTunnelPort -UsedPorts $usedTunnelPorts
    $baseUrl = "http://127.0.0.1:$managementPort"
    $enrollmentToken = [guid]::NewGuid().ToString()
    $adminPassword = 'LinkLake-UDP-E2E-Password-123!'
    $dataDirectory = Join-Path $runRoot 'data'

    $udpEchoProcess = Start-LoggedProcess -Name 'udp-echo' -FilePath $shellPath -Arguments @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $echoScriptPath,
        '-Port', $targetUdpPort, '-ObservationPath', $observationPath
    )
    Wait-EchoReady

    $tcpEchoScript = @"
`$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $targetTcpPort)
`$listener.Start()
try {
    while (`$true) {
        `$client = `$listener.AcceptTcpClient()
        try {
            `$stream = `$client.GetStream()
            `$buffer = [byte[]]::new(16384)
            while ((`$read = `$stream.Read(`$buffer, 0, `$buffer.Length)) -gt 0) {
                `$stream.Write(`$buffer, 0, `$read)
                `$stream.Flush()
            }
        } finally { `$client.Dispose() }
    }
} finally { `$listener.Stop() }
"@
    $tcpEchoEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($tcpEchoScript))
    $tcpEchoProcess = Start-LoggedProcess -Name 'tcp-echo' -FilePath $shellPath -Arguments @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $tcpEchoEncoded
    )
    Wait-TcpPort -Port $targetTcpPort

    $serverProcess = Start-LoggedProcess -Name 'server' -FilePath $serverPath -Environment @{
        LINKLAKE_BIND = "127.0.0.1:$managementPort"
        LINKLAKE_CONTROL_BIND = "127.0.0.1:$controlPort"
        LINKLAKE_UDP_RELAY_BIND = "127.0.0.1:$relayPort"
        LINKLAKE_UDP_RELAY_ENDPOINT = "127.0.0.1:$relayPort"
        LINKLAKE_UDP_RELAY_SERVER_NAME = 'localhost'
        LINKLAKE_CONTROL_CERT_PATH = $certificates.Chain
        LINKLAKE_CONTROL_KEY_PATH = $certificates.Key
        LINKLAKE_ENROLLMENT_TOKEN = $enrollmentToken
        LINKLAKE_DATA_DIR = $dataDirectory
        LINKLAKE_ADMIN_USERNAME = 'admin'
        LINKLAKE_ADMIN_PASSWORD = $adminPassword
        RUST_LOG = 'linklake_server=debug,quinn=debug,info'
    }
    Wait-HttpHealth -BaseUrl $baseUrl

    $platform = if ($env:OS -eq 'Windows_NT') { 'windows' } else { 'linux' }
    $enrollment = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'udp-e2e-client'; platform = $platform } | ConvertTo-Json)
    $login = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/login" `
        -SessionVariable webSession -ContentType 'application/json' `
        -Body (@{ username = 'admin'; password = $adminPassword } | ConvertTo-Json)
    if (-not $login.expires_unix_seconds) { throw 'Administrator login failed.' }

    $mainPolicy = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/udp-tunnels" `
        -WebSession $webSession -ContentType 'application/json' -Body (@{
            client_id = $enrollment.client_id
            name = 'udp-e2e-main'
            public_port = $sharedPublicPort
            target_addr = "127.0.0.1:$targetUdpPort"
            max_sessions = 16
            session_idle_timeout_seconds = 30
            bandwidth_limit_bps = $null
        } | ConvertTo-Json)
    $limitedPolicy = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/udp-tunnels" `
        -WebSession $webSession -ContentType 'application/json' -Body (@{
            client_id = $enrollment.client_id
            name = 'udp-e2e-limit'
            public_port = $limitedPublicPort
            target_addr = "127.0.0.1:$targetUdpPort"
            max_sessions = 1
            session_idle_timeout_seconds = 30
            bandwidth_limit_bps = $null
        } | ConvertTo-Json)
    $tcpPolicy = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tcp-tunnels" `
        -WebSession $webSession -ContentType 'application/json' -Body (@{
            client_id = $enrollment.client_id
            name = 'udp-e2e-shared-port-tcp'
            public_port = $sharedPublicPort
            target_addr = "127.0.0.1:$targetTcpPort"
            max_connections = 4
            bandwidth_limit_bps = $null
        } | ConvertTo-Json)

    $clientConfigPath = Join-Path $runRoot 'client.toml'
    $clientConfig = @"
[[udp_tunnels]]
name = "udp-e2e-main"
control = "127.0.0.1:$controlPort"
control_ca_cert = "$($certificates.Root.Replace('\', '\\'))"
control_server_name = "localhost"
client_id = "$($enrollment.client_id)"
client_token = "$($enrollment.client_token)"
public_port = $sharedPublicPort
target = "127.0.0.1:$targetUdpPort"

[[udp_tunnels]]
name = "udp-e2e-limit"
control = "127.0.0.1:$controlPort"
control_ca_cert = "$($certificates.Root.Replace('\', '\\'))"
control_server_name = "localhost"
client_id = "$($enrollment.client_id)"
client_token = "$($enrollment.client_token)"
public_port = $limitedPublicPort
target = "127.0.0.1:$targetUdpPort"

[[tcp_tunnels]]
name = "udp-e2e-shared-port-tcp"
control = "127.0.0.1:$controlPort"
control_ca_cert = "$($certificates.Root.Replace('\', '\\'))"
control_server_name = "localhost"
client_id = "$($enrollment.client_id)"
client_token = "$($enrollment.client_token)"
public_port = $sharedPublicPort
target = "127.0.0.1:$targetTcpPort"
"@
    [IO.File]::WriteAllText($clientConfigPath, $clientConfig, [Text.UTF8Encoding]::new($false))
    $clientProcess = Start-LoggedProcess -Name 'client' -FilePath $clientPath `
        -Arguments @('run', '--config', $clientConfigPath) -Environment @{
            LINKLAKE_LOG_DIR = (Join-Path $runRoot 'client-logs')
            RUST_LOG = 'linklake_client=debug,quinn=debug,info'
        }

    Wait-UdpTunnelState -BaseUrl $baseUrl -Session $webSession -PolicyId $mainPolicy.id -Online $true
    Wait-UdpTunnelState -BaseUrl $baseUrl -Session $webSession -PolicyId $limitedPolicy.id -Online $true
    Wait-TcpTunnelOnline -BaseUrl $baseUrl -Session $webSession -PolicyId $tcpPolicy.id -Online $true
    $baselineMetrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    $limitedPolicyBeforeIdle = Get-UdpTunnel -BaseUrl $baseUrl -Session $webSession -PolicyId $limitedPolicy.id
    if ($null -eq $limitedPolicyBeforeIdle) {
        throw 'The limited UDP policy disappeared before its idle-recovery check.'
    }
    $limitedSessionTimeoutBaseline = [Convert]::ToUInt64($limitedPolicyBeforeIdle.session_timeouts)

    $sizeSocket = New-UdpSocket
    $expectedMinimumBytes = 0L
    try {
        foreach ($size in @(0, 1, 1200, 1472, 4096, 32768, 60000, 65507)) {
            $payload = New-TestPayload -Length $size -Seed (20260730 + $size)
            $response = Send-UdpAndReceive -Socket $sizeSocket -Port $sharedPublicPort -Payload $payload
            Assert-BytesEqual -Expected $payload -Actual $response -Context "$size-byte echo"
            $expectedMinimumBytes += $size
        }
    } finally { $sizeSocket.Dispose() }

    $mappingSockets = [Collections.Generic.List[System.Net.Sockets.UdpClient]]::new()
    $firstPayloads = [Collections.Generic.List[byte[]]]::new()
    $secondPayloads = [Collections.Generic.List[byte[]]]::new()
    try {
        for ($index = 0; $index -lt 4; $index++) {
            $mappingSockets.Add((New-UdpSocket))
            $firstPayloads.Add([Text.Encoding]::UTF8.GetBytes("mapping-$index-first"))
            $secondPayloads.Add([Text.Encoding]::UTF8.GetBytes("mapping-$index-second"))
        }
        $receiveTasks = @()
        for ($index = 0; $index -lt 4; $index++) {
            $receiveTasks += $mappingSockets[$index].ReceiveAsync()
        }
        for ($index = 0; $index -lt 4; $index++) {
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $sharedPublicPort)
            $null = $mappingSockets[$index].Send(
                $firstPayloads[$index], $firstPayloads[$index].Length, $remote
            )
        }
        for ($index = 0; $index -lt 4; $index++) {
            if (-not $receiveTasks[$index].Wait(10000)) { throw "Concurrent UDP socket $index timed out." }
            Assert-BytesEqual -Expected $firstPayloads[$index] `
                -Actual $receiveTasks[$index].Result.Buffer -Context "concurrent socket $index"
            $response = Send-UdpAndReceive -Socket $mappingSockets[$index] `
                -Port $sharedPublicPort -Payload $secondPayloads[$index]
            Assert-BytesEqual -Expected $secondPayloads[$index] -Actual $response `
                -Context "mapping repeat $index"
        }
        $targetPorts = [Collections.Generic.HashSet[int]]::new()
        for ($index = 0; $index -lt 4; $index++) {
            $firstRecords = Wait-Observation -Hash (Get-ByteHash $firstPayloads[$index])
            $secondRecords = Wait-Observation -Hash (Get-ByteHash $secondPayloads[$index])
            $firstPort = [int]$firstRecords[-1].remote_port
            $secondPort = [int]$secondRecords[-1].remote_port
            if ($firstPort -ne $secondPort) {
                throw "UDP source mapping for socket $index was not stable."
            }
            if (-not $targetPorts.Add($firstPort)) {
                throw 'Two public UDP sockets were mapped onto the same target-side source port.'
            }
        }
    } finally {
        foreach ($socket in $mappingSockets) { $socket.Dispose() }
    }

    $limitedFirst = New-UdpSocket
    try {
        $first = [Text.Encoding]::UTF8.GetBytes('limit-first')
        $response = Send-UdpAndReceive -Socket $limitedFirst -Port $limitedPublicPort -Payload $first
        Assert-BytesEqual -Expected $first -Actual $response -Context 'first limited session'
        Assert-NoUdpResponse -Port $limitedPublicPort `
            -Payload ([Text.Encoding]::UTF8.GetBytes('limit-rejected'))
        $again = [Text.Encoding]::UTF8.GetBytes('limit-first-again')
        $response = Send-UdpAndReceive -Socket $limitedFirst -Port $limitedPublicPort -Payload $again
        Assert-BytesEqual -Expected $again -Actual $response -Context 'existing limited session'
    } finally { $limitedFirst.Dispose() }
    # max_sessions=1 时，第一个公网源地址在完整 30 秒空闲后才应释放配额；
    # 仅在该策略的超时计数相对基线增长后，才允许新的 UDP socket 建立会话。
    Write-Host 'Waiting for the 30-second UDP session idle timeout before testing permit recovery.'
    Wait-UdpPolicyMetricAtLeast -BaseUrl $baseUrl -Session $webSession `
        -PolicyId $limitedPolicy.id -Name 'session_timeouts' `
        -Minimum ([uint64]($limitedSessionTimeoutBaseline + 1)) -Seconds 50
    $afterIdle = New-UdpSocket
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes('limit-after-idle-recovery')
        $response = Send-UdpAndReceive -Socket $afterIdle -Port $limitedPublicPort -Payload $payload
        Assert-BytesEqual -Expected $payload -Actual $response -Context 'session permit after idle'
    } finally { $afterIdle.Dispose() }

    $tcp = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $sharedPublicPort)
    try {
        $tcpPayload = [Text.Encoding]::UTF8.GetBytes('same-numbered-tcp-and-udp-port')
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 10000
        $stream.Write($tcpPayload, 0, $tcpPayload.Length)
        $tcpResponse = [byte[]]::new($tcpPayload.Length)
        $offset = 0
        while ($offset -lt $tcpResponse.Length) {
            $read = $stream.Read($tcpResponse, $offset, $tcpResponse.Length - $offset)
            if ($read -eq 0) { throw 'Shared-port TCP echo closed early.' }
            $offset += $read
        }
        Assert-BytesEqual -Expected $tcpPayload -Actual $tcpResponse -Context 'shared-port TCP'
    } finally { $tcp.Dispose() }

    $probeOutput = Join-Path $runRoot 'udp-probe-result.json'
    & $shellPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $probeScriptPath `
        -HostName '127.0.0.1' -Port $sharedPublicPort -Count 50 -PacketsPerSecond 100 `
        -MinimumDeliveryRatio 1.0 -PayloadBytes 512 -TimeoutSeconds 5 -OutputPath $probeOutput
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $probeOutput)) {
        throw 'The standalone UDP probe failed.'
    }

    Stop-LoggedProcess $clientProcess -Verify
    $clientProcess = $null
    Wait-UdpTunnelState -BaseUrl $baseUrl -Session $webSession -PolicyId $mainPolicy.id -Online $false
    Wait-UdpTunnelState -BaseUrl $baseUrl -Session $webSession -PolicyId $limitedPolicy.id -Online $false
    Wait-TcpTunnelOnline -BaseUrl $baseUrl -Session $webSession -PolicyId $tcpPolicy.id -Online $false
    Assert-NoUdpResponse -Port $sharedPublicPort `
        -Payload ([Text.Encoding]::UTF8.GetBytes('client-stopped'))

    $clientProcess = Start-LoggedProcess -Name 'client-restarted' -FilePath $clientPath `
        -Arguments @('run', '--config', $clientConfigPath) -Environment @{
            LINKLAKE_LOG_DIR = (Join-Path $runRoot 'client-restarted-logs')
            RUST_LOG = 'linklake_client=debug,quinn=debug,info'
        }
    Wait-UdpTunnelState -BaseUrl $baseUrl -Session $webSession -PolicyId $mainPolicy.id -Online $true
    Wait-UdpTunnelState -BaseUrl $baseUrl -Session $webSession -PolicyId $limitedPolicy.id -Online $true
    Wait-TcpTunnelOnline -BaseUrl $baseUrl -Session $webSession -PolicyId $tcpPolicy.id -Online $true
    $reconnectSocket = New-UdpSocket
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes('client-reconnected')
        $response = Send-UdpAndReceive -Socket $reconnectSocket -Port $sharedPublicPort -Payload $payload
        Assert-BytesEqual -Expected $payload -Actual $response -Context 'reconnected UDP client'
    } finally { $reconnectSocket.Dispose() }

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/udp-tunnels/$($mainPolicy.id)/enabled" `
        -WebSession $webSession -ContentType 'application/json' -Body '{"enabled":false}'
    Wait-UdpTunnelState -BaseUrl $baseUrl -Session $webSession -PolicyId $mainPolicy.id -Online $false
    Wait-UdpPortAvailable -Port $sharedPublicPort
    Assert-NoUdpResponse -Port $sharedPublicPort `
        -Payload ([Text.Encoding]::UTF8.GetBytes('policy-disabled'))
    Wait-TcpTunnelOnline -BaseUrl $baseUrl -Session $webSession -PolicyId $tcpPolicy.id -Online $true

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/udp-tunnels/$($mainPolicy.id)/enabled" `
        -WebSession $webSession -ContentType 'application/json' -Body '{"enabled":true}'
    Wait-UdpTunnelState -BaseUrl $baseUrl -Session $webSession -PolicyId $mainPolicy.id -Online $true
    $enabledSocket = New-UdpSocket
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes('policy-enabled-again')
        $response = Send-UdpAndReceive -Socket $enabledSocket -Port $sharedPublicPort -Payload $payload
        Assert-BytesEqual -Expected $payload -Actual $response -Context 're-enabled UDP policy'
    } finally { $enabledSocket.Dispose() }

    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if ([uint64]$metrics.udp_packets_from_public -lt [uint64]$baselineMetrics.udp_packets_from_public + 8 -or
        [uint64]$metrics.udp_packets_to_public -lt [uint64]$baselineMetrics.udp_packets_to_public + 8 -or
        [uint64]$metrics.udp_bytes_from_public -lt [uint64]$baselineMetrics.udp_bytes_from_public + [uint64]$expectedMinimumBytes -or
        [uint64]$metrics.udp_bytes_to_public -lt [uint64]$baselineMetrics.udp_bytes_to_public + [uint64]$expectedMinimumBytes) {
        throw 'UDP packet or byte metrics did not increase as expected.'
    }
    if ([uint64]$metrics.udp_dropped_policy_session_limit -lt
        [uint64]$baselineMetrics.udp_dropped_policy_session_limit + 1) {
        throw 'UDP policy session-limit drop metric did not increase.'
    }
    if ([uint64]$metrics.tunnel_reconnects_total -lt
        [uint64]$baselineMetrics.tunnel_reconnects_total + 1) {
        throw 'Tunnel reconnect metric did not increase after restarting the client.'
    }
    $mainView = Get-UdpTunnel -BaseUrl $baseUrl -Session $webSession -PolicyId $mainPolicy.id
    $limitedView = Get-UdpTunnel -BaseUrl $baseUrl -Session $webSession -PolicyId $limitedPolicy.id
    if ([uint64]$mainView.packets_from_public -lt 8 -or [uint64]$mainView.packets_to_public -lt 8) {
        throw 'Per-policy UDP packet metrics were not updated.'
    }
    if ([uint64]$limitedView.dropped_policy_session_limit -lt 1) {
        throw 'Per-policy UDP session-limit metric was not updated.'
    }

    Invoke-RestMethod -Method Delete -Uri "$baseUrl/api/v1/udp-tunnels/$($mainPolicy.id)" `
        -WebSession $webSession
    Wait-UdpTunnelState -BaseUrl $baseUrl -Session $webSession -PolicyId $mainPolicy.id `
        -Online $false -Present $false
    Wait-UdpPortAvailable -Port $sharedPublicPort
    Assert-NoUdpResponse -Port $sharedPublicPort `
        -Payload ([Text.Encoding]::UTF8.GetBytes('policy-deleted'))
    Wait-TcpTunnelOnline -BaseUrl $baseUrl -Session $webSession -PolicyId $tcpPolicy.id -Online $true

    Invoke-RestMethod -Method Delete -Uri "$baseUrl/api/v1/udp-tunnels/$($limitedPolicy.id)" `
        -WebSession $webSession
    Wait-UdpTunnelState -BaseUrl $baseUrl -Session $webSession -PolicyId $limitedPolicy.id `
        -Online $false -Present $false
    Write-Host 'UDP E2E passed: boundaries, multi-session isolation, mapping stability, limits, lifecycle, reconnect, metrics, probe, and shared TCP/UDP port.'
} catch {
    $testFailed = $true
    Write-FailureDiagnostics
    throw
} finally {
    Stop-LoggedProcess $clientProcess
    Stop-LoggedProcess $serverProcess
    Stop-LoggedProcess $udpEchoProcess
    Stop-LoggedProcess $tcpEchoProcess
    if (-not $testFailed) {
        for ($attempt = 0; $attempt -lt 10 -and (Test-Path -LiteralPath $runRoot); $attempt++) {
            try { Remove-Item -LiteralPath $runRoot -Recurse -Force }
            catch {
                if ($attempt -eq 9) { throw }
                Start-Sleep -Milliseconds 200
            }
        }
    }
}
