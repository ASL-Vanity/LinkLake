param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target\e2e'
$serverPath = Join-Path $targetRoot 'debug\linklake-server.exe'
$clientPath = Join-Path $targetRoot 'debug\linklake-client.exe'
$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('linklake-socks5-e2e-' + [guid]::NewGuid())
$processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$stage = 'initialization'

function Get-FreePort {
    param([int]$Minimum = 0, [int]$Maximum = 0)
    if ($Minimum -eq 0) {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
        finally { $listener.Stop() }
    }
    foreach ($candidate in ($Minimum..$Maximum | Sort-Object { Get-Random })) {
        try {
            $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, $candidate)
            $listener.Start()
            $listener.Stop()
            return $candidate
        } catch {}
    }
    throw "No free port is available in $Minimum-$Maximum."
}

function Get-FreeUdpPort {
    $socket = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $socket.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
        return ([Net.IPEndPoint]$socket.Client.LocalEndPoint).Port
    } finally { $socket.Dispose() }
}

function New-TestCertificates {
    $generatorRoot = Join-Path $runRoot 'cert-generator'
    $sourceRoot = Join-Path $generatorRoot 'src'
    New-Item -ItemType Directory -Force -Path $sourceRoot | Out-Null
    [IO.File]::WriteAllText((Join-Path $generatorRoot 'Cargo.toml'), @"
[package]
name = "linklake-socks5-udp-e2e-cert-generator"
version = "0.0.0"
edition = "2021"

[dependencies]
rcgen = "=0.14.8"
"@, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $sourceRoot 'main.rs'), @'
use rcgen::generate_simple_self_signed;
use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let output = PathBuf::from(env::args().nth(1).ok_or("missing output directory")?);
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()])?;
    fs::write(output.join("socks5-e2e.cert.pem"), certified.cert.pem())?;
    fs::write(output.join("socks5-e2e.key.pem"), certified.signing_key.serialize_pem())?;
    Ok(())
}
'@, [Text.UTF8Encoding]::new($false))
    & cargo run --quiet --offline --manifest-path (Join-Path $generatorRoot 'Cargo.toml') `
        --target-dir (Join-Path $targetRoot 'cert-generator') -- $runRoot
    if ($LASTEXITCODE -ne 0) { throw 'The SOCKS5 E2E certificate generator failed.' }
    return [pscustomobject]@{
        Root = Join-Path $runRoot 'socks5-e2e.cert.pem'
        Chain = Join-Path $runRoot 'socks5-e2e.cert.pem'
        Key = Join-Path $runRoot 'socks5-e2e.key.pem'
    }
}

function Start-HiddenProcess {
    param([string]$FilePath, [string[]]$Arguments = @())
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments -join ' '
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($startInfo)
    $processes.Add($process)
    return $process
}

function Wait-ForCondition {
    param([scriptblock]$Condition, [string]$Failure, [int]$Seconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $result = & $Condition
            if ($result) { return }
        } catch {}
        Start-Sleep -Milliseconds 200
    }
    throw $Failure
}

function Read-Exact {
    param([IO.Stream]$Stream, [int]$Length)
    $buffer = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        try { $read = $Stream.Read($buffer, $offset, $Length - $offset) }
        catch { throw "SOCKS5 read failed during ${script:stage}: $($_.Exception.Message)" }
        if ($read -eq 0) { throw 'The SOCKS5 connection closed early.' }
        $offset += $read
    }
    return ,$buffer
}

function Write-Bytes {
    param([IO.Stream]$Stream, [byte[]]$Bytes)
    $Stream.Write($Bytes, 0, $Bytes.Length)
    $Stream.Flush()
}

function Open-Socks5Connection {
    param(
        [int]$ProxyPort,
        [string]$Username,
        [string]$Password,
        [string]$TargetHost,
        [int]$TargetPort,
        [byte]$Command = 1
    )
    $tcp = [Net.Sockets.TcpClient]::new('127.0.0.1', $ProxyPort)
    try {
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 12000
        Write-Bytes -Stream $stream -Bytes ([byte[]](5, 1, 2))
        $method = Read-Exact -Stream $stream -Length 2
        if ($method[0] -ne 5 -or $method[1] -ne 2) { throw 'SOCKS5 username/password negotiation failed.' }

        $usernameBytes = [Text.Encoding]::ASCII.GetBytes($Username)
        $passwordBytes = [Text.Encoding]::ASCII.GetBytes($Password)
        $auth = [Collections.Generic.List[byte]]::new()
        $auth.Add(1)
        $auth.Add([byte]$usernameBytes.Length)
        $auth.AddRange($usernameBytes)
        $auth.Add([byte]$passwordBytes.Length)
        $auth.AddRange($passwordBytes)
        Write-Bytes -Stream $stream -Bytes $auth.ToArray()
        $authReply = Read-Exact -Stream $stream -Length 2
        if ($authReply[0] -ne 1 -or $authReply[1] -ne 0) { throw 'SOCKS5 authentication failed.' }

        $request = [Collections.Generic.List[byte]]::new()
        $request.Add(5)
        $request.Add($Command)
        $request.Add(0)
        $targetAddress = $null
        if ([Net.IPAddress]::TryParse($TargetHost, [ref]$targetAddress)) {
            if ($targetAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
                $request.Add(4)
            } else {
                $request.Add(1)
            }
            $request.AddRange($targetAddress.GetAddressBytes())
        } else {
            $hostBytes = [Text.Encoding]::ASCII.GetBytes($TargetHost)
            $request.Add(3)
            $request.Add([byte]$hostBytes.Length)
            $request.AddRange($hostBytes)
        }
        $request.Add([byte](($TargetPort -shr 8) -band 255))
        $request.Add([byte]($TargetPort -band 255))
        Write-Bytes -Stream $stream -Bytes $request.ToArray()
        $replyHeader = Read-Exact -Stream $stream -Length 4
        $boundAddressLength = switch ($replyHeader[3]) {
            1 { 4 }
            4 { 16 }
            3 {
                $domainLength = Read-Exact -Stream $stream -Length 1
                [int]$domainLength[0]
            }
            default { throw "SOCKS5 returned unsupported address type $($replyHeader[3])." }
        }
        $boundAddressBytes = Read-Exact -Stream $stream -Length $boundAddressLength
        $boundPortBytes = Read-Exact -Stream $stream -Length 2
        $boundAddress = if ($replyHeader[3] -eq 3) {
            [Text.Encoding]::ASCII.GetString($boundAddressBytes)
        } else {
            ([Net.IPAddress]::new($boundAddressBytes)).ToString()
        }
        return [pscustomobject]@{
            Client = $tcp
            Stream = $stream
            Reply = $replyHeader[1]
            BoundAddressType = $replyHeader[3]
            BoundAddress = $boundAddress
            BoundPort = ([int]$boundPortBytes[0] -shl 8) -bor [int]$boundPortBytes[1]
        }
    } catch {
        $tcp.Dispose()
        throw
    }
}

function Assert-WrongPasswordRejected {
    param([int]$ProxyPort, [string]$Username)
    $tcp = [Net.Sockets.TcpClient]::new('127.0.0.1', $ProxyPort)
    try {
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 5000
        Write-Bytes -Stream $stream -Bytes ([byte[]](5, 1, 2))
        $null = Read-Exact -Stream $stream -Length 2
        $usernameBytes = [Text.Encoding]::ASCII.GetBytes($Username)
        $wrongPassword = [Text.Encoding]::ASCII.GetBytes(('llp_' + ('0' * 64)))
        $auth = [Collections.Generic.List[byte]]::new()
        $auth.Add(1)
        $auth.Add([byte]$usernameBytes.Length)
        $auth.AddRange($usernameBytes)
        $auth.Add([byte]$wrongPassword.Length)
        $auth.AddRange($wrongPassword)
        Write-Bytes -Stream $stream -Bytes $auth.ToArray()
        $reply = Read-Exact -Stream $stream -Length 2
        if ($reply[1] -eq 0) { throw 'The SOCKS5 proxy accepted a wrong password.' }
    } finally {
        $tcp.Dispose()
    }
}

function Assert-NoAuthRejected {
    param([int]$ProxyPort)
    $tcp = [Net.Sockets.TcpClient]::new('127.0.0.1', $ProxyPort)
    try {
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 5000
        Write-Bytes -Stream $stream -Bytes ([byte[]](5, 1, 0))
        $reply = Read-Exact -Stream $stream -Length 2
        if ($reply[0] -ne 5 -or $reply[1] -ne 255) {
            throw 'The SOCKS5 proxy did not reject unauthenticated mode.'
        }
    } finally {
        $tcp.Dispose()
    }
}

New-Item -ItemType Directory -Path $runRoot | Out-Null
try {
    if (-not $SkipBuild) {
        $previousTarget = $env:CARGO_TARGET_DIR
        try {
            $env:CARGO_TARGET_DIR = $targetRoot
            & cargo build --workspace
            if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
        } finally {
            $env:CARGO_TARGET_DIR = $previousTarget
        }
    }
    if (-not (Test-Path -LiteralPath $serverPath) -or -not (Test-Path -LiteralPath $clientPath)) {
        throw 'The E2E binaries do not exist. Run without -SkipBuild first.'
    }

    $managementPort = Get-FreePort
    $controlPort = Get-FreePort
    $targetPort = Get-FreePort
    $udpTargetPort = Get-FreeUdpPort
    $relayPort = Get-FreeUdpPort
    $proxyPort = Get-FreePort -Minimum 32000 -Maximum 32999
    $baseUrl = "http://127.0.0.1:$managementPort"
    $enrollmentToken = [guid]::NewGuid().ToString()
    $managementToken = [guid]::NewGuid().ToString()
    $certificates = New-TestCertificates

    $echoScript = @"
`$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $targetPort)
`$listener.Start()
try {
    while (`$true) {
        `$client = `$listener.AcceptTcpClient()
        `$stream = `$client.GetStream()
        try {
            `$buffer = [byte[]]::new(4096)
            while ((`$read = `$stream.Read(`$buffer, 0, `$buffer.Length)) -gt 0) {
                `$stream.Write(`$buffer, 0, `$read)
                `$stream.Flush()
            }
        } finally {
            `$client.Dispose()
        }
    }
} finally {
    `$listener.Stop()
}
"@
    $echoCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($echoScript))
    Start-HiddenProcess -FilePath 'powershell.exe' -Arguments @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $echoCommand
    ) | Out-Null
    $udpObservationPath = Join-Path $runRoot 'udp-observations.jsonl'
    Start-HiddenProcess -FilePath 'powershell.exe' -Arguments @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
        ('"' + (Join-Path $PSScriptRoot 'udp-echo-service.ps1') + '"'),
        '-Port', $udpTargetPort, '-ObservationPath', ('"' + $udpObservationPath + '"')
    ) | Out-Null

    $environmentNames = @(
        'LINKLAKE_BIND', 'LINKLAKE_CONTROL_BIND', 'LINKLAKE_ENROLLMENT_TOKEN',
        'LINKLAKE_MANAGEMENT_TOKEN', 'LINKLAKE_DATA_DIR', 'LINKLAKE_ADMIN_USERNAME',
        'LINKLAKE_ADMIN_PASSWORD', 'LINKLAKE_UDP_RELAY_BIND',
        'LINKLAKE_UDP_RELAY_ENDPOINT', 'LINKLAKE_UDP_RELAY_SERVER_NAME',
        'LINKLAKE_UDP_PUBLIC_BIND_MODE', 'LINKLAKE_CONTROL_CERT_PATH',
        'LINKLAKE_CONTROL_KEY_PATH'
    )
    $oldEnvironment = @{}
    foreach ($name in $environmentNames) { $oldEnvironment[$name] = [Environment]::GetEnvironmentVariable($name) }
    try {
        $env:LINKLAKE_BIND = "127.0.0.1:$managementPort"
        $env:LINKLAKE_CONTROL_BIND = "127.0.0.1:$controlPort"
        $env:LINKLAKE_ENROLLMENT_TOKEN = $enrollmentToken
        $env:LINKLAKE_MANAGEMENT_TOKEN = $managementToken
        $env:LINKLAKE_DATA_DIR = Join-Path $runRoot 'data'
        $env:LINKLAKE_ADMIN_USERNAME = 'admin'
        $env:LINKLAKE_ADMIN_PASSWORD = 'Socks5-E2E-Password-123!'
        $env:LINKLAKE_UDP_RELAY_BIND = "127.0.0.1:$relayPort"
        $env:LINKLAKE_UDP_RELAY_ENDPOINT = "127.0.0.1:$relayPort"
        $env:LINKLAKE_UDP_RELAY_SERVER_NAME = 'localhost'
        $env:LINKLAKE_UDP_PUBLIC_BIND_MODE = 'dual_stack_required'
        $env:LINKLAKE_CONTROL_CERT_PATH = $certificates.Chain
        $env:LINKLAKE_CONTROL_KEY_PATH = $certificates.Key
        $serverProcess = Start-HiddenProcess -FilePath $serverPath
    } finally {
        foreach ($name in $environmentNames) {
            if ($null -eq $oldEnvironment[$name]) { Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue }
            else { Set-Item -Path "Env:$name" -Value $oldEnvironment[$name] }
        }
    }

    Wait-ForCondition -Failure 'The LinkLake server did not become healthy.' -Condition {
        (Invoke-RestMethod -Uri "$baseUrl/api/v1/health" -TimeoutSec 2).status -eq 'ok'
    }
    $headers = @{ Authorization = "Bearer $managementToken" }
    $enrollment = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'socks5-exit'; platform = 'windows' } | ConvertTo-Json)
    $created = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/socks5-proxies" `
        -Headers $headers -ContentType 'application/json' -Body (@{
            client_id = $enrollment.client_id
            name = 'office-exit'
            public_port = $proxyPort
            username = 'linklake-user'
            max_connections = 1
        } | ConvertTo-Json)
    if ($created.password -notmatch '^llp_[0-9a-f]{64}$') {
        throw 'The generated SOCKS5 password has an invalid format.'
    }
    $listedJson = Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers | ConvertTo-Json -Depth 8
    if ($listedJson -match 'password' -or $listedJson -match [regex]::Escape($created.password)) {
        throw 'The one-time SOCKS5 password leaked through the list API.'
    }

    $managedPath = Join-Path $runRoot 'managed.toml'
    $configPath = Join-Path $runRoot 'client.toml'
    $managedTomlPath = $managedPath.Replace('\', '/')
    [IO.File]::WriteAllText($configPath, @"
[client]
control = "127.0.0.1:$controlPort"
control_ca_cert = "$($certificates.Root.Replace('\', '\\'))"
control_server_name = "localhost"
client_id = "$($enrollment.client_id)"
client_token = "$($enrollment.client_token)"
config_mode = "server_managed"
managed_config_path = "$managedTomlPath"
"@, [Text.UTF8Encoding]::new($false))
    Start-HiddenProcess -FilePath $clientPath -Arguments @('run', '--config', ('"' + $configPath + '"')) | Out-Null

    Wait-ForCondition -Failure 'The managed SOCKS5 client did not synchronize.' -Condition {
        $client = Invoke-RestMethod -Uri "$baseUrl/api/v1/clients" -Headers $headers |
            Where-Object { $_.client_id -eq $enrollment.client_id }
        $client.config_sync_status -eq 'synchronized' -and
            (Get-Content -LiteralPath $managedPath -Raw) -match 'office-exit'
    }
    Wait-ForCondition -Failure 'The SOCKS5 proxy did not become online.' -Condition {
        $proxy = Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers |
            Where-Object { $_.id -eq $created.id }
        $proxy.online
    }

    $stage = 'no-auth rejection'
    Assert-NoAuthRejected -ProxyPort $proxyPort
    $stage = 'wrong-password rejection'
    Assert-WrongPasswordRejected -ProxyPort $proxyPort -Username $created.username

    $stage = 'domain CONNECT'
    $connection = Open-Socks5Connection -ProxyPort $proxyPort -Username $created.username `
        -Password $created.password -TargetHost 'localhost' -TargetPort $targetPort
    try {
        if ($connection.Reply -ne 0) { throw "SOCKS5 CONNECT failed with reply $($connection.Reply)." }
        $payload = [Text.Encoding]::UTF8.GetBytes('socks5-domain-echo')
        Write-Bytes -Stream $connection.Stream -Bytes $payload
        $received = Read-Exact -Stream $connection.Stream -Length $payload.Length
        if ([Text.Encoding]::UTF8.GetString($received) -ne 'socks5-domain-echo') {
            throw 'The SOCKS5 payload was corrupted.'
        }

        Wait-ForCondition -Failure 'The active SOCKS5 connection was not reported.' -Condition {
            $proxy = Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers |
                Where-Object { $_.id -eq $created.id }
            $proxy.active_connections -eq 1
        }
        $limited = [Net.Sockets.TcpClient]::new('127.0.0.1', $proxyPort)
        try {
            $limited.GetStream().ReadTimeout = 3000
            Write-Bytes -Stream $limited.GetStream() -Bytes ([byte[]](5, 1, 2))
            try {
                $read = $limited.GetStream().ReadByte()
                if ($read -ge 0) { throw 'The SOCKS5 connection limit was not enforced.' }
            } catch [IO.IOException] {}
        } finally {
            $limited.Dispose()
        }
    } finally {
        $connection.Client.Dispose()
    }
    Wait-ForCondition -Failure 'The completed SOCKS5 connection did not release its policy permit.' -Condition {
        $proxy = Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers |
            Where-Object { $_.id -eq $created.id }
        $proxy.active_connections -eq 0
    }

    $stage = 'BIND rejection'
    $unsupported = Open-Socks5Connection -ProxyPort $proxyPort -Username $created.username `
        -Password $created.password -TargetHost 'localhost' -TargetPort $targetPort -Command 2
    try {
        if ($unsupported.Reply -ne 7) { throw 'SOCKS5 BIND was not rejected with reply 7.' }
    } finally {
        $unsupported.Client.Dispose()
    }

    $stage = 'disable policy'
    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/socks5-proxies/$($created.id)/enabled" `
        -Headers $headers -ContentType 'application/json' -Body '{"enabled":false}'
    Wait-ForCondition -Failure 'The SOCKS5 proxy did not stop after being disabled.' -Condition {
        $proxy = Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers |
            Where-Object { $_.id -eq $created.id }
        -not $proxy.online
    }

    $stage = 're-enable policy'
    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/socks5-proxies/$($created.id)/enabled" `
        -Headers $headers -ContentType 'application/json' -Body '{"enabled":true}'
    Wait-ForCondition -Failure 'The SOCKS5 proxy did not recover after being re-enabled.' -Condition {
        $proxy = Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers |
            Where-Object { $_.id -eq $created.id }
        $proxy.online
    }
    $stage = 'IPv4 CONNECT after recovery'
    $recovered = Open-Socks5Connection -ProxyPort $proxyPort -Username $created.username `
        -Password $created.password -TargetHost '127.0.0.1' -TargetPort $targetPort
    try {
        if ($recovered.Reply -ne 0) { throw 'The recovered SOCKS5 proxy could not connect.' }
    } finally {
        $recovered.Client.Dispose()
    }
    Wait-ForCondition -Failure 'The recovered SOCKS5 connection did not release its policy permit.' -Condition {
        $proxy = Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers |
            Where-Object { $_.id -eq $created.id }
        $proxy.active_connections -eq 0
    }

    $stage = 'UDP ASSOCIATE'
    $udpAssociation = Open-Socks5Connection -ProxyPort $proxyPort -Username $created.username `
        -Password $created.password -TargetHost '0.0.0.0' -TargetPort 0 -Command 3
    $udpClient = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        if ($udpAssociation.Reply -ne 0) { throw 'SOCKS5 UDP ASSOCIATE was rejected.' }
        $udpClient.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
        $udpClient.Client.ReceiveTimeout = 10000
        $udpPayload = [Text.Encoding]::UTF8.GetBytes('socks5-udp-echo')
        $udpRequest = [Collections.Generic.List[byte]]::new()
        $udpRequest.AddRange([byte[]](0, 0, 0, 1, 127, 0, 0, 1))
        $udpRequest.Add([byte](($udpTargetPort -shr 8) -band 255))
        $udpRequest.Add([byte]($udpTargetPort -band 255))
        $udpRequest.AddRange($udpPayload)
        $relayEndpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $proxyPort)
        $sent = $udpClient.Send($udpRequest.ToArray(), $udpRequest.Count, $relayEndpoint)
        if ($sent -ne $udpRequest.Count) { throw 'The SOCKS5 UDP request was truncated.' }
        $responseSource = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
        $udpResponse = $udpClient.Receive([ref]$responseSource)
        if ($udpResponse.Length -lt 10 -or $udpResponse[0] -ne 0 -or $udpResponse[1] -ne 0 -or
            $udpResponse[2] -ne 0 -or $udpResponse[3] -ne 1) {
            throw 'The SOCKS5 UDP response header is invalid.'
        }
        $responsePayload = [byte[]]$udpResponse[10..($udpResponse.Length - 1)]
        if ([Text.Encoding]::UTF8.GetString($responsePayload) -ne 'socks5-udp-echo') {
            throw 'The SOCKS5 UDP response payload was corrupted.'
        }

        $fragmented = $udpRequest.ToArray()
        $fragmented[2] = 1
        $udpClient.Client.ReceiveTimeout = 1000
        $null = $udpClient.Send($fragmented, $fragmented.Length, $relayEndpoint)
        try {
            $unexpectedSource = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            $null = $udpClient.Receive([ref]$unexpectedSource)
            throw 'A fragmented SOCKS5 UDP datagram was forwarded.'
        } catch [Net.Sockets.SocketException] {}
    } finally {
        $udpClient.Dispose()
        $udpAssociation.Client.Dispose()
    }
    Wait-ForCondition -Failure 'The SOCKS5 UDP association did not close with its TCP control connection.' -Condition {
        $proxy = Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers |
            Where-Object { $_.id -eq $created.id }
        $proxy.udp_active_associations -eq 0
    }

    $stage = 'IPv6 UDP ASSOCIATE'
    $udpV6Client = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
    $udpV6Client.Client.DualMode = $false
    $udpV6Client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::IPv6Loopback, 0))
    $udpV6SourcePort = ([Net.IPEndPoint]$udpV6Client.Client.LocalEndPoint).Port
    $udpV6Association = Open-Socks5Connection -ProxyPort $proxyPort -Username $created.username `
        -Password $created.password -TargetHost '::1' -TargetPort $udpV6SourcePort -Command 3
    try {
        if ($udpV6Association.Reply -ne 0 -or $udpV6Association.BoundAddressType -ne 1 -or
            $udpV6Association.BoundAddress -ne '0.0.0.0' -or
            $udpV6Association.BoundPort -ne $proxyPort) {
            throw 'SOCKS5 IPv6 UDP ASSOCIATE did not advertise the server-side IPv4 control address family.'
        }
        $udpV6Client.Client.ReceiveTimeout = 10000
        $udpV6Payload = [Text.Encoding]::UTF8.GetBytes('socks5-udp-ipv6-transport')
        $udpV6Request = [Collections.Generic.List[byte]]::new()
        $udpV6Request.AddRange([byte[]](0, 0, 0, 1, 127, 0, 0, 1))
        $udpV6Request.Add([byte](($udpTargetPort -shr 8) -band 255))
        $udpV6Request.Add([byte]($udpTargetPort -band 255))
        $udpV6Request.AddRange($udpV6Payload)
        $ipv6RelayEndpoint = [Net.IPEndPoint]::new([Net.IPAddress]::IPv6Loopback, $proxyPort)
        $sent = $udpV6Client.Send($udpV6Request.ToArray(), $udpV6Request.Count, $ipv6RelayEndpoint)
        if ($sent -ne $udpV6Request.Count) { throw 'The SOCKS5 IPv6 UDP request was truncated.' }
        $responseSource = [Net.IPEndPoint]::new([Net.IPAddress]::IPv6Any, 0)
        $udpV6Response = $udpV6Client.Receive([ref]$responseSource)
        if ($responseSource.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6 -or
            $udpV6Response.Length -lt 10 -or $udpV6Response[0] -ne 0 -or
            $udpV6Response[1] -ne 0 -or $udpV6Response[2] -ne 0 -or $udpV6Response[3] -ne 1) {
            throw 'The SOCKS5 IPv6 UDP response header or transport family is invalid.'
        }
        $responsePayload = [byte[]]$udpV6Response[10..($udpV6Response.Length - 1)]
        if ([Text.Encoding]::UTF8.GetString($responsePayload) -ne 'socks5-udp-ipv6-transport') {
            throw 'The SOCKS5 IPv6 UDP response payload was corrupted.'
        }
    } finally {
        $udpV6Client.Dispose()
        $udpV6Association.Client.Dispose()
    }
    Wait-ForCondition -Failure 'The SOCKS5 IPv6 UDP association did not close with its TCP control connection.' -Condition {
        $proxy = Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers |
            Where-Object { $_.id -eq $created.id }
        $proxy.udp_active_associations -eq 0
    }

    $proxyStats = Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers |
        Where-Object { $_.id -eq $created.id }
    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -Headers $headers
    if ($proxyStats.requests_total -lt 2 -or $proxyStats.authentication_failures -lt 2 -or
        $proxyStats.unsupported_commands -lt 1 -or $metrics.socks5_requests_total -lt 2 -or
        $proxyStats.udp_datagrams_from_public -lt 2 -or $proxyStats.udp_datagrams_to_public -lt 2 -or
        $proxyStats.udp_dropped_datagrams -lt 1 -or $metrics.socks5_udp_datagrams_from_public -lt 1) {
        throw 'SOCKS5 policy or aggregate metrics were not updated as expected.'
    }
    if ([uint64]$metrics.udp_public_ipv6_bind_successes_total -lt 1 -or
        [uint64]$metrics.udp_public_ipv6_bind_fallbacks_total -ne 0) {
        throw 'The SOCKS5 required dual-stack UDP listener did not report a successful IPv6 bind.'
    }

    Invoke-RestMethod -Method Delete -Uri "$baseUrl/api/v1/socks5-proxies/$($created.id)" -Headers $headers
    Wait-ForCondition -Failure 'The deleted SOCKS5 policy remained visible.' -Condition {
        $remaining = @(Invoke-RestMethod -Uri "$baseUrl/api/v1/socks5-proxies" -Headers $headers)
        -not ($remaining | Where-Object { $_.id -eq $created.id })
    }

    Write-Host 'SOCKS5 TCP/UDP E2E passed: managed exit, one-time password, mandatory auth, CONNECT, IPv4/IPv6 UDP ASSOCIATE, fragmentation rejection, limits, lifecycle, and metrics.'
} finally {
    foreach ($process in $processes) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            $null = $process.WaitForExit(5000)
        }
    }
    $resolvedRunRoot = [IO.Path]::GetFullPath($runRoot)
    $resolvedTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolvedRunRoot.StartsWith($resolvedTempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedRunRoot).StartsWith('linklake-socks5-e2e-')) {
        for ($attempt = 0; $attempt -lt 10 -and (Test-Path -LiteralPath $resolvedRunRoot); $attempt++) {
            try { Remove-Item -LiteralPath $resolvedRunRoot -Recurse -Force }
            catch {
                if ($attempt -eq 9) { throw }
                Start-Sleep -Milliseconds 200
            }
        }
    }
}
