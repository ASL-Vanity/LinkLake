param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target\e2e'
$serverPath = Join-Path $targetRoot 'debug\linklake-server.exe'
$clientPath = Join-Path $targetRoot 'debug\linklake-client.exe'
$runRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('linklake-e2e-' + [guid]::NewGuid())
$serverProcess = $null
$clientProcess = $null
$echoProcess = $null
$fakeControl = $null

function Get-FreePort {
    param([int]$Minimum = 0, [int]$Maximum = 0)
    if ($Minimum -eq 0) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $listener.Stop()
        return $port
    }
    foreach ($candidate in ($Minimum..$Maximum | Sort-Object { Get-Random })) {
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $candidate)
            $listener.Start()
            $listener.Stop()
            return $candidate
        } catch {
            continue
        }
    }
    throw "No free port is available in $Minimum-$Maximum."
}

function Wait-HttpHealth {
    param([string]$BaseUrl)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri "$BaseUrl/api/v1/health" -TimeoutSec 2
            if ($health.status -eq 'ok') { return }
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    throw 'The LinkLake management endpoint did not become healthy.'
}

function Wait-TcpPort {
    param([int]$Port, [int]$Seconds = 20)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $connection = [System.Net.Sockets.TcpClient]::new()
        try {
            $connection.Connect('127.0.0.1', $Port)
            $connection.Dispose()
            return
        } catch {
            $connection.Dispose()
            Start-Sleep -Milliseconds 200
        }
    }
    throw "TCP port $Port did not become reachable."
}

function Wait-TunnelOnline {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$PolicyId
    )
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) {
        $policies = Invoke-RestMethod -Uri "$BaseUrl/api/v1/tcp-tunnels" -WebSession $Session
        $current = $policies | Where-Object { $_.id -eq $PolicyId }
        if ($current.online) { return }
        Start-Sleep -Milliseconds 200
    }
    throw 'The TCP tunnel did not become online.'
}

function Wait-TunnelOffline {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$PolicyId
    )
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) {
        $policies = Invoke-RestMethod -Uri "$BaseUrl/api/v1/tcp-tunnels" -WebSession $Session
        $current = $policies | Where-Object { $_.id -eq $PolicyId }
        if (-not $current.online) { return }
        Start-Sleep -Milliseconds 200
    }
    throw 'The TCP tunnel did not become offline.'
}

function Wait-ActiveConnections {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [int]$Expected
    )
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        $metrics = Invoke-RestMethod -Uri "$BaseUrl/api/v1/metrics" -WebSession $Session
        if ($metrics.tcp_active_connections -eq $Expected) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "Active TCP connection count did not become $Expected."
}

function Start-HiddenProcess {
    param(
        [string]$FilePath,
        [string[]]$Arguments = @()
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments -join ' '
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    return [System.Diagnostics.Process]::Start($startInfo)
}

function Write-ControlFrame {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [hashtable]$Frame
    )
    $payload = [Text.Encoding]::UTF8.GetBytes(($Frame | ConvertTo-Json -Compress))
    $header = [byte[]]::new(4)
    $header[0] = [byte](($payload.Length -shr 24) -band 255)
    $header[1] = [byte](($payload.Length -shr 16) -band 255)
    $header[2] = [byte](($payload.Length -shr 8) -band 255)
    $header[3] = [byte]($payload.Length -band 255)
    $Stream.Write($header, 0, $header.Length)
    $Stream.Write($payload, 0, $payload.Length)
    $Stream.Flush()
}

function Read-ExactBytes {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [int]$Length
    )
    $buffer = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($buffer, $offset, $Length - $offset)
        if ($read -eq 0) { throw 'The control connection closed unexpectedly.' }
        $offset += $read
    }
    return $buffer
}

function Read-ControlFrame {
    param([System.Net.Sockets.NetworkStream]$Stream)
    $header = Read-ExactBytes -Stream $Stream -Length 4
    $length = ([int]$header[0] -shl 24) -bor ([int]$header[1] -shl 16) `
        -bor ([int]$header[2] -shl 8) -bor [int]$header[3]
    $payload = Read-ExactBytes -Stream $Stream -Length $length
    return [Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json
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
    $publicPort = Get-FreePort -Minimum 32000 -Maximum 32999
    $baseUrl = "http://127.0.0.1:$managementPort"
    $enrollmentToken = [guid]::NewGuid().ToString()
    $adminPassword = 'LinkLake-E2E-Password-123!'

    $echoScript = @"
        `$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $targetPort)
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
                } finally {
                    `$client.Dispose()
                }
            }
        } finally {
            `$listener.Stop()
        }
"@
    $echoCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($echoScript))
    $echoProcess = Start-HiddenProcess -FilePath 'powershell.exe' -Arguments @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $echoCommand
    )
    Wait-TcpPort -Port $targetPort

    $oldEnvironment = @{
        LINKLAKE_BIND = $env:LINKLAKE_BIND
        LINKLAKE_CONTROL_BIND = $env:LINKLAKE_CONTROL_BIND
        LINKLAKE_ENROLLMENT_TOKEN = $env:LINKLAKE_ENROLLMENT_TOKEN
        LINKLAKE_DATA_DIR = $env:LINKLAKE_DATA_DIR
        LINKLAKE_ADMIN_USERNAME = $env:LINKLAKE_ADMIN_USERNAME
        LINKLAKE_ADMIN_PASSWORD = $env:LINKLAKE_ADMIN_PASSWORD
    }
    try {
        $env:LINKLAKE_BIND = "127.0.0.1:$managementPort"
        $env:LINKLAKE_CONTROL_BIND = "127.0.0.1:$controlPort"
        $env:LINKLAKE_ENROLLMENT_TOKEN = $enrollmentToken
        $env:LINKLAKE_DATA_DIR = Join-Path $runRoot 'data'
        $env:LINKLAKE_ADMIN_USERNAME = 'admin'
        $env:LINKLAKE_ADMIN_PASSWORD = $adminPassword
        $serverProcess = Start-HiddenProcess -FilePath $serverPath
    } finally {
        foreach ($entry in $oldEnvironment.GetEnumerator()) {
            if ($null -eq $entry.Value) {
                Remove-Item -Path "Env:$($entry.Key)" -ErrorAction SilentlyContinue
            } else {
                Set-Item -Path "Env:$($entry.Key)" -Value $entry.Value
            }
        }
    }

    Wait-HttpHealth -BaseUrl $baseUrl
    $enrollment = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'e2e-client'; platform = 'windows' } | ConvertTo-Json)
    $login = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/login" `
        -SessionVariable webSession -ContentType 'application/json' `
        -Body (@{ username = 'admin'; password = $adminPassword } | ConvertTo-Json)
    if (-not $login.expires_unix_seconds) { throw 'Administrator login failed.' }

    $policy = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tcp-tunnels" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body (@{
            client_id = $enrollment.client_id
            name = 'e2e-tcp'
            public_port = $publicPort
            target_addr = "127.0.0.1:$targetPort"
            max_connections = 8
            bandwidth_limit_bps = 1048576
        } | ConvertTo-Json)

    $clientArguments = @(
        'agent', '--control', "127.0.0.1:$controlPort",
        '--client-id', $enrollment.client_id, '--token', $enrollment.client_token,
        '--public-port', $publicPort, '--target', "127.0.0.1:$targetPort", '--name', 'e2e-tcp'
    )
    $clientProcess = Start-HiddenProcess -FilePath $clientPath -Arguments $clientArguments

    Wait-TunnelOnline -BaseUrl $baseUrl -Session $webSession -PolicyId $policy.id
    $payload = [byte[]]::new(262144)
    [Random]::new(20260728).NextBytes($payload)
    $tcp = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $publicPort)
    try {
        $tcp.ReceiveTimeout = 10000
        $tcp.SendTimeout = 10000
        $stream = $tcp.GetStream()
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $stream.Write($payload, 0, $payload.Length)
        $received = [byte[]]::new($payload.Length)
        $offset = 0
        while ($offset -lt $received.Length) {
            $read = $stream.Read($received, $offset, $received.Length - $offset)
            if ($read -eq 0) {
                Start-Sleep -Milliseconds 200
                $diagnostics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
                throw "The public TCP tunnel closed before returning the payload. Metrics: $($diagnostics | ConvertTo-Json -Compress)"
            }
            $offset += $read
        }
        $stopwatch.Stop()
        $sha256 = [Security.Cryptography.SHA256]::Create()
        if (-not [Convert]::ToBase64String($sha256.ComputeHash($received)).Equals(
            [Convert]::ToBase64String($sha256.ComputeHash($payload)))) {
            throw 'The TCP tunnel payload was corrupted.'
        }
        if ($stopwatch.ElapsedMilliseconds -lt 300) {
            throw "The configured aggregate bandwidth limit was not enforced ($($stopwatch.ElapsedMilliseconds) ms)."
        }
    } finally {
        $tcp.Dispose()
    }

    $loadResult = & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $PSScriptRoot 'tcp-load-probe.ps1') -Port $publicPort `
        -Connections 8 -BytesPerConnection 65536 -ChunkBytes 1024 -DelayMilliseconds 1
    if ($LASTEXITCODE -ne 0) { throw 'The concurrent weak-network TCP load probe failed.' }
    $loadSummary = $loadResult | ConvertFrom-Json
    if ($loadSummary.connections -ne 8 -or $loadSummary.round_trip_bytes -ne 1048576) {
        throw 'The concurrent TCP load probe returned an invalid summary.'
    }

    Start-Sleep -Milliseconds 300
    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if ($metrics.tcp_bytes_from_public -lt $payload.Length -or $metrics.tcp_bytes_to_public -lt $payload.Length) {
        throw 'TCP traffic metrics were not updated.'
    }

    $heldConnections = [System.Collections.Generic.List[System.Net.Sockets.TcpClient]]::new()
    try {
        1..8 | ForEach-Object {
            $heldConnections.Add([System.Net.Sockets.TcpClient]::new('127.0.0.1', $publicPort))
        }
        Wait-ActiveConnections -BaseUrl $baseUrl -Session $webSession -Expected 8
        $rejectedConnection = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $publicPort)
        try {
            $rejectedConnection.ReceiveTimeout = 3000
            $rejectedStream = $rejectedConnection.GetStream()
            $rejectedStream.WriteByte(1)
            try {
                if ($rejectedStream.ReadByte() -ge 0) {
                    throw 'A connection above the per-policy limit transferred data.'
                }
            } catch [System.IO.IOException] {
                # Expected: a connection above the policy limit is reset or closed.
            }
        } finally {
            $rejectedConnection.Dispose()
        }
    } finally {
        $heldConnections | ForEach-Object { $_.Dispose() }
    }
    Wait-ActiveConnections -BaseUrl $baseUrl -Session $webSession -Expected 0
    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if ($metrics.tcp_rejected_policy_limit -lt 1) {
        throw 'The per-policy connection rejection metric was not updated.'
    }

    Stop-Process -Id $clientProcess.Id -Force
    $clientProcess.WaitForExit()
    Wait-TunnelOffline -BaseUrl $baseUrl -Session $webSession -PolicyId $policy.id
    $clientProcess = Start-HiddenProcess -FilePath $clientPath -Arguments $clientArguments
    Wait-TunnelOnline -BaseUrl $baseUrl -Session $webSession -PolicyId $policy.id
    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if ($metrics.tunnel_reconnects_total -lt 1) {
        throw 'The tunnel reconnect metric was not updated.'
    }

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tcp-tunnels/$($policy.id)/enabled" `
        -WebSession $webSession -ContentType 'application/json' -Body '{"enabled":false}'
    Wait-TunnelOffline -BaseUrl $baseUrl -Session $webSession -PolicyId $policy.id
    $disabledConnection = [System.Net.Sockets.TcpClient]::new()
    try {
        $disabledConnection.Connect('127.0.0.1', $publicPort)
        throw 'The public port remained reachable after disabling the policy.'
    } catch [System.Net.Sockets.SocketException] {
        # Expected: disabling the policy closes the listener immediately.
    } finally {
        $disabledConnection.Dispose()
    }

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tcp-tunnels/$($policy.id)/enabled" `
        -WebSession $webSession -ContentType 'application/json' -Body '{"enabled":true}'
    Wait-TunnelOnline -BaseUrl $baseUrl -Session $webSession -PolicyId $policy.id

    try {
        Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/$($enrollment.client_id)/heartbeat" `
            -Headers @{ Authorization = 'Bearer invalid-e2e-token' }
        throw 'Invalid client authentication was unexpectedly accepted.'
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw }
    }
    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if ($metrics.authentication_failures_total -lt 1) {
        throw 'The authentication failure metric was not updated.'
    }

    Stop-Process -Id $clientProcess.Id -Force
    $clientProcess.WaitForExit()
    Wait-TunnelOffline -BaseUrl $baseUrl -Session $webSession -PolicyId $policy.id
    $fakeControl = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $controlPort)
    $fakeControl.ReceiveTimeout = 15000
    $fakeStream = $fakeControl.GetStream()
    Write-ControlFrame -Stream $fakeStream -Frame @{
        kind = 'register_tcp_tunnel'
        client_id = $enrollment.client_id
        client_token = $enrollment.client_token
        name = 'e2e-tcp'
        public_port = $publicPort
        target_addr = "127.0.0.1:$targetPort"
    }
    $registration = Read-ControlFrame -Stream $fakeStream
    if ($registration.kind -ne 'tcp_tunnel_registered') {
        throw 'The timeout test control tunnel was not registered.'
    }
    Wait-TunnelOnline -BaseUrl $baseUrl -Session $webSession -PolicyId $policy.id
    $timeoutConnection = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $publicPort)
    try {
        $timeoutConnection.ReceiveTimeout = 15000
        $timeoutStream = $timeoutConnection.GetStream()
        $timeoutStream.WriteByte(1)
        try {
            if ($timeoutStream.ReadByte() -ge 0) {
                throw 'An unpaired public connection unexpectedly transferred data.'
            }
        } catch [System.IO.IOException] {
            # Expected: the server resets an unpaired connection after the timeout.
        }
    } finally {
        $timeoutConnection.Dispose()
    }
    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if ($metrics.tcp_pairing_timeouts -lt 1) {
        throw 'The TCP pairing timeout metric was not updated.'
    }

    Write-Host "TCP E2E passed: echo, bandwidth, limits, reconnect, policy lifecycle, timeout, metrics."
} finally {
    if ($fakeControl) { $fakeControl.Dispose() }
    foreach ($process in @($clientProcess, $serverProcess, $echoProcess)) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            $null = $process.WaitForExit(5000)
        }
    }
    for ($attempt = 0; $attempt -lt 10 -and (Test-Path -LiteralPath $runRoot); $attempt++) {
        try { Remove-Item -LiteralPath $runRoot -Recurse -Force }
        catch {
            if ($attempt -eq 9) { throw }
            Start-Sleep -Milliseconds 200
        }
    }
}
