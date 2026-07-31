param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target\e2e'
$serverPath = Join-Path $targetRoot 'debug\linklake-server.exe'
$clientPath = Join-Path $targetRoot 'debug\linklake-client.exe'
$runRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('linklake-secret-e2e-' + [guid]::NewGuid())
$processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$clientLogCounter = 0

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Start-HiddenProcess {
    param([string]$FilePath, [string[]]$Arguments = @())
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments -join ' '
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($startInfo)
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

function Write-Utf8File {
    param([string]$Path, [string]$Content)
    [IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

function Start-Client {
    param([string]$ConfigPath)
    $script:clientLogCounter += 1
    $logDirectory = Join-Path $runRoot ("client-log-{0}" -f $script:clientLogCounter)
    $oldLogDirectory = $env:LINKLAKE_LOG_DIR
    try {
        $env:LINKLAKE_LOG_DIR = $logDirectory
        $process = Start-HiddenProcess -FilePath $clientPath -Arguments @(
            'run', '--config', ('"' + $ConfigPath + '"')
        )
    } finally {
        if ($null -eq $oldLogDirectory) { Remove-Item Env:LINKLAKE_LOG_DIR -ErrorAction SilentlyContinue }
        else { $env:LINKLAKE_LOG_DIR = $oldLogDirectory }
    }
    $process | Add-Member -NotePropertyName LinkLakeLogDirectory -NotePropertyValue $logDirectory
    return $process
}

function Write-ClientLogs {
    param([System.Diagnostics.Process]$Process)
    if ($Process.LinkLakeLogDirectory -and (Test-Path -LiteralPath $Process.LinkLakeLogDirectory)) {
        Get-ChildItem -LiteralPath $Process.LinkLakeLogDirectory -File | ForEach-Object {
            Write-Host "--- $($_.FullName) ---"
            Get-Content -LiteralPath $_.FullName -Raw
        }
    }
}

function Invoke-Echo {
    param([int]$Port, [string]$Message)
    $tcp = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $Port)
    try {
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 45000
        $payload = [Text.Encoding]::UTF8.GetBytes($Message)
        $stream.Write($payload, 0, $payload.Length)
        $received = [byte[]]::new($payload.Length)
        $offset = 0
        while ($offset -lt $received.Length) {
            $read = $stream.Read($received, $offset, $received.Length - $offset)
            if ($read -eq 0) { throw 'The secret tunnel echo connection closed early.' }
            $offset += $read
        }
        if ([Text.Encoding]::UTF8.GetString($received) -ne $Message) {
            throw 'The secret tunnel echo payload was corrupted.'
        }
    } finally {
        $tcp.Dispose()
    }
}

function Assert-ConnectionRejected {
    param([int]$Port, [string]$Failure)
    $tcp = [System.Net.Sockets.TcpClient]::new()
    try {
        $tcp.Connect('127.0.0.1', $Port)
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 5000
        $probe = [Text.Encoding]::UTF8.GetBytes('must-be-rejected')
        try {
            $stream.Write($probe, 0, $probe.Length)
            $buffer = [byte[]]::new(1)
            $read = $stream.Read($buffer, 0, 1)
            if ($read -gt 0) { throw $Failure }
        } catch [System.IO.IOException] {
            return
        } catch [System.Net.Sockets.SocketException] {
            return
        }
    } catch [System.Net.Sockets.SocketException] {
        return
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
    $visitorPort = Get-FreePort
    $wrongKeyPort = Get-FreePort
    $deniedPort = Get-FreePort
    $p2pPort = Get-FreePort
    $baseUrl = "http://127.0.0.1:$managementPort"
    $enrollmentToken = [guid]::NewGuid().ToString()
    $managementToken = [guid]::NewGuid().ToString()

    $echoScript = @"
        `$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $targetPort)
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

    $environmentNames = @(
        'LINKLAKE_BIND', 'LINKLAKE_CONTROL_BIND', 'LINKLAKE_ENROLLMENT_TOKEN',
        'LINKLAKE_MANAGEMENT_TOKEN', 'LINKLAKE_DATA_DIR', 'LINKLAKE_ADMIN_USERNAME',
        'LINKLAKE_ADMIN_PASSWORD', 'LINKLAKE_HTTP_BIND', 'LINKLAKE_HTTPS_BIND'
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
        $env:LINKLAKE_ADMIN_PASSWORD = 'Secret-E2E-Password-123!'
        Remove-Item Env:LINKLAKE_HTTP_BIND -ErrorAction SilentlyContinue
        Remove-Item Env:LINKLAKE_HTTPS_BIND -ErrorAction SilentlyContinue
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
    $provider = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'secret-provider'; platform = 'windows' } | ConvertTo-Json)
    $visitor = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'secret-visitor'; platform = 'windows' } | ConvertTo-Json)
    $deniedVisitor = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'secret-denied-visitor'; platform = 'windows' } | ConvertTo-Json)

    $policy = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/secret-tunnels" `
        -Headers $headers -ContentType 'application/json' -Body (@{
            provider_client_id = $provider.client_id
            allowed_client_id = $visitor.client_id
            name = 'private-echo'
            target_addr = "127.0.0.1:$targetPort"
            max_connections = 1
        } | ConvertTo-Json)
    if ($policy.access_key -notmatch '^lls_[0-9a-f]{64}$') {
        throw 'The created secret access key has an invalid format.'
    }
    $listedJson = Invoke-RestMethod -Uri "$baseUrl/api/v1/secret-tunnels" -Headers $headers | ConvertTo-Json -Depth 8
    if ($listedJson -match 'access_key' -or $listedJson -match [regex]::Escape($policy.access_key)) {
        throw 'The one-time secret access key leaked through the list API.'
    }

    $providerManagedPath = Join-Path $runRoot 'provider-managed.toml'
    $providerConfigPath = Join-Path $runRoot 'provider.toml'
    $providerManagedTomlPath = $providerManagedPath.Replace('\', '/')
    Write-Utf8File -Path $providerConfigPath -Content @"
[client]
control = "127.0.0.1:$controlPort"
client_id = "$($provider.client_id)"
client_token = "$($provider.client_token)"
config_mode = "server_managed"
managed_config_path = "$providerManagedTomlPath"
p2p_bind = "127.0.0.1:$p2pPort"
p2p_endpoint = "127.0.0.1:$p2pPort"
p2p_tcp_enabled = false
p2p_iroh_enabled = true
"@

    $wrongAccessKey = 'lls_' + ('b' * 64)
    $visitorConfigPath = Join-Path $runRoot 'visitor.toml'
    Write-Utf8File -Path $visitorConfigPath -Content @"
[client]
control = "127.0.0.1:$controlPort"
client_id = "$($visitor.client_id)"
client_token = "$($visitor.client_token)"

[[secret_visitors]]
name = "allowed-access"
local_bind = "127.0.0.1:$visitorPort"
access_key = "$($policy.access_key)"

[[secret_visitors]]
name = "wrong-key"
local_bind = "127.0.0.1:$wrongKeyPort"
access_key = "$wrongAccessKey"
"@

    $deniedConfigPath = Join-Path $runRoot 'denied.toml'
    Write-Utf8File -Path $deniedConfigPath -Content @"
[client]
control = "127.0.0.1:$controlPort"
client_id = "$($deniedVisitor.client_id)"
client_token = "$($deniedVisitor.client_token)"

[[secret_visitors]]
name = "denied-access"
local_bind = "127.0.0.1:$deniedPort"
access_key = "$($policy.access_key)"
"@

    $providerProcess = Start-Client -ConfigPath $providerConfigPath
    $visitorProcess = Start-Client -ConfigPath $visitorConfigPath
    Start-Client -ConfigPath $deniedConfigPath | Out-Null

    Wait-ForCondition -Failure 'The managed provider did not synchronize its secret target.' -Condition {
        $currentClient = Invoke-RestMethod -Uri "$baseUrl/api/v1/clients" -Headers $headers |
            Where-Object { $_.client_id -eq $provider.client_id }
        $currentClient.config_sync_status -eq 'synchronized' -and
            (Get-Content -LiteralPath $providerManagedPath -Raw) -match 'private-echo'
    }
    Wait-ForCondition -Failure 'The secret tunnel provider did not become online.' -Condition {
        $current = Invoke-RestMethod -Uri "$baseUrl/api/v1/secret-tunnels" -Headers $headers |
            Where-Object { $_.id -eq $policy.id }
        $current.online
    }
    try {
        Wait-ForCondition -Seconds 60 -Failure 'The provider did not register its P2P candidate.' -Condition {
            $nodes = @(Invoke-RestMethod -Uri "$baseUrl/api/v1/p2p/nodes" -Headers $headers)
            $node = $nodes | Where-Object { $_.client_id -eq $provider.client_id }
            $irohCandidate = @($node.candidates) | Where-Object { $_.transport -eq 'iroh_quic' } |
                Select-Object -First 1
            if (-not $node -or $node.fresh -ne $true -or $node.age_seconds -gt 120 -or
                -not $irohCandidate) {
                return $false
            }
            $irohAddress = $irohCandidate.endpoint | ConvertFrom-Json
            $irohAddress.endpoint_id -match '^[0-9a-f]{64}$' -and
                @($irohAddress.direct_addresses).Count -ge 1
        }
    } catch {
        try {
            Write-Host '--- P2P node API snapshot ---'
            Invoke-RestMethod -Uri "$baseUrl/api/v1/p2p/nodes" -Headers $headers |
                ConvertTo-Json -Depth 10 | Write-Host
        } catch {}
        Write-ClientLogs -Process $providerProcess
        throw
    }
    Wait-ForCondition -Failure 'The local secret visitor listeners did not start.' -Condition {
        $ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort
        $ports -contains $visitorPort -and $ports -contains $wrongKeyPort -and $ports -contains $deniedPort
    }

    $serverListeners = Get-NetTCPConnection -State Listen -OwningProcess $serverProcess.Id -ErrorAction Stop |
        Select-Object -ExpandProperty LocalPort -Unique
    $unexpectedListeners = @($serverListeners | Where-Object { $_ -notin @($managementPort, $controlPort) })
    if ($unexpectedListeners.Count -ne 0) {
        throw "Secret tunnel unexpectedly opened public server listener(s): $($unexpectedListeners -join ', ')."
    }

    Invoke-Echo -Port $visitorPort -Message 'secret-tunnel-e2e'
    Wait-ForCondition -Failure 'The direct P2P connection metric was not updated.' -Condition {
        (Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -Headers $headers).p2p_direct_connections_total -ge 1
    }

    Stop-Process -Id $providerProcess.Id -Force
    $null = $providerProcess.WaitForExit(5000)
    Write-Utf8File -Path $providerConfigPath -Content @"
[client]
control = "127.0.0.1:$controlPort"
client_id = "$($provider.client_id)"
client_token = "$($provider.client_token)"
config_mode = "server_managed"
managed_config_path = "$providerManagedTomlPath"
p2p_bind = "127.0.0.1:$p2pPort"
p2p_endpoint = "127.0.0.1:$p2pPort"
p2p_tcp_enabled = true
p2p_iroh_enabled = false
"@
    $providerProcess = Start-Client -ConfigPath $providerConfigPath
    Wait-ForCondition -Seconds 60 -Failure 'The TCP Noise P2P provider did not become ready.' -Condition {
        $nodes = @(Invoke-RestMethod -Uri "$baseUrl/api/v1/p2p/nodes" -Headers $headers)
        $node = $nodes | Where-Object { $_.client_id -eq $provider.client_id }
        $tcpCandidate = @($node.candidates) | Where-Object { $_.transport -eq 'tcp' } |
            Select-Object -First 1
        $node -and $node.fresh -eq $true -and $tcpCandidate -and
            $tcpCandidate.endpoint -eq "127.0.0.1:$p2pPort"
    }
    Invoke-Echo -Port $visitorPort -Message 'secret-tunnel-tcp-noise'
    Wait-ForCondition -Failure 'The TCP Noise direct P2P metric was not updated.' -Condition {
        (Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -Headers $headers).p2p_direct_connections_total -ge 2
    }

    Stop-Process -Id $providerProcess.Id -Force
    $null = $providerProcess.WaitForExit(5000)
    Write-Utf8File -Path $providerConfigPath -Content @"
[client]
control = "127.0.0.1:$controlPort"
client_id = "$($provider.client_id)"
client_token = "$($provider.client_token)"
config_mode = "server_managed"
managed_config_path = "$providerManagedTomlPath"
"@
    $providerProcess = Start-Client -ConfigPath $providerConfigPath
    Wait-ForCondition -Failure 'The relay provider did not recover after removing the direct listener.' -Condition {
        $current = Invoke-RestMethod -Uri "$baseUrl/api/v1/secret-tunnels" -Headers $headers |
            Where-Object { $_.id -eq $policy.id }
        $current.online
    }
    Invoke-Echo -Port $visitorPort -Message 'secret-tunnel-relay-fallback'
    Wait-ForCondition -Failure 'The explicit relay fallback metric was not updated.' -Condition {
        (Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -Headers $headers).p2p_relay_fallbacks_total -ge 1
    }
    $p2pMetrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -Headers $headers
    if ($p2pMetrics.p2p_session_offers_total -lt 3) {
        throw 'P2P session offers were not counted for Iroh, TCP Noise, and fallback attempts.'
    }

    # 已验证自动回退后，后续授权、连接上限和生命周期用例明确走服务端中继。
    # 服务端会短期保留旧 P2P 候选；若继续优先直连，失效 Iroh 候选的正常拨号超时
    # 会让这些用例测到候选过期等待，而不是它们真正要验证的中继行为。
    Stop-Process -Id $visitorProcess.Id -Force
    $null = $visitorProcess.WaitForExit(5000)
    Write-Utf8File -Path $visitorConfigPath -Content @"
[client]
control = "127.0.0.1:$controlPort"
client_id = "$($visitor.client_id)"
client_token = "$($visitor.client_token)"

[[secret_visitors]]
name = "allowed-access"
local_bind = "127.0.0.1:$visitorPort"
access_key = "$($policy.access_key)"
prefer_direct = false

[[secret_visitors]]
name = "wrong-key"
local_bind = "127.0.0.1:$wrongKeyPort"
access_key = "$wrongAccessKey"
"@
    $visitorProcess = Start-Client -ConfigPath $visitorConfigPath
    Wait-ForCondition -Failure 'The relay-only secret visitor listeners did not restart.' -Condition {
        $ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty LocalPort
        $ports -contains $visitorPort -and $ports -contains $wrongKeyPort
    }

    Assert-ConnectionRejected -Port $wrongKeyPort -Failure 'A wrong secret key was accepted.'
    Assert-ConnectionRejected -Port $deniedPort -Failure 'A disallowed visitor client was accepted.'

    $held = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $visitorPort)
    try {
        $heldStream = $held.GetStream()
        $heldStream.ReadTimeout = 15000
        $heldPayload = [Text.Encoding]::UTF8.GetBytes('held')
        $heldStream.Write($heldPayload, 0, $heldPayload.Length)
        $heldResponse = [byte[]]::new($heldPayload.Length)
        $heldOffset = 0
        while ($heldOffset -lt $heldResponse.Length) {
            $heldRead = $heldStream.Read(
                $heldResponse, $heldOffset, $heldResponse.Length - $heldOffset
            )
            if ($heldRead -eq 0) {
                throw 'The held secret tunnel connection closed before echoing all bytes.'
            }
            $heldOffset += $heldRead
        }
        for ($index = 0; $index -lt $heldPayload.Length; $index++) {
            if ($heldPayload[$index] -ne $heldResponse[$index]) {
                throw 'The held secret tunnel connection returned corrupted bytes.'
            }
        }
        Wait-ForCondition -Failure 'The active secret connection was not reported.' -Condition {
            $current = Invoke-RestMethod -Uri "$baseUrl/api/v1/secret-tunnels" -Headers $headers |
                Where-Object { $_.id -eq $policy.id }
            $current.active_connections -eq 1
        }
        Assert-ConnectionRejected -Port $visitorPort -Failure 'The secret tunnel connection limit was not enforced.'

        Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/secret-tunnels/$($policy.id)/enabled" `
            -Headers $headers -ContentType 'application/json' -Body '{"enabled":false}'
        Wait-ForCondition -Failure 'The secret tunnel did not stop after being disabled.' -Condition {
            $current = Invoke-RestMethod -Uri "$baseUrl/api/v1/secret-tunnels" -Headers $headers |
                Where-Object { $_.id -eq $policy.id }
            (-not $current.online) -and $current.active_connections -eq 0
        }
        Assert-ConnectionRejected -Port $visitorPort -Failure 'A disabled secret tunnel accepted a connection.'
    } finally {
        $held.Dispose()
    }

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/secret-tunnels/$($policy.id)/enabled" `
        -Headers $headers -ContentType 'application/json' -Body '{"enabled":true}'
    Wait-ForCondition -Failure 'The secret tunnel did not recover after being re-enabled.' -Condition {
        $current = Invoke-RestMethod -Uri "$baseUrl/api/v1/secret-tunnels" -Headers $headers |
            Where-Object { $_.id -eq $policy.id }
        $current.online
    }
    Invoke-Echo -Port $visitorPort -Message 'secret-tunnel-reenabled'

    $statistics = Invoke-RestMethod -Uri "$baseUrl/api/v1/secret-tunnels" -Headers $headers |
        Where-Object { $_.id -eq $policy.id }
    if ($statistics.connections_total -lt 3 -or $statistics.rejected_connections -lt 1 -or
        $statistics.bytes_from_visitor -lt 1 -or $statistics.bytes_to_visitor -lt 1) {
        throw 'Secret tunnel statistics were not updated as expected.'
    }

    Invoke-RestMethod -Method Delete -Uri "$baseUrl/api/v1/secret-tunnels/$($policy.id)" -Headers $headers
    Wait-ForCondition -Failure 'The deleted secret tunnel policy remained visible.' -Condition {
        $remaining = @(Invoke-RestMethod -Uri "$baseUrl/api/v1/secret-tunnels" -Headers $headers)
        -not ($remaining | Where-Object { $_.id -eq $policy.id })
    }
    Assert-ConnectionRejected -Port $visitorPort -Failure 'A deleted secret tunnel accepted a connection.'

    Write-Host 'Secret tunnel E2E passed: managed target, one-time key isolation, local visitor, authorization, limits, lifecycle, statistics, and no public business listener.'
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
        (Split-Path -Leaf $resolvedRunRoot).StartsWith('linklake-secret-e2e-')) {
        for ($attempt = 0; $attempt -lt 10 -and (Test-Path -LiteralPath $resolvedRunRoot); $attempt++) {
            try { Remove-Item -LiteralPath $resolvedRunRoot -Recurse -Force }
            catch {
                if ($attempt -eq 9) { throw }
                Start-Sleep -Milliseconds 200
            }
        }
    }
}
