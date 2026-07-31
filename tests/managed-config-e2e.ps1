param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target\e2e'
$serverPath = Join-Path $targetRoot 'debug\linklake-server.exe'
$clientPath = Join-Path $targetRoot 'debug\linklake-client.exe'
$runRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('linklake-managed-e2e-' + [guid]::NewGuid())
$serverProcess = $null
$clientProcess = $null
$echoProcess = $null

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

function Start-HiddenProcess {
    param([string]$FilePath, [string[]]$Arguments = @())
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments -join ' '
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    return [System.Diagnostics.Process]::Start($startInfo)
}

function Wait-ForCondition {
    param([scriptblock]$Condition, [string]$Failure, [int]$Seconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $result = & $Condition
            if ($result) { return }
        } catch {
            # Transient read failures are expected while services start or files are replaced.
        }
        Start-Sleep -Milliseconds 200
    }
    throw $Failure
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
    $managementToken = [guid]::NewGuid().ToString()

    $echoScript = @"
        `$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $targetPort)
        `$listener.Start()
        try {
            while (`$true) {
                `$client = `$listener.AcceptTcpClient()
                try {
                    `$stream = `$client.GetStream()
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
    $echoProcess = Start-HiddenProcess -FilePath 'powershell.exe' -Arguments @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $echoCommand
    )

    $oldEnvironment = @{
        LINKLAKE_BIND = $env:LINKLAKE_BIND
        LINKLAKE_CONTROL_BIND = $env:LINKLAKE_CONTROL_BIND
        LINKLAKE_ENROLLMENT_TOKEN = $env:LINKLAKE_ENROLLMENT_TOKEN
        LINKLAKE_MANAGEMENT_TOKEN = $env:LINKLAKE_MANAGEMENT_TOKEN
        LINKLAKE_DATA_DIR = $env:LINKLAKE_DATA_DIR
        LINKLAKE_ADMIN_USERNAME = $env:LINKLAKE_ADMIN_USERNAME
        LINKLAKE_ADMIN_PASSWORD = $env:LINKLAKE_ADMIN_PASSWORD
    }
    try {
        $env:LINKLAKE_BIND = "127.0.0.1:$managementPort"
        $env:LINKLAKE_CONTROL_BIND = "127.0.0.1:$controlPort"
        $env:LINKLAKE_ENROLLMENT_TOKEN = $enrollmentToken
        $env:LINKLAKE_MANAGEMENT_TOKEN = $managementToken
        $env:LINKLAKE_DATA_DIR = Join-Path $runRoot 'data'
        $env:LINKLAKE_ADMIN_USERNAME = 'admin'
        $env:LINKLAKE_ADMIN_PASSWORD = 'Managed-E2E-Password-123!'
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

    Wait-ForCondition -Failure 'The LinkLake server did not become healthy.' -Condition {
        (Invoke-RestMethod -Uri "$baseUrl/api/v1/health" -TimeoutSec 2).status -eq 'ok'
    }
    $headers = @{ Authorization = "Bearer $managementToken" }
    $enrollment = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'managed-e2e'; platform = 'windows' } | ConvertTo-Json)
    $policy = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tcp-tunnels" `
        -Headers $headers -ContentType 'application/json' -Body (@{
            client_id = $enrollment.client_id
            name = 'managed-tcp'
            public_port = $publicPort
            target_addr = "127.0.0.1:$targetPort"
            max_connections = 8
        } | ConvertTo-Json)

    $managedPath = Join-Path $runRoot 'managed.toml'
    $bootstrapPath = Join-Path $runRoot 'client.toml'
    $managedTomlPath = $managedPath.Replace('\', '/')
    $bootstrap = @"
[client]
control = "127.0.0.1:$controlPort"
client_id = "$($enrollment.client_id)"
client_token = "$($enrollment.client_token)"
config_mode = "server_managed"
managed_config_path = "$managedTomlPath"
"@
    [IO.File]::WriteAllText($bootstrapPath, $bootstrap, [Text.UTF8Encoding]::new($false))
    $clientProcess = Start-HiddenProcess -FilePath $clientPath -Arguments @(
        'run', '--config', ('"' + $bootstrapPath + '"')
    )

    Wait-ForCondition -Failure 'The managed client did not synchronize.' -Condition {
        $client = Invoke-RestMethod -Uri "$baseUrl/api/v1/clients" -Headers $headers |
            Where-Object { $_.client_id -eq $enrollment.client_id }
        $client.config_mode -eq 'server_managed' -and
            $client.config_sync_status -eq 'synchronized' -and
            $client.applied_config_revision -like 'sha256:*'
    }
    Wait-ForCondition -Failure 'The managed TCP tunnel did not become online.' -Condition {
        $current = Invoke-RestMethod -Uri "$baseUrl/api/v1/tcp-tunnels" -Headers $headers |
            Where-Object { $_.id -eq $policy.id }
        $current.online
    }
    if (-not (Test-Path -LiteralPath $managedPath) -or
        -not (Test-Path -LiteralPath ($managedPath + '.backup'))) {
        throw 'Managed configuration and its last-known-good backup were not created.'
    }
    $managedContent = Get-Content -LiteralPath $managedPath -Raw
    if ($managedContent -notmatch 'managed-tcp' -or $managedContent -match [regex]::Escape($enrollment.client_token)) {
        throw 'Managed configuration is missing the policy or contains the client token.'
    }

    $tcp = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $publicPort)
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes('managed-configuration-e2e')
        $stream = $tcp.GetStream()
        $stream.Write($payload, 0, $payload.Length)
        $received = [byte[]]::new($payload.Length)
        $offset = 0
        while ($offset -lt $received.Length) {
            $read = $stream.Read($received, $offset, $received.Length - $offset)
            if ($read -eq 0) { throw 'The managed TCP echo closed early.' }
            $offset += $read
        }
        if ([Text.Encoding]::UTF8.GetString($received) -ne 'managed-configuration-e2e') {
            throw 'The managed TCP payload was corrupted.'
        }
    } finally {
        $tcp.Dispose()
    }

    [IO.File]::WriteAllText($managedPath, 'this is not valid = [', [Text.UTF8Encoding]::new($false))
    Wait-ForCondition -Failure 'The server did not repair a locally damaged managed configuration.' -Condition {
        $content = Get-Content -LiteralPath $managedPath -Raw
        $content -match 'revision = "sha256:' -and $content -match 'managed-tcp'
    }

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tcp-tunnels/$($policy.id)/enabled" `
        -Headers $headers -ContentType 'application/json' -Body '{"enabled":false}'
    Wait-ForCondition -Failure 'The managed tunnel did not stop after the Web UI policy was disabled.' -Condition {
        $current = Invoke-RestMethod -Uri "$baseUrl/api/v1/tcp-tunnels" -Headers $headers |
            Where-Object { $_.id -eq $policy.id }
        (-not $current.online) -and ((Get-Content -LiteralPath $managedPath -Raw) -match 'enabled = false')
    }

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tcp-tunnels/$($policy.id)/enabled" `
        -Headers $headers -ContentType 'application/json' -Body '{"enabled":true}'
    Wait-ForCondition -Failure 'The managed tunnel did not restart after the policy was enabled.' -Condition {
        $current = Invoke-RestMethod -Uri "$baseUrl/api/v1/tcp-tunnels" -Headers $headers |
            Where-Object { $_.id -eq $policy.id }
        $current.online
    }

    Write-Host 'Managed config E2E passed: delivery, persistence, secret isolation, repair, dynamic disable and re-enable.'
} finally {
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
