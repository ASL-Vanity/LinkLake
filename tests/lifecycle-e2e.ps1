param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
$PSDefaultParameterValues['Invoke-RestMethod:Headers'] = @{ 'X-LinkLake-CSRF' = '1' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target\lifecycle-e2e'
$serverPath = Join-Path $targetRoot 'debug\linklake-server.exe'
$clientPath = Join-Path $targetRoot 'debug\linklake-client.exe'
$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('linklake-lifecycle-e2e-' + [guid]::NewGuid())
$serverProcess = $null
$clientProcess = $null
$echoProcess = $null
$heldConnection = $null

function Get-FreePort {
    param([int]$Minimum = 0, [int]$Maximum = 0)
    if ($Minimum -eq 0) {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $listener.Stop()
        return $port
    }
    foreach ($candidate in ($Minimum..$Maximum | Sort-Object { Get-Random })) {
        try {
            $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, $candidate)
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
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments -join ' '
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    return [Diagnostics.Process]::Start($startInfo)
}

function Wait-ForCondition {
    param([scriptblock]$Condition, [string]$Failure, [int]$Seconds = 20)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            if (& $Condition) { return }
        } catch {
            # Retry transient failures while the service starts or changes state.
        }
        Start-Sleep -Milliseconds 150
    }
    throw $Failure
}

function Assert-ProbeStatus {
    param([string]$Uri, [int]$ExpectedStatus, [string]$ExpectedPhase)
    $client = [Net.Http.HttpClient]::new()
    try {
        $client.Timeout = [TimeSpan]::FromSeconds(3)
        $response = $client.GetAsync($Uri).GetAwaiter().GetResult()
        $status = [int]$response.StatusCode
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
    } finally {
        $client.Dispose()
    }
    if ($status -ne $ExpectedStatus -or $body.phase -ne $ExpectedPhase) {
        throw "Probe $Uri returned status=$status phase=$($body.phase); expected $ExpectedStatus/$ExpectedPhase."
    }
}

function Invoke-EchoRoundTrip {
    param([Net.Sockets.TcpClient]$Client, [string]$Text)
    $stream = $Client.GetStream()
    $payload = [Text.Encoding]::UTF8.GetBytes($Text)
    $received = [byte[]]::new($payload.Length)
    $stream.Write($payload, 0, $payload.Length)
    $stream.Flush()
    $offset = 0
    while ($offset -lt $received.Length) {
        $read = $stream.Read($received, $offset, $received.Length - $offset)
        if ($read -eq 0) { throw 'The held TCP tunnel connection closed unexpectedly.' }
        $offset += $read
    }
    if ([Text.Encoding]::UTF8.GetString($received) -ne $Text) {
        throw 'The TCP tunnel returned corrupted data.'
    }
}

New-Item -ItemType Directory -Path $runRoot | Out-Null
try {
    if (-not $SkipBuild) {
        $previousTarget = $env:CARGO_TARGET_DIR
        try {
            $env:CARGO_TARGET_DIR = $targetRoot
            & cargo build --workspace --locked
            if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
        } finally {
            $env:CARGO_TARGET_DIR = $previousTarget
        }
    }
    if (-not (Test-Path -LiteralPath $serverPath) -or -not (Test-Path -LiteralPath $clientPath)) {
        throw 'The lifecycle E2E binaries do not exist. Run without -SkipBuild first.'
    }

    $managementPort = Get-FreePort
    $controlPort = Get-FreePort
    $targetPort = Get-FreePort
    $publicPort = Get-FreePort -Minimum 32000 -Maximum 32999
    $baseUrl = "http://127.0.0.1:$managementPort"
    $enrollmentToken = [guid]::NewGuid().ToString()
    $adminPassword = 'LinkLake-Lifecycle-E2E-123!'

    $echoScript = @"
        `$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $targetPort)
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

    Wait-ForCondition -Failure 'The LinkLake server did not become ready.' -Condition {
        (Invoke-RestMethod -Uri "$baseUrl/readyz" -TimeoutSec 2).status -eq 'ready'
    }
    Assert-ProbeStatus -Uri "$baseUrl/livez" -ExpectedStatus 200 -ExpectedPhase 'ready'
    Assert-ProbeStatus -Uri "$baseUrl/startupz" -ExpectedStatus 200 -ExpectedPhase 'ready'

    $enrollment = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'lifecycle-client'; platform = 'windows' } | ConvertTo-Json)
    $login = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/login" `
        -SessionVariable webSession -ContentType 'application/json' `
        -Body (@{ username = 'admin'; password = $adminPassword } | ConvertTo-Json)
    if ($login.role -ne 'administrator') { throw 'Administrator login failed.' }

    $policy = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tcp-tunnels" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body (@{
            client_id = $enrollment.client_id
            name = 'lifecycle-tcp'
            public_port = $publicPort
            target_addr = "127.0.0.1:$targetPort"
            max_connections = 8
        } | ConvertTo-Json)
    $clientProcess = Start-HiddenProcess -FilePath $clientPath -Arguments @(
        'agent', '--control', "127.0.0.1:$controlPort",
        '--client-id', $enrollment.client_id, '--token', $enrollment.client_token,
        '--public-port', $publicPort, '--target', "127.0.0.1:$targetPort",
        '--name', 'lifecycle-tcp'
    )
    Wait-ForCondition -Failure 'The TCP tunnel did not become online.' -Condition {
        $current = Invoke-RestMethod -Uri "$baseUrl/api/v1/tcp-tunnels" -WebSession $webSession |
            Where-Object { $_.id -eq $policy.id }
        $current.online
    }

    $heldConnection = [Net.Sockets.TcpClient]::new('127.0.0.1', $publicPort)
    $heldConnection.ReceiveTimeout = 5000
    $heldConnection.SendTimeout = 5000
    Invoke-EchoRoundTrip -Client $heldConnection -Text 'before-drain'
    Wait-ForCondition -Failure 'The held connection was not reflected in lifecycle state.' -Condition {
        (Invoke-RestMethod -Uri "$baseUrl/api/v1/lifecycle" -WebSession $webSession).active_tcp_connections -eq 1
    }

    $draining = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/lifecycle/drain" `
        -WebSession $webSession -ContentType 'application/json' -Body '{"timeout_seconds":120}'
    if ($draining.phase -ne 'draining' -or $draining.accepting_new_work -or
        $draining.active_tcp_connections -ne 1 -or -not $draining.drain_deadline_unix_seconds) {
        throw "The drain response was invalid: $($draining | ConvertTo-Json -Compress)"
    }
    Assert-ProbeStatus -Uri "$baseUrl/readyz" -ExpectedStatus 503 -ExpectedPhase 'draining'
    Assert-ProbeStatus -Uri "$baseUrl/livez" -ExpectedStatus 200 -ExpectedPhase 'draining'
    Assert-ProbeStatus -Uri "$baseUrl/startupz" -ExpectedStatus 200 -ExpectedPhase 'draining'
    Invoke-EchoRoundTrip -Client $heldConnection -Text 'existing-connection-survives-drain'

    $rejectedConnection = [Net.Sockets.TcpClient]::new()
    try {
        $rejectedConnection.ReceiveTimeout = 3000
        $rejectedConnection.Connect('127.0.0.1', $publicPort)
        $stream = $rejectedConnection.GetStream()
        $stream.WriteByte(1)
        try {
            if ($stream.ReadByte() -ge 0) { throw 'A new TCP connection transferred data during drain.' }
        } catch [IO.IOException] {
            # Expected: the listener closes or resets a newly accepted connection.
        }
    } catch [Net.Sockets.SocketException] {
        # A direct refusal in the platform scheduling window is also valid.
    } finally {
        $rejectedConnection.Dispose()
    }

    try {
        Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
            -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
            -Body (@{ name = 'rejected-client'; platform = 'windows' } | ConvertTo-Json)
        throw 'Client enrollment unexpectedly succeeded during drain.'
    } catch {
        if (-not $_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 503) { throw }
    }

    $heldConnection.Dispose()
    $heldConnection = $null
    Wait-ForCondition -Failure 'The server did not report a fully drained state.' -Condition {
        (Invoke-RestMethod -Uri "$baseUrl/api/v1/lifecycle" -WebSession $webSession).drained
    }
    $resumed = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/lifecycle/resume" `
        -WebSession $webSession -ContentType 'application/json' -Body '{}'
    if ($resumed.phase -ne 'ready' -or -not $resumed.accepting_new_work) {
        throw "The resume response was invalid: $($resumed | ConvertTo-Json -Compress)"
    }
    Assert-ProbeStatus -Uri "$baseUrl/readyz" -ExpectedStatus 200 -ExpectedPhase 'ready'

    $resumedConnection = [Net.Sockets.TcpClient]::new('127.0.0.1', $publicPort)
    try {
        $resumedConnection.ReceiveTimeout = 5000
        $resumedConnection.SendTimeout = 5000
        Invoke-EchoRoundTrip -Client $resumedConnection -Text 'after-resume'
    } finally {
        $resumedConnection.Dispose()
    }

    $audit = @(Invoke-RestMethod -Uri "$baseUrl/api/v1/audit?limit=50" -WebSession $webSession)
    if (-not ($audit | Where-Object { $_.action -eq 'lifecycle.drain' }) -or
        -not ($audit | Where-Object { $_.action -eq 'lifecycle.resume' })) {
        throw 'Lifecycle administrator operations were not recorded in the audit log.'
    }

    Write-Host 'Lifecycle E2E passed: probes, administrator drain/resume, enrollment rejection, existing TCP survival, new TCP rejection, drained state, and audit.'
} finally {
    if ($heldConnection) { $heldConnection.Dispose() }
    foreach ($process in @($clientProcess, $serverProcess, $echoProcess)) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            $null = $process.WaitForExit(5000)
        }
    }
    $resolvedRunRoot = [IO.Path]::GetFullPath($runRoot)
    $resolvedTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolvedRunRoot.StartsWith($resolvedTempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedRunRoot).StartsWith('linklake-lifecycle-e2e-')) {
        for ($attempt = 0; $attempt -lt 10 -and (Test-Path -LiteralPath $resolvedRunRoot); $attempt++) {
            try { Remove-Item -LiteralPath $resolvedRunRoot -Recurse -Force }
            catch {
                if ($attempt -eq 9) { throw }
                Start-Sleep -Milliseconds 200
            }
        }
    }
}
