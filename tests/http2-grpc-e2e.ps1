param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['Invoke-RestMethod:Headers'] = @{ 'X-LinkLake-CSRF' = '1' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target\e2e'
$serverPath = Join-Path $targetRoot 'debug\linklake-server.exe'
$clientPath = Join-Path $targetRoot 'debug\linklake-client.exe'
$probePath = Join-Path $targetRoot 'debug\examples\http2_grpc_probe.exe'
$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('linklake-http2-grpc-e2e-' + [guid]::NewGuid())
$processes = [System.Collections.Generic.List[Diagnostics.Process]]::new()
$stage = 'initialization'
$testPassed = $false

function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Start-HiddenProcess {
    param(
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [hashtable]$Environment = @{}
    )
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments -join ' '
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    foreach ($entry in $Environment.GetEnumerator()) {
        $startInfo.EnvironmentVariables[[string]$entry.Key] = [string]$entry.Value
    }
    $process = [Diagnostics.Process]::Start($startInfo)
    $processes.Add($process)
    return $process
}

function Invoke-CheckedProcess {
    param(
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [string]$DisplayName,
        [int]$TimeoutSeconds
    )
    $id = [guid]::NewGuid().ToString('N')
    $stdoutPath = Join-Path $runRoot "$DisplayName-$id.stdout.log"
    $stderrPath = Join-Path $runRoot "$DisplayName-$id.stderr.log"
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -WorkingDirectory $projectRoot `
        -NoNewWindow -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $null = $process.WaitForExit(5000)
        throw "$DisplayName did not exit within $TimeoutSeconds seconds during ${stage}. Diagnostic output was retained at $stdoutPath and $stderrPath."
    }
    $output = if (Test-Path -LiteralPath $stdoutPath) { @(Get-Content -LiteralPath $stdoutPath) } else { @() }
    if ($process.ExitCode -ne 0) {
        throw "$DisplayName failed with exit code $($process.ExitCode) during ${stage}. Diagnostic output was retained at $stdoutPath and $stderrPath."
    }
    return $output
}

function Wait-TcpPort {
    param([int]$Port, [int]$Seconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $Port)
            return
        } catch {
            Start-Sleep -Milliseconds 200
        } finally {
            $client.Dispose()
        }
    }
    throw "TCP port $Port did not become reachable during $stage."
}

function Wait-HttpHealth {
    param([string]$BaseUrl)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
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

function Get-Route {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$RouteId
    )
    return Invoke-RestMethod -Uri "$BaseUrl/api/v1/http-routes" -WebSession $Session |
        Where-Object { $_.id -eq $RouteId } | Select-Object -First 1
}

function Wait-Route {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$RouteId,
        [scriptblock]$Condition,
        [string]$Failure,
        [int]$Seconds = 30
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $route = Get-Route -BaseUrl $BaseUrl -Session $Session -RouteId $RouteId
        if ($route -and (& $Condition $route)) { return $route }
        Start-Sleep -Milliseconds 200
    }
    throw $Failure
}

function Invoke-Probe {
    param([string[]]$Arguments)
    $output = Invoke-CheckedProcess -FilePath $probePath -Arguments $Arguments `
        -DisplayName 'http2-grpc-probe' -TimeoutSeconds 90
    $json = @($output | Where-Object { $_ -match '^\s*\{' } | Select-Object -Last 1)
    if ($json.Count -ne 1) {
        throw "HTTP/2 probe did not emit one JSON result during ${stage}. Output: $($output -join ' ')"
    }
    return $json[0] | ConvertFrom-Json
}

function Read-Observations {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    return @(Get-Content -LiteralPath $Path | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_ | ConvertFrom-Json })
}

New-Item -ItemType Directory -Path $runRoot | Out-Null
try {
    if (-not $SkipBuild) {
        $previousTarget = $env:CARGO_TARGET_DIR
        $previousJobs = $env:CARGO_BUILD_JOBS
        try {
            $env:CARGO_TARGET_DIR = $targetRoot
            $env:CARGO_BUILD_JOBS = '2'
            Invoke-CheckedProcess -FilePath 'cargo' -Arguments @('build', '--workspace', '--bins', '--example', 'http2_grpc_probe') `
                -DisplayName 'cargo-build' -TimeoutSeconds 900 | Out-Null
        } finally {
            $env:CARGO_TARGET_DIR = $previousTarget
            $env:CARGO_BUILD_JOBS = $previousJobs
        }
    }
    foreach ($path in @($serverPath, $clientPath, $probePath)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "The E2E binary does not exist: $path"
        }
    }

    $managementPort = Get-FreePort
    $controlPort = Get-FreePort
    $httpPort = Get-FreePort
    $backendPort = Get-FreePort
    $baseUrl = "http://127.0.0.1:$managementPort"
    $hostname = 'grpc.e2e.test'
    $enrollmentToken = [guid]::NewGuid().ToString()
    $adminPassword = 'LinkLake-H2-gRPC-E2E-Password-123!'
    $observationsPath = Join-Path $runRoot 'backend-observations.jsonl'

    $stage = 'backend start'
    Start-HiddenProcess -FilePath $probePath -Arguments @(
        'backend', "127.0.0.1:$backendPort", "`"$observationsPath`""
    ) | Out-Null
    Wait-TcpPort -Port $backendPort

    $stage = 'server start'
    Start-HiddenProcess -FilePath $serverPath -Environment @{
        LINKLAKE_BIND = "127.0.0.1:$managementPort"
        LINKLAKE_CONTROL_BIND = "127.0.0.1:$controlPort"
        LINKLAKE_HTTP_BIND = "127.0.0.1:$httpPort"
        LINKLAKE_ENROLLMENT_TOKEN = $enrollmentToken
        LINKLAKE_DATA_DIR = (Join-Path $runRoot 'data')
        LINKLAKE_ADMIN_USERNAME = 'admin'
        LINKLAKE_ADMIN_PASSWORD = $adminPassword
    } | Out-Null
    Wait-HttpHealth -BaseUrl $baseUrl
    Wait-TcpPort -Port $httpPort

    $stage = 'management bootstrap'
    $enrollment = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'http2-grpc-e2e-client'; platform = 'windows' } | ConvertTo-Json)
    $login = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/login" `
        -SessionVariable webSession -ContentType 'application/json' `
        -Body (@{ username = 'admin'; password = $adminPassword } | ConvertTo-Json)
    if (-not $login.expires_unix_seconds) { throw 'Administrator login failed.' }
    $route = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/http-routes" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body (@{
            client_id = $enrollment.client_id
            name = 'http2-grpc-e2e'
            hostname = $hostname
            target_addr = "127.0.0.1:$backendPort"
            max_connections = 64
        } | ConvertTo-Json)

    $configPath = Join-Path $runRoot 'client.toml'
    $clientConfig = @"
[client]
control = "127.0.0.1:$controlPort"
client_id = "$($enrollment.client_id)"
client_token = "$($enrollment.client_token)"
config_mode = "local"

[[http_routes]]
name = "http2-grpc-e2e"
hostname = "$hostname"
target = "127.0.0.1:$backendPort"
"@
    [IO.File]::WriteAllText($configPath, $clientConfig, [Text.UTF8Encoding]::new($false))
    Start-HiddenProcess -FilePath $clientPath -Arguments @('run', '--config', "`"$configPath`"") | Out-Null
    Wait-Route -BaseUrl $baseUrl -Session $webSession -RouteId $route.id `
        -Condition { param($value) [bool]$value.online } `
        -Failure 'The HTTP/2 route did not become online.' | Out-Null

    $routeContract = Get-Route -BaseUrl $baseUrl -Session $webSession -RouteId $route.id
    if (-not $routeContract.capabilities.http1 -or -not $routeContract.capabilities.http2 -or
        -not $routeContract.capabilities.grpc -or -not $routeContract.capabilities.h2c_prior_knowledge -or
        $routeContract.capabilities.grpc_backend_transport -ne 'h2c') {
        throw 'The HTTP/2 and gRPC capability contract is incorrect.'
    }

    $stage = 'streaming and multiplexing'
    $stream = Invoke-Probe -Arguments @('probe-stream', "127.0.0.1:$httpPort", $hostname)
    if ($stream.first_chunk -ne 'one' -or $stream.remaining -ne 'three' -or
        $stream.second -ne 'two' -or $stream.first_status -ne '0' -or
        $stream.second_status -ne '0' -or $stream.first_connection -ne $stream.second_connection) {
        throw 'gRPC bidirectional streaming, trailers, or backend multiplexing failed.'
    }

    $stage = 'cancellation'
    $cancel = Invoke-Probe -Arguments @('probe-cancel', "127.0.0.1:$httpPort", $hostname)
    if ($cancel.first_chunk -ne 'cancel-me' -or $cancel.recovery_body -ne 'after-cancel' -or
        $cancel.grpc_status -ne '0' -or $cancel.cancelled_connection -ne $cancel.recovery_connection) {
        throw 'gRPC cancellation did not preserve the shared HTTP/2 connection.'
    }
    $routeAfterCancel = Wait-Route -BaseUrl $baseUrl -Session $webSession -RouteId $route.id `
        -Condition { param($value) $value.grpc_cancellations_total -ge 1 } `
        -Failure 'The gRPC cancellation metric was not updated.'

    $stage = 'GOAWAY'
    $goaway = Invoke-Probe -Arguments @(
        'probe-single', "127.0.0.1:$httpPort", $hostname, '/grpc.echo/GoAway', 'before-goaway'
    )
    if ($goaway.body -ne 'before-goaway' -or $goaway.grpc_status -ne '0') {
        throw 'The request before GOAWAY was not completed.'
    }
    Wait-Route -BaseUrl $baseUrl -Session $webSession -RouteId $route.id `
        -Condition { param($value) $value.http2_backend_goaway_total -ge 1 } `
        -Failure 'The HTTP/2 GOAWAY metric was not updated.' | Out-Null
    $recovered = Invoke-Probe -Arguments @(
        'probe-single', "127.0.0.1:$httpPort", $hostname, '/grpc.echo/Stream', 'after-goaway'
    )
    if ($recovered.body -ne 'after-goaway' -or $recovered.grpc_status -ne '0' -or
        $recovered.backend_connection -eq $goaway.backend_connection) {
        throw 'The HTTP/2 backend did not reconnect after GOAWAY.'
    }
    $routeRecovered = Wait-Route -BaseUrl $baseUrl -Session $webSession -RouteId $route.id `
        -Condition { param($value) $value.http2_backend_reconnects_total -ge 1 } `
        -Failure 'The HTTP/2 backend reconnect metric was not updated.'

    $stage = 'final metrics'
    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if (-not $metrics.http_transport_capabilities.http1 -or
        -not $metrics.http_transport_capabilities.http2 -or
        -not $metrics.http_transport_capabilities.grpc -or
        $metrics.http_transport_capabilities.grpc_backend_transport -ne 'h2c') {
        throw 'The aggregate HTTP transport capability contract is incorrect.'
    }
    if ($routeRecovered.http2_requests_total -lt 6 -or $routeRecovered.grpc_requests_total -lt 6 -or
        $routeRecovered.grpc_trailers_total -lt 5 -or $routeRecovered.grpc_cancellations_total -lt 1 -or
        $routeRecovered.http2_backend_connections_total -lt 2 -or
        $routeRecovered.http2_backend_reused_total -lt 3 -or
        $routeRecovered.http2_backend_goaway_total -lt 1 -or
        $routeRecovered.http2_backend_reconnects_total -lt 1 -or
        $metrics.http2_requests_total -lt 6 -or $metrics.grpc_requests_total -lt 6 -or
        $metrics.grpc_cancellations_total -lt 1 -or $metrics.http2_backend_connections_total -lt 2 -or
        $metrics.http2_backend_goaway_total -lt 1 -or $metrics.http2_backend_reconnects_total -lt 1) {
        throw 'The HTTP/2 or gRPC policy and aggregate metrics were not updated as expected.'
    }

    $observations = Read-Observations -Path $observationsPath
    $openConnections = @($observations | Where-Object { $_.event -eq 'connection_open' })
    $cancelled = @($observations | Where-Object { $_.event -eq 'cancelled' })
    $goaways = @($observations | Where-Object { $_.event -eq 'goaway' })
    if ($openConnections.Count -lt 2 -or $cancelled.Count -lt 1 -or $goaways.Count -lt 1) {
        throw 'The backend did not observe multiplexing cancellation and GOAWAY lifecycle events.'
    }

    Write-Host 'HTTP/2 and gRPC E2E passed: h2c ingress, multiplexing, bidirectional streaming, trailers, cancellation, GOAWAY drain, reconnect, limits, and metrics.'
    $testPassed = $true
} finally {
    foreach ($process in $processes) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $null = $process.WaitForExit(5000)
        }
    }
    if ($testPassed) {
        for ($attempt = 0; $attempt -lt 10 -and (Test-Path -LiteralPath $runRoot); $attempt++) {
            try { Remove-Item -LiteralPath $runRoot -Recurse -Force }
            catch {
                if ($attempt -eq 9) { throw }
                Start-Sleep -Milliseconds 200
            }
        }
    } else {
        Write-Warning "HTTP/2 gRPC E2E artifacts were preserved at $runRoot during stage '$stage'."
    }
}
