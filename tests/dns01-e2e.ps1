param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['Invoke-RestMethod:Headers'] = @{ 'X-LinkLake-CSRF' = '1' }
$PSDefaultParameterValues['Invoke-WebRequest:Headers'] = @{ 'X-LinkLake-CSRF' = '1' }
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath 'Variable:PSNativeCommandUseErrorActionPreference') {
    $PSNativeCommandUseErrorActionPreference = $false
}
$env:NO_PROXY = '*'
$env:no_proxy = '*'

$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target/dns01-e2e'
$serverPath = Join-Path $targetRoot 'debug/linklake-server'
$clientPath = Join-Path $targetRoot 'debug/linklake-client'
$mockPath = Join-Path $PSScriptRoot 'cloudflare_dns_mock.py'
$rootCaPath = Join-Path $PSScriptRoot 'pebble/pebble.minica.pem'
$runRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('linklake-dns01-e2e-' + [guid]::NewGuid())
$issuedRootCaPath = Join-Path $runRoot 'pebble-issued-root.pem'
$challengeContainer = 'linklake-dns01-challtestsrv-' + [guid]::NewGuid().ToString('N')
$pebbleContainer = 'linklake-dns01-pebble-' + [guid]::NewGuid().ToString('N')
$pebbleVersion = '2.10.1'
$serverProcess = $null
$clientProcess = $null
$backendProcess = $null
$mockProcess = $null
$containersStarted = $false

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Get-DistinctFreePort {
    param([System.Collections.Generic.HashSet[int]]$UsedPorts)
    while ($true) {
        $port = Get-FreePort
        if ($UsedPorts.Add($port)) { return $port }
    }
}

function Assert-TcpPortAvailable {
    param([int]$Port)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
    } catch {
        throw "TCP port $Port is required by the DNS-01 E2E test but is already in use."
    } finally {
        $listener.Stop()
    }
}

function Assert-UdpPortAvailable {
    param([int]$Port)
    $socket = [System.Net.Sockets.Socket]::new(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Dgram,
        [System.Net.Sockets.ProtocolType]::Udp
    )
    try {
        $socket.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, $Port))
    } catch {
        throw "UDP port $Port is required by the DNS-01 E2E test but is already in use."
    } finally {
        $socket.Dispose()
    }
}

function Start-ChildProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [hashtable]$Environment = @{}
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    # 不继承操作者机器上可能存在的真实 Cloudflare 凭据。
    foreach ($name in @('LINKLAKE_CLOUDFLARE_API_TOKEN', 'LINKLAKE_CLOUDFLARE_API_TOKEN_FILE')) {
        $null = $startInfo.Environment.Remove($name)
    }
    foreach ($entry in $Environment.GetEnumerator()) {
        $startInfo.Environment[$entry.Key] = [string]$entry.Value
    }
    foreach ($argument in $Arguments) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    return [System.Diagnostics.Process]::Start($startInfo)
}

function Stop-ChildProcess {
    param($Process)
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            $null = $Process.WaitForExit(10000)
        }
    } catch {
    } finally {
        $Process.Dispose()
    }
}

function Wait-TcpPort {
    param([int]$Port, [int]$Seconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $connection = [System.Net.Sockets.TcpClient]::new()
        try {
            $connection.Connect('127.0.0.1', $Port)
            return
        } catch {
            Start-Sleep -Milliseconds 200
        } finally {
            $connection.Dispose()
        }
    }
    throw "TCP port $Port did not become reachable."
}

function Wait-HttpHealth {
    param([string]$BaseUrl, [int]$Seconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
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

function Wait-MockHealth {
    param([string]$BaseUrl, [int]$Seconds = 20)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri "$BaseUrl/__test/health" -TimeoutSec 2
            if ($health.status -eq 'ok') { return }
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    throw 'The local Cloudflare Mock did not become healthy.'
}

function Wait-PebbleDirectory {
    param([int]$Seconds = 45)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        & curl --silent --show-error --fail --cacert $rootCaPath --output /dev/null `
            'https://localhost:14000/dir'
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Milliseconds 500
    }
    throw 'Pebble ACME directory did not become ready.'
}

function Export-PebbleIssuedRoot {
    & curl --silent --show-error --fail --cacert $rootCaPath --output $issuedRootCaPath `
        'https://localhost:15000/roots/0'
    $issuedRoot = if (Test-Path -LiteralPath $issuedRootCaPath) {
        Get-Content -LiteralPath $issuedRootCaPath -Raw
    } else {
        ''
    }
    if ($LASTEXITCODE -ne 0 -or $issuedRoot -notmatch '-----BEGIN CERTIFICATE-----') {
        throw 'Could not export the Pebble issued-certificate root CA.'
    }
}

function Start-LinkLakeServer {
    param([hashtable]$Environment)
    return Start-ChildProcess -FilePath $serverPath -Environment $Environment
}

function Assert-ServerStartupFails {
    param(
        [hashtable]$Environment,
        [string]$Context
    )
    $process = Start-LinkLakeServer -Environment $Environment
    try {
        if (-not $process.WaitForExit(10000)) {
            throw "$Context did not stop the server during startup."
        }
        if ($process.ExitCode -eq 0) {
            throw "$Context unexpectedly exited successfully."
        }
    } finally {
        Stop-ChildProcess -Process $process
    }
}

function Get-HttpRoute {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$RouteId
    )
    $routes = Invoke-RestMethod -Uri "$BaseUrl/api/v1/http-routes" -WebSession $Session
    return $routes | Where-Object { $_.id -eq $RouteId } | Select-Object -First 1
}

function Wait-HttpRouteOnline {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$RouteId,
        [int]$Seconds = 40
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $route = Get-HttpRoute -BaseUrl $BaseUrl -Session $Session -RouteId $RouteId
        if ($null -ne $route -and [bool]$route.online) { return $route }
        Start-Sleep -Milliseconds 250
    }
    throw "HTTP route $RouteId did not become online."
}

function Wait-RouteTlsStatus {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$RouteId,
        [string]$ExpectedStatus,
        [bool]$ExpectedOnline,
        [int]$Seconds = 150
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $lastRoute = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $lastRoute = Get-HttpRoute -BaseUrl $BaseUrl -Session $Session -RouteId $RouteId
        if ($null -ne $lastRoute -and
            $lastRoute.tls.status -eq $ExpectedStatus -and
            [bool]$lastRoute.tls.https_online -eq $ExpectedOnline) {
            return $lastRoute
        }
        if ($null -ne $lastRoute -and $lastRoute.tls.status -eq 'error') {
            throw "Certificate operation failed: $($lastRoute.tls.last_error_code): $($lastRoute.tls.last_error_message)"
        }
        Start-Sleep -Milliseconds 500
    }
    throw "Route TLS did not reach $ExpectedStatus/$ExpectedOnline."
}

function Wait-RouteTlsError {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$RouteId,
        [int]$Seconds = 150
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $route = Get-HttpRoute -BaseUrl $BaseUrl -Session $Session -RouteId $RouteId
        if ($null -ne $route -and $route.tls.status -eq 'error') { return $route }
        Start-Sleep -Milliseconds 500
    }
    throw "Route $RouteId did not enter the certificate error state."
}

function Invoke-CurlRequest {
    param(
        [int]$Port,
        [string]$ServerName,
        [string]$Path = '/',
        [switch]$ExpectFailure
    )
    $bodyPath = Join-Path $runRoot ('curl-body-' + [guid]::NewGuid())
    $arguments = @(
        '--silent', '--show-error', '--connect-timeout', '10', '--max-time', '30',
        '--resolve', "${ServerName}:${Port}:127.0.0.1",
        '--cacert', $issuedRootCaPath,
        '--output', $bodyPath,
        '--write-out', '%{http_code}',
        "https://${ServerName}:${Port}${Path}"
    )
    try {
        $statusOutput = & curl @arguments
        $exitCode = $LASTEXITCODE
        if ($ExpectFailure) {
            if ($exitCode -eq 0) {
                throw "TLS request for $ServerName unexpectedly succeeded with HTTP $statusOutput."
            }
            if ($exitCode -ne 35) {
                throw "TLS request for $ServerName failed with curl exit code $exitCode, expected handshake error 35."
            }
            return [pscustomobject]@{ ExitCode = $exitCode; StatusCode = 0; Content = '' }
        }
        if ($exitCode -ne 0) {
            throw "curl failed for https://${ServerName}:${Port}${Path} with exit code $exitCode."
        }
        return [pscustomobject]@{
            ExitCode = $exitCode
            StatusCode = [int]([string]$statusOutput).Trim()
            Content = if (Test-Path -LiteralPath $bodyPath) {
                Get-Content -LiteralPath $bodyPath -Raw
            } else {
                ''
            }
        }
    } finally {
        Remove-Item -LiteralPath $bodyPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-MockState {
    param([string]$MockBaseUrl)
    return Invoke-RestMethod -Uri "$MockBaseUrl/__test/state"
}

function Set-MockConfig {
    param(
        [string]$MockBaseUrl,
        [hashtable]$Config
    )
    return Invoke-RestMethod -Method Post -Uri "$MockBaseUrl/__test/config" `
        -ContentType 'application/json' -Body ($Config | ConvertTo-Json)
}

function New-TestHttpRoute {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$ClientId,
        [string]$Name,
        [string]$Hostname,
        [int]$BackendPort
    )
    return Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/v1/http-routes" `
        -WebSession $Session -ContentType 'application/json' `
        -Body (@{
            client_id = $ClientId
            name = $Name
            hostname = $Hostname
            target_addr = "127.0.0.1:$BackendPort"
            max_connections = 32
        } | ConvertTo-Json)
}

function Set-RouteTlsPolicy {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$RouteId,
        [AllowNull()][string]$CertificateIdentifier
    )
    $body = [ordered]@{
        mode = 'acme'
        redirect_http_to_https = $false
    }
    if (-not [string]::IsNullOrWhiteSpace($CertificateIdentifier)) {
        $body.certificate_identifier = $CertificateIdentifier
    }
    return Invoke-RestMethod -Method Put -Uri "$BaseUrl/api/v1/http-routes/$RouteId/tls" `
        -WebSession $Session -ContentType 'application/json' -Body ($body | ConvertTo-Json)
}

function Set-TestHttpRouteEnabled {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$RouteId,
        [bool]$Enabled
    )
    $null = Invoke-RestMethod -Method Post `
        -Uri "$BaseUrl/api/v1/http-routes/$RouteId/enabled" `
        -WebSession $Session -ContentType 'application/json' `
        -Body (@{ enabled = $Enabled } | ConvertTo-Json)
}

function Start-CertificateIssue {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$RouteId
    )
    $response = Invoke-WebRequest -Method Post `
        -Uri "$BaseUrl/api/v1/http-routes/$RouteId/certificate/issue" `
        -WebSession $Session -SkipHttpErrorCheck
    if ([int]$response.StatusCode -eq 202) { return }
    if ([int]$response.StatusCode -eq 409) {
        $conflict = $response.Content | ConvertFrom-Json
        if ($conflict.code -in @(
            'certificate_operation_in_progress',
            'certificate_operation_cooldown'
        )) {
            return
        }
    }
    throw "Certificate issue request returned HTTP $($response.StatusCode): $($response.Content)"
}

function Assert-CloudflareLifecycle {
    param(
        $State,
        [int]$EventOffset,
        [string]$ExpectedRecordName,
        [string]$ExpectedZoneId,
        [string[]]$ExpectedZoneLookups
    )
    $events = @($State.events | Select-Object -Skip $EventOffset)
    $lookups = @($events | Where-Object { $_.kind -eq 'zone_lookup' })
    if ($lookups.Count -lt $ExpectedZoneLookups.Count) {
        throw 'Cloudflare zone lookup did not visit all expected suffixes.'
    }
    for ($index = 0; $index -lt $ExpectedZoneLookups.Count; $index++) {
        if ($lookups[$index].name -ne $ExpectedZoneLookups[$index]) {
            throw "Unexpected zone lookup order at index ${index}: $($lookups[$index].name)"
        }
    }
    $created = @($events | Where-Object {
        $_.kind -eq 'txt_created' -and $_.name -eq $ExpectedRecordName
    })
    if ($created.Count -ne 1 -or $created[0].zone_id -ne $ExpectedZoneId) {
        throw 'Cloudflare TXT record was not created in the expected longest-suffix zone.'
    }
    $deleted = @($events | Where-Object {
        $_.kind -eq 'txt_deleted' -and $_.record_id -eq $created[0].record_id
    })
    if ($deleted.Count -ne 1) {
        throw 'The TXT record created by LinkLake was not deleted exactly once.'
    }
}

function Assert-NoSecretInDirectory {
    param(
        [string]$Directory,
        [string]$Secret
    )
    if (-not (Test-Path -LiteralPath $Directory)) { return }
    foreach ($file in Get-ChildItem -LiteralPath $Directory -File -Recurse -ErrorAction SilentlyContinue) {
        try {
            $content = [Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($file.FullName))
            if ($content.Contains($Secret)) {
                throw "Cloudflare token leaked into $($file.FullName)."
            }
        } catch [System.IO.IOException] {
            throw "Could not inspect $($file.FullName) for secret leakage: $($_.Exception.Message)"
        }
    }
}

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Linux)) {
    throw 'tests/dns01-e2e.ps1 requires Linux because Pebble uses Docker host networking.'
}
foreach ($command in @('docker', 'curl', 'python3', 'chmod')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "$command is required for the DNS-01 E2E test."
    }
}
foreach ($requiredFile in @($rootCaPath, $mockPath)) {
    if (-not (Test-Path -LiteralPath $requiredFile)) {
        throw "Required DNS-01 E2E file is missing: $requiredFile"
    }
}

New-Item -ItemType Directory -Path $runRoot | Out-Null
try {
    foreach ($port in @(5002, 8053, 8055, 14000, 15000)) {
        Assert-TcpPortAvailable -Port $port
    }
    Assert-UdpPortAvailable -Port 8053

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
        throw 'The DNS-01 E2E binaries do not exist. Run without -SkipBuild first.'
    }

    $testToken = 'LinkLake-DNS01-E2E-Token-Only-0001'
    $tokenPath = Join-Path $runRoot 'cloudflare-token'
    [System.IO.File]::WriteAllText($tokenPath, $testToken, [Text.UTF8Encoding]::new($false))

    # 在启动完整系统前验证凭据来源边界。
    & chmod 0600 $tokenPath
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the test token file permissions.' }
    $failurePorts = [System.Collections.Generic.HashSet[int]]::new()
    $failureEnvironment = @{
        LINKLAKE_BIND = "127.0.0.1:$(Get-DistinctFreePort -UsedPorts $failurePorts)"
        LINKLAKE_CONTROL_BIND = "127.0.0.1:$(Get-DistinctFreePort -UsedPorts $failurePorts)"
        LINKLAKE_HTTP_BIND = "127.0.0.1:$(Get-DistinctFreePort -UsedPorts $failurePorts)"
        LINKLAKE_HTTPS_BIND = "127.0.0.1:$(Get-DistinctFreePort -UsedPorts $failurePorts)"
        LINKLAKE_DATA_DIR = (Join-Path $runRoot 'ambiguous-token-data')
        LINKLAKE_ADMIN_USERNAME = 'admin'
        LINKLAKE_ADMIN_PASSWORD = 'LinkLake-DNS01-Startup-Test-Password!'
        LINKLAKE_ENROLLMENT_TOKEN = 'dns01-startup-test-enrollment'
        LINKLAKE_CLOUDFLARE_API_TOKEN = $testToken
        LINKLAKE_CLOUDFLARE_API_TOKEN_FILE = $tokenPath
    }
    Assert-ServerStartupFails -Environment $failureEnvironment `
        -Context 'Ambiguous inline and file Cloudflare token sources'

    & chmod 0644 $tokenPath
    if ($LASTEXITCODE -ne 0) { throw 'Could not make the test token file deliberately permissive.' }
    $failureEnvironment.Remove('LINKLAKE_CLOUDFLARE_API_TOKEN')
    $failureEnvironment.LINKLAKE_DATA_DIR = Join-Path $runRoot 'permissive-token-data'
    Assert-ServerStartupFails -Environment $failureEnvironment `
        -Context 'Group-readable Cloudflare token file'
    & chmod 0600 $tokenPath
    if ($LASTEXITCODE -ne 0) { throw 'Could not restore the test token file permissions.' }

    $failureEnvironment.LINKLAKE_CLOUDFLARE_API_TOKEN_FILE = Join-Path $runRoot 'missing-token'
    $failureEnvironment.LINKLAKE_DATA_DIR = Join-Path $runRoot 'missing-token-data'
    Assert-ServerStartupFails -Environment $failureEnvironment `
        -Context 'Missing Cloudflare token file'

    & docker run --detach --network host --name $challengeContainer `
        "ghcr.io/letsencrypt/pebble-challtestsrv:$pebbleVersion" `
        '-http01=' '-https01=' '-tlsalpn01=' '-doh=' `
        '-dnsserver=:8053' '-management=:8055' `
        '-defaultIPv4=127.0.0.1' '-defaultIPv6='
    if ($LASTEXITCODE -ne 0) { throw 'Could not start pebble-challtestsrv.' }
    $containersStarted = $true
    Wait-TcpPort -Port 8055

    $usedPorts = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($reserved in @(5002, 8053, 8055, 14000, 15000)) { $null = $usedPorts.Add($reserved) }
    $mockPort = Get-DistinctFreePort -UsedPorts $usedPorts
    $managementPort = Get-DistinctFreePort -UsedPorts $usedPorts
    $controlPort = Get-DistinctFreePort -UsedPorts $usedPorts
    $httpPort = Get-DistinctFreePort -UsedPorts $usedPorts
    $httpsPort = Get-DistinctFreePort -UsedPorts $usedPorts
    $backendPort = Get-DistinctFreePort -UsedPorts $usedPorts
    $mockBaseUrl = "http://127.0.0.1:$mockPort"
    $baseUrl = "http://127.0.0.1:$managementPort"
    $mockProcess = Start-ChildProcess -FilePath 'python3' -Arguments @(
        $mockPath,
        '--bind', "127.0.0.1:$mockPort",
        '--zone', 'example.test:zone-example',
        '--zone', 'sub.example.test:zone-sub',
        '--challenge-management-url', 'http://127.0.0.1:8055'
    ) -Environment @{ MOCK_CLOUDFLARE_API_TOKEN = $testToken }
    Wait-MockHealth -BaseUrl $mockBaseUrl

    & docker run --detach --network host --name $pebbleContainer `
        --env PEBBLE_VA_NOSLEEP=1 `
        "ghcr.io/letsencrypt/pebble:$pebbleVersion" `
        -config test/config/pebble-config.json -strict -dnsserver 127.0.0.1:8053
    if ($LASTEXITCODE -ne 0) { throw 'Could not start Pebble.' }
    Wait-PebbleDirectory
    Export-PebbleIssuedRoot

    $backendScript = @'
$ErrorActionPreference = 'Stop'
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, __BACKEND_PORT__)
$listener.Start()
try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $reader = [System.IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $false, 4096, $true)
            $requestLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($requestLine)) { continue }
            while (-not [string]::IsNullOrEmpty($reader.ReadLine())) {}
            $payload = [Text.Encoding]::UTF8.GetBytes('{"status":"dns01-backend-ok"}')
            $head = "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: $($payload.Length)`r`nConnection: close`r`n`r`n"
            $headBytes = [Text.Encoding]::ASCII.GetBytes($head)
            $stream.Write($headBytes, 0, $headBytes.Length)
            $stream.Write($payload, 0, $payload.Length)
            $stream.Flush()
        } catch {
        } finally {
            $client.Dispose()
        }
    }
} finally {
    $listener.Stop()
}
'@.Replace('__BACKEND_PORT__', [string]$backendPort)
    $backendCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($backendScript))
    $currentPowerShell = (Get-Process -Id $PID).Path
    $backendProcess = Start-ChildProcess -FilePath $currentPowerShell -Arguments @(
        '-NoProfile', '-NonInteractive', '-EncodedCommand', $backendCommand
    )
    Wait-TcpPort -Port $backendPort

    $dataDirectory = Join-Path $runRoot 'data'
    $logDirectory = Join-Path $runRoot 'logs'
    $adminPassword = 'LinkLake-DNS01-E2E-Password-123!'
    $enrollmentToken = [guid]::NewGuid().ToString()
    $serverEnvironment = @{
        LINKLAKE_BIND = "127.0.0.1:$managementPort"
        LINKLAKE_CONTROL_BIND = "127.0.0.1:$controlPort"
        LINKLAKE_HTTP_BIND = "127.0.0.1:$httpPort"
        LINKLAKE_HTTPS_BIND = "127.0.0.1:$httpsPort"
        LINKLAKE_ENROLLMENT_TOKEN = $enrollmentToken
        LINKLAKE_DATA_DIR = $dataDirectory
        LINKLAKE_LOG_DIR = $logDirectory
        LINKLAKE_ADMIN_USERNAME = 'admin'
        LINKLAKE_ADMIN_PASSWORD = $adminPassword
        LINKLAKE_ACME_ROOT_CA_PATH = $rootCaPath
        LINKLAKE_CERTIFICATE_OPERATION_COOLDOWN_SECONDS = '1'
        LINKLAKE_CLOUDFLARE_API_TOKEN_FILE = $tokenPath
        LINKLAKE_CLOUDFLARE_API_BASE_URL = "$mockBaseUrl/client/v4/"
        LINKLAKE_ACME_DNS_LOOKUP_URL = "$mockBaseUrl/dns-query"
        LINKLAKE_ACME_DNS_PROPAGATION_TIMEOUT_SECONDS = '5'
        LINKLAKE_ACME_DNS_PROPAGATION_INTERVAL_MILLISECONDS = '50'
        RUST_LOG = 'linklake_server=info'
    }
    $serverProcess = Start-LinkLakeServer -Environment $serverEnvironment
    Wait-HttpHealth -BaseUrl $baseUrl
    Wait-TcpPort -Port $controlPort
    Wait-TcpPort -Port $httpsPort

    $enrollment = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'dns01-e2e-client'; platform = 'linux' } | ConvertTo-Json)
    $login = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/login" `
        -SessionVariable webSession -ContentType 'application/json' `
        -Body (@{ username = 'admin'; password = $adminPassword } | ConvertTo-Json)
    if (-not $login.expires_unix_seconds) { throw 'Administrator login failed.' }

    $routeSpecs = @(
        [ordered]@{ name = 'dns01-wildcard'; hostname = 'node.deep.sub.example.test' },
        [ordered]@{ name = 'dns01-invalid'; hostname = 'invalid.example.test' },
        [ordered]@{ name = 'dns01-zone-error'; hostname = 'zone-error.example.test' },
        [ordered]@{ name = 'dns01-create-error'; hostname = 'create-error.example.test' },
        [ordered]@{ name = 'dns01-delete-retry'; hostname = 'delete-retry.example.test' },
        [ordered]@{ name = 'dns01-recovery'; hostname = 'recovery.example.test' }
    )
    $routes = @{}
    foreach ($spec in $routeSpecs) {
        $routes[$spec.name] = New-TestHttpRoute -BaseUrl $baseUrl -Session $webSession `
            -ClientId $enrollment.client_id -Name $spec.name -Hostname $spec.hostname `
            -BackendPort $backendPort
    }

    $configBuilder = [Text.StringBuilder]::new()
    foreach ($spec in $routeSpecs) {
        $null = $configBuilder.AppendLine('[[http_routes]]')
        $null = $configBuilder.AppendLine("name = `"$($spec.name)`"")
        $null = $configBuilder.AppendLine("control = `"127.0.0.1:$controlPort`"")
        $null = $configBuilder.AppendLine("client_id = `"$($enrollment.client_id)`"")
        $null = $configBuilder.AppendLine("client_token = `"$($enrollment.client_token)`"")
        $null = $configBuilder.AppendLine("hostname = `"$($spec.hostname)`"")
        $null = $configBuilder.AppendLine("target = `"127.0.0.1:$backendPort`"")
        $null = $configBuilder.AppendLine()
    }
    $clientConfigPath = Join-Path $runRoot 'client.toml'
    [System.IO.File]::WriteAllText(
        $clientConfigPath,
        $configBuilder.ToString(),
        [Text.UTF8Encoding]::new($false)
    )
    $clientProcess = Start-ChildProcess -FilePath $clientPath -Arguments @(
        'run', '--config', $clientConfigPath
    )
    foreach ($route in $routes.Values) {
        $null = Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession -RouteId $route.id
        Set-TestHttpRouteEnabled -BaseUrl $baseUrl -Session $webSession `
            -RouteId $route.id -Enabled $false
    }

    $defaultAcme = Invoke-RestMethod -Uri "$baseUrl/api/v1/acme/config" -WebSession $webSession
    if ($defaultAcme.challenge_type -ne 'http-01' -or
        -not [bool]$defaultAcme.cloudflare_token_configured) {
        throw 'ACME defaults or Cloudflare credential presence are incorrect.'
    }
    $rawTokenBody = @{
        enabled = $true
        environment = 'custom'
        directory_url = 'https://localhost:14000/dir'
        contact_email = 'dns01-e2e@linklake.test'
        terms_accepted = $true
        challenge_type = 'dns-01'
        renew_before_days = 30
        cloudflare_api_token = $testToken
    } | ConvertTo-Json
    $rawTokenResponse = Invoke-WebRequest -Method Put -Uri "$baseUrl/api/v1/acme/config" `
        -WebSession $webSession -ContentType 'application/json' -Body $rawTokenBody `
        -SkipHttpErrorCheck
    if ([int]$rawTokenResponse.StatusCode -notin @(400, 422) -or
        $rawTokenResponse.Content.Contains($testToken)) {
        throw 'The ACME API did not safely reject a raw Cloudflare token field.'
    }
    $rawClearBody = $rawTokenBody | ConvertFrom-Json
    $rawClearBody.PSObject.Properties.Remove('cloudflare_api_token')
    $rawClearBody | Add-Member -NotePropertyName clear_cloudflare_api_token -NotePropertyValue $true
    $rawClearResponse = Invoke-WebRequest -Method Put -Uri "$baseUrl/api/v1/acme/config" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body ($rawClearBody | ConvertTo-Json) -SkipHttpErrorCheck
    if ([int]$rawClearResponse.StatusCode -notin @(400, 422)) {
        throw 'The ACME API did not reject the raw token-clear field.'
    }
    $unchangedAcme = Invoke-RestMethod -Uri "$baseUrl/api/v1/acme/config" -WebSession $webSession
    if ($unchangedAcme.challenge_type -ne 'http-01') {
        throw 'A rejected raw-token request unexpectedly changed ACME configuration.'
    }

    $acmeConfig = Invoke-RestMethod -Method Put -Uri "$baseUrl/api/v1/acme/config" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body (@{
            enabled = $false
            environment = 'custom'
            directory_url = 'https://localhost:14000/dir'
            contact_email = 'dns01-e2e@linklake.test'
            terms_accepted = $true
            challenge_type = 'dns-01'
            renew_before_days = 30
        } | ConvertTo-Json)
    $serializedAcmeConfig = $acmeConfig | ConvertTo-Json -Compress
    if ($acmeConfig.challenge_type -ne 'dns-01' -or
        -not [bool]$acmeConfig.cloudflare_token_configured -or
        $serializedAcmeConfig.Contains($testToken)) {
        throw 'DNS-01 ACME configuration response is incomplete or leaked the token.'
    }

    # ACME 尚未启用时先配置全部 TLS 策略，避免策略写入自动触发订单并干扰故障注入顺序。
    $wildcardIdentifier = '*.deep.sub.example.test'
    $wildcardPolicy = Set-RouteTlsPolicy -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-wildcard'].id -CertificateIdentifier $wildcardIdentifier
    if ($wildcardPolicy.certificate_identifier -ne $wildcardIdentifier) {
        throw 'Wildcard certificate identifier was not preserved in the TLS policy.'
    }
    foreach ($name in @(
        'dns01-invalid',
        'dns01-zone-error',
        'dns01-create-error',
        'dns01-delete-retry',
        'dns01-recovery'
    )) {
        $null = Set-RouteTlsPolicy -BaseUrl $baseUrl -Session $webSession `
            -RouteId $routes[$name].id -CertificateIdentifier $null
    }

    $legacyConfigUpdate = Invoke-RestMethod -Method Put -Uri "$baseUrl/api/v1/acme/config" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body (@{
            enabled = $true
            environment = 'custom'
            directory_url = 'https://localhost:14000/dir'
            contact_email = 'dns01-e2e@linklake.test'
            terms_accepted = $true
            renew_before_days = 30
        } | ConvertTo-Json)
    if ($legacyConfigUpdate.challenge_type -ne 'dns-01') {
        throw 'A legacy ACME update without challenge_type reset the configured DNS-01 mode.'
    }
    $baselineMetrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession

    # 通配符成功路径同时验证最长后缀 Zone 发现和 TXT 生命周期。
    $stateBeforeSuccess = Get-MockState -MockBaseUrl $mockBaseUrl
    $successOffset = @($stateBeforeSuccess.events).Count
    Set-TestHttpRouteEnabled -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-wildcard'].id -Enabled $true
    $null = Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-wildcard'].id
    Start-CertificateIssue -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-wildcard'].id
    $activeWildcard = Wait-RouteTlsStatus -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-wildcard'].id -ExpectedStatus 'active' -ExpectedOnline $true
    if ($activeWildcard.tls.certificate_identifier -ne $wildcardIdentifier) {
        throw 'The active route does not report its wildcard certificate identifier.'
    }
    $stateAfterSuccess = Get-MockState -MockBaseUrl $mockBaseUrl
    Assert-CloudflareLifecycle -State $stateAfterSuccess -EventOffset $successOffset `
        -ExpectedRecordName '_acme-challenge.deep.sub.example.test' `
        -ExpectedZoneId 'zone-sub' `
        -ExpectedZoneLookups @('deep.sub.example.test', 'sub.example.test')
    if (@($stateAfterSuccess.records).Count -ne 0) {
        throw 'The successful DNS-01 order left a TXT record behind.'
    }

    $routeRequest = Invoke-CurlRequest -Port $httpsPort -ServerName 'node.deep.sub.example.test' `
        -Path '/dns01'
    if ($routeRequest.StatusCode -ne 200) {
        throw "Wildcard-backed route returned HTTP $($routeRequest.StatusCode)."
    }
    $singleLabel = Invoke-CurlRequest -Port $httpsPort `
        -ServerName 'alternate.deep.sub.example.test'
    if ($singleLabel.StatusCode -ne 404) {
        throw "Single-label wildcard SNI did not complete TLS before route lookup (HTTP $($singleLabel.StatusCode))."
    }
    $null = Invoke-CurlRequest -Port $httpsPort `
        -ServerName 'nested.alternate.deep.sub.example.test' -ExpectFailure

    # 错误的权威 TXT 会令 Pebble 拒绝授权，但 LinkLake 仍必须删除自己创建的记录。
    $null = Set-MockConfig -MockBaseUrl $mockBaseUrl -Config @{ publish_mode = 'wrong' }
    $stateBeforeInvalid = Get-MockState -MockBaseUrl $mockBaseUrl
    $invalidOffset = @($stateBeforeInvalid.events).Count
    Set-TestHttpRouteEnabled -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-invalid'].id -Enabled $true
    $null = Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-invalid'].id
    Start-CertificateIssue -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-invalid'].id
    $null = Wait-RouteTlsError -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-invalid'].id
    $stateAfterInvalid = Get-MockState -MockBaseUrl $mockBaseUrl
    Assert-CloudflareLifecycle -State $stateAfterInvalid -EventOffset $invalidOffset `
        -ExpectedRecordName '_acme-challenge.invalid.example.test' `
        -ExpectedZoneId 'zone-example' `
        -ExpectedZoneLookups @('invalid.example.test', 'example.test')
    if (@($stateAfterInvalid.records).Count -ne 0) {
        throw 'The failed ACME authorization left its TXT record behind.'
    }

    # Cloudflare success=false envelope 必须被视为失败，不能继续创建记录。
    $null = Set-MockConfig -MockBaseUrl $mockBaseUrl -Config @{
        publish_mode = 'correct'
        zone_error_count = 1
    }
    $stateBeforeZoneError = Get-MockState -MockBaseUrl $mockBaseUrl
    $zoneErrorOffset = @($stateBeforeZoneError.events).Count
    Set-TestHttpRouteEnabled -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-zone-error'].id -Enabled $true
    $null = Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-zone-error'].id
    Start-CertificateIssue -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-zone-error'].id
    $null = Wait-RouteTlsError -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-zone-error'].id
    $zoneErrorEvents = @((Get-MockState -MockBaseUrl $mockBaseUrl).events | Select-Object -Skip $zoneErrorOffset)
    if (@($zoneErrorEvents | Where-Object { $_.kind -eq 'txt_created' }).Count -ne 0) {
        throw 'LinkLake created a TXT record after a failed Cloudflare zone envelope.'
    }

    $null = Set-MockConfig -MockBaseUrl $mockBaseUrl -Config @{ create_error_count = 1 }
    $stateBeforeCreateError = Get-MockState -MockBaseUrl $mockBaseUrl
    $createErrorOffset = @($stateBeforeCreateError.events).Count
    Set-TestHttpRouteEnabled -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-create-error'].id -Enabled $true
    $null = Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-create-error'].id
    Start-CertificateIssue -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-create-error'].id
    $null = Wait-RouteTlsError -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-create-error'].id
    $createErrorEvents = @((Get-MockState -MockBaseUrl $mockBaseUrl).events | Select-Object -Skip $createErrorOffset)
    if (@($createErrorEvents | Where-Object { $_.kind -eq 'txt_created' }).Count -ne 0 -or
        @((Get-MockState -MockBaseUrl $mockBaseUrl).records).Count -ne 0) {
        throw 'A rejected Cloudflare TXT create mutated Mock DNS state.'
    }

    # 删除 envelope 失败时保留私密 journal；下一次订单必须先恢复并清除孤儿记录。
    $null = Set-MockConfig -MockBaseUrl $mockBaseUrl -Config @{ delete_error_count = 1 }
    Set-TestHttpRouteEnabled -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-delete-retry'].id -Enabled $true
    $null = Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-delete-retry'].id
    Start-CertificateIssue -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-delete-retry'].id
    $null = Wait-RouteTlsStatus -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-delete-retry'].id -ExpectedStatus 'active' -ExpectedOnline $true
    $deleteFailureState = Get-MockState -MockBaseUrl $mockBaseUrl
    if (@($deleteFailureState.records).Count -ne 1 -or
        @($deleteFailureState.events | Where-Object { $_.kind -eq 'txt_delete_rejected' }).Count -lt 1) {
        throw 'Injected Cloudflare delete failure was not observed.'
    }
    $journalDirectory = Join-Path $dataDirectory 'acme/dns01-records'
    if (@(Get-ChildItem -LiteralPath $journalDirectory -Filter '*.json' -File -ErrorAction SilentlyContinue).Count -ne 1) {
        throw 'DNS-01 cleanup journal was not retained after delete failure.'
    }

    $null = Set-MockConfig -MockBaseUrl $mockBaseUrl -Config @{ delete_error_count = 0 }
    Set-TestHttpRouteEnabled -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-recovery'].id -Enabled $true
    $null = Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-recovery'].id
    Start-CertificateIssue -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-recovery'].id
    $null = Wait-RouteTlsStatus -BaseUrl $baseUrl -Session $webSession `
        -RouteId $routes['dns01-recovery'].id -ExpectedStatus 'active' -ExpectedOnline $true
    $recoveredState = Get-MockState -MockBaseUrl $mockBaseUrl
    if (@($recoveredState.records).Count -ne 0 -or
        @(Get-ChildItem -LiteralPath $journalDirectory -Filter '*.json' -File -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'The next DNS-01 order did not recover the orphaned TXT record and journal.'
    }

    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if ([uint64]$metrics.acme_dns01_challenges_total -lt
            ([uint64]$baselineMetrics.acme_dns01_challenges_total + 3) -or
        [uint64]$metrics.acme_orders_failed_total -lt
            ([uint64]$baselineMetrics.acme_orders_failed_total + 3)) {
        throw 'DNS-01 challenge or failed-order metrics did not increase as expected.'
    }
    $audit = Invoke-RestMethod -Uri "$baseUrl/api/v1/audit?limit=100" -WebSession $webSession
    if (($audit | ConvertTo-Json -Depth 8 -Compress).Contains($testToken)) {
        throw 'Cloudflare token leaked through the audit API.'
    }

    Stop-ChildProcess -Process $serverProcess
    $serverProcess = $null
    Assert-NoSecretInDirectory -Directory $dataDirectory -Secret $testToken
    Assert-NoSecretInDirectory -Directory $logDirectory -Secret $testToken
    Write-Host 'LinkLake Cloudflare DNS-01 and wildcard certificate end-to-end tests passed.'
} catch {
    if ($containersStarted) {
        Write-Host 'pebble-challtestsrv logs:'
        & docker logs $challengeContainer 2>&1
        Write-Host 'Pebble logs:'
        & docker logs $pebbleContainer 2>&1
    }
    throw
} finally {
    Stop-ChildProcess -Process $clientProcess
    Stop-ChildProcess -Process $serverProcess
    Stop-ChildProcess -Process $backendProcess
    Stop-ChildProcess -Process $mockProcess
    & docker rm --force $pebbleContainer $challengeContainer 2>$null | Out-Null
    Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
}
