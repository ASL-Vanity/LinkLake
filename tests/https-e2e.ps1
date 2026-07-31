param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Net.Http
if (Test-Path -LiteralPath 'Variable:PSNativeCommandUseErrorActionPreference') {
    $PSNativeCommandUseErrorActionPreference = $false
}
$env:NO_PROXY = '*'
$env:no_proxy = '*'

$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target/https-e2e'
$serverPath = Join-Path $targetRoot 'debug/linklake-server'
$clientPath = Join-Path $targetRoot 'debug/linklake-client'
$rootCaPath = Join-Path $PSScriptRoot 'pebble/pebble.minica.pem'
$runRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('linklake-https-e2e-' + [guid]::NewGuid())
$issuedRootCaPath = Join-Path $runRoot 'pebble-issued-root.pem'
$challengeContainer = 'linklake-challtestsrv-' + [guid]::NewGuid().ToString('N')
$pebbleContainer = 'linklake-pebble-' + [guid]::NewGuid().ToString('N')
$pebbleVersion = '2.10.1'
$serverProcess = $null
$clientProcess = $null
$backendProcess = $null
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
        throw "TCP port $Port is required by the HTTPS E2E test but is already in use."
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
        throw "UDP port $Port is required by the HTTPS E2E test but is already in use."
    } finally {
        $socket.Dispose()
    }
}

function Start-ChildProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
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

function Wait-PebbleDirectory {
    param([int]$Seconds = 45)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $arguments = @(
            '--silent', '--show-error', '--fail',
            '--cacert', $rootCaPath,
            '--output', '/dev/null',
            'https://localhost:14000/dir'
        )
        & curl @arguments
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Milliseconds 500
    }
    throw 'Pebble ACME directory did not become ready.'
}

function Export-PebbleIssuedRoot {
    $curlArguments = @(
        '--silent'
        '--show-error'
        '--fail'
        '--cacert'
        $rootCaPath
        '--output'
        $issuedRootCaPath
        'https://localhost:15000/roots/0'
    )
    & curl @curlArguments
    $issuedRoot = if (Test-Path -LiteralPath $issuedRootCaPath) {
        Get-Content -LiteralPath $issuedRootCaPath -Raw
    } else {
        ''
    }
    if ($LASTEXITCODE -ne 0 -or $issuedRoot -notmatch '-----BEGIN CERTIFICATE-----') {
        throw 'Could not export the Pebble issued-certificate root CA.'
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
        [bool]$Expected,
        [int]$Seconds = 40
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $route = Get-HttpRoute -BaseUrl $BaseUrl -Session $Session -RouteId $RouteId
        if ($null -ne $route -and [bool]$route.online -eq $Expected) { return $route }
        Start-Sleep -Milliseconds 250
    }
    throw "The HTTP route online state did not become $Expected."
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
    $observed = if ($null -eq $lastRoute) { 'route missing' } else {
        "status=$($lastRoute.tls.status), https_online=$($lastRoute.tls.https_online), error=$($lastRoute.tls.last_error_message)"
    }
    throw "Route TLS did not reach $ExpectedStatus/$ExpectedOnline. Last state: $observed"
}

function Invoke-CurlRequest {
    param(
        [ValidateSet('http', 'https')][string]$Scheme,
        [int]$Port,
        [string]$ServerName,
        [string]$Path = '/',
        [string]$Method = 'GET',
        [string]$HostHeader,
        [string]$Body,
        [switch]$ExpectFailure
    )
    $bodyPath = Join-Path $runRoot ('curl-body-' + [guid]::NewGuid())
    $headerPath = Join-Path $runRoot ('curl-headers-' + [guid]::NewGuid())
    $arguments = @(
        '--silent', '--show-error',
        '--connect-timeout', '10', '--max-time', '30',
        '--resolve', "${ServerName}:${Port}:127.0.0.1",
        '--request', $Method,
        '--dump-header', $headerPath,
        '--output', $bodyPath,
        '--write-out', '%{http_code}'
    )
    if ($Scheme -eq 'https') {
        $arguments += @('--cacert', $issuedRootCaPath)
    }
    if (-not [string]::IsNullOrEmpty($HostHeader)) {
        $arguments += @('--header', "Host: $HostHeader")
    }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $arguments += @('--header', 'Content-Type: text/plain; charset=utf-8', '--data-binary', $Body)
    }
    $arguments += "${Scheme}://${ServerName}:${Port}${Path}"
    try {
        $statusOutput = & curl @arguments
        $exitCode = $LASTEXITCODE
        if ($ExpectFailure) {
            if ($exitCode -eq 0) {
                throw "TLS request for $ServerName unexpectedly succeeded with HTTP $statusOutput."
            }
            if ($exitCode -ne 35) {
                throw "TLS request for $ServerName failed for an unexpected reason (curl exit code $exitCode, expected TLS handshake error 35)."
            }
            return [pscustomobject]@{ ExitCode = $exitCode; StatusCode = 0; Content = ''; Headers = '' }
        }
        if ($exitCode -ne 0) {
            throw "curl failed for ${Scheme}://${ServerName}:${Port}${Path} with exit code $exitCode."
        }
        return [pscustomobject]@{
            ExitCode = $exitCode
            StatusCode = [int]([string]$statusOutput).Trim()
            Content = if (Test-Path -LiteralPath $bodyPath) { Get-Content -LiteralPath $bodyPath -Raw } else { '' }
            Headers = if (Test-Path -LiteralPath $headerPath) { Get-Content -LiteralPath $headerPath -Raw } else { '' }
        }
    } finally {
        Remove-Item -LiteralPath $bodyPath, $headerPath -Force -ErrorAction SilentlyContinue
    }
}

function Assert-Status {
    param($Response, [int]$Expected, [string]$Context)
    if ($Response.StatusCode -ne $Expected) {
        throw "$Context returned HTTP $($Response.StatusCode), expected $Expected. Body: $($Response.Content)"
    }
}

function Start-LinkLakeServer {
    param([hashtable]$Environment)
    $saved = @{}
    try {
        foreach ($entry in $Environment.GetEnumerator()) {
            $saved[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
            [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process')
        }
        return Start-ChildProcess -FilePath $serverPath
    } finally {
        foreach ($entry in $saved.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
        }
    }
}

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Linux)) {
    throw 'tests/https-e2e.ps1 requires Linux because Pebble uses Docker host networking.'
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required for the HTTPS/ACME E2E test.'
}
if (-not (Get-Command curl -ErrorAction SilentlyContinue)) {
    throw 'curl is required for the HTTPS/ACME E2E test.'
}
if (-not (Test-Path -LiteralPath $rootCaPath)) {
    throw "Pebble root CA is missing: $rootCaPath"
}

New-Item -ItemType Directory -Path $runRoot | Out-Null
try {
    Assert-TcpPortAvailable -Port 5002
    Assert-TcpPortAvailable -Port 8053
    Assert-UdpPortAvailable -Port 8053
    Assert-TcpPortAvailable -Port 8055
    Assert-TcpPortAvailable -Port 14000
    Assert-TcpPortAvailable -Port 15000

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
        throw 'The HTTPS E2E binaries do not exist. Run without -SkipBuild first.'
    }

    & docker run --detach --network host --name $challengeContainer `
        "ghcr.io/letsencrypt/pebble-challtestsrv:$pebbleVersion" `
        '-http01=' '-https01=' '-tlsalpn01=' '-doh=' `
        '-dnsserver=:8053' '-management=:8055' `
        '-defaultIPv4=127.0.0.1' '-defaultIPv6='
    if ($LASTEXITCODE -ne 0) { throw 'Could not start pebble-challtestsrv.' }
    $containersStarted = $true
    Wait-TcpPort -Port 8055

    & docker run --detach --network host --name $pebbleContainer `
        --env PEBBLE_VA_NOSLEEP=1 `
        "ghcr.io/letsencrypt/pebble:$pebbleVersion" `
        -config test/config/pebble-config.json -strict -dnsserver 127.0.0.1:8053
    if ($LASTEXITCODE -ne 0) { throw 'Could not start Pebble.' }
    Wait-PebbleDirectory
    Export-PebbleIssuedRoot

    $usedPorts = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($reserved in @(5002, 8053, 8055, 14000, 15000)) { $null = $usedPorts.Add($reserved) }
    $managementPort = Get-DistinctFreePort -UsedPorts $usedPorts
    $controlPort = Get-DistinctFreePort -UsedPorts $usedPorts
    $httpsPort = Get-DistinctFreePort -UsedPorts $usedPorts
    $backendPort = Get-DistinctFreePort -UsedPorts $usedPorts
    $baseUrl = "http://127.0.0.1:$managementPort"
    $hostname = 'https-e2e.linklake.test'
    $unknownHostname = 'unknown-https-e2e.linklake.test'
    $enrollmentToken = [guid]::NewGuid().ToString()
    $adminPassword = 'LinkLake-HTTPS-E2E-Password-123!'
    $dataDirectory = Join-Path $runRoot 'data'

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
            $requestParts = $requestLine.Split(' ')
            $headers = @{}
            while ($true) {
                $line = $reader.ReadLine()
                if ([string]::IsNullOrEmpty($line)) { break }
                $separator = $line.IndexOf(':')
                if ($separator -gt 0) {
                    $headers[$line.Substring(0, $separator).Trim()] = $line.Substring($separator + 1).Trim()
                }
            }
            $contentLength = 0
            if ($headers.ContainsKey('Content-Length')) { $contentLength = [int]$headers['Content-Length'] }
            $body = ''
            if ($contentLength -gt 0) {
                $buffer = [char[]]::new($contentLength)
                $offset = 0
                while ($offset -lt $contentLength) {
                    $read = $reader.ReadBlock($buffer, $offset, $contentLength - $offset)
                    if ($read -eq 0) { break }
                    $offset += $read
                }
                $body = [string]::new($buffer, 0, $offset)
            }
            $payload = [ordered]@{
                method = $requestParts[0]
                target = $requestParts[1]
                host = [string]$headers['Host']
                forwarded_for = [string]$headers['X-Forwarded-For']
                forwarded_host = [string]$headers['X-Forwarded-Host']
                forwarded_proto = [string]$headers['X-Forwarded-Proto']
                body = $body
            } | ConvertTo-Json -Compress
            $payloadBytes = [Text.Encoding]::UTF8.GetBytes($payload)
            $responseHead = "HTTP/1.1 200 OK`r`nContent-Type: application/json; charset=utf-8`r`nContent-Length: $($payloadBytes.Length)`r`nConnection: close`r`n`r`n"
            $responseHeadBytes = [Text.Encoding]::ASCII.GetBytes($responseHead)
            $stream.Write($responseHeadBytes, 0, $responseHeadBytes.Length)
            $stream.Write($payloadBytes, 0, $payloadBytes.Length)
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

    $serverEnvironment = @{
        LINKLAKE_BIND = "127.0.0.1:$managementPort"
        LINKLAKE_CONTROL_BIND = "127.0.0.1:$controlPort"
        LINKLAKE_HTTP_BIND = '127.0.0.1:5002'
        LINKLAKE_HTTPS_BIND = "127.0.0.1:$httpsPort"
        LINKLAKE_ENROLLMENT_TOKEN = $enrollmentToken
        LINKLAKE_DATA_DIR = $dataDirectory
        LINKLAKE_ADMIN_USERNAME = 'admin'
        LINKLAKE_ADMIN_PASSWORD = $adminPassword
        LINKLAKE_ACME_ROOT_CA_PATH = $rootCaPath
        LINKLAKE_CERTIFICATE_OPERATION_COOLDOWN_SECONDS = '1'
        RUST_LOG = 'linklake_server=info'
    }
    $serverProcess = Start-LinkLakeServer -Environment $serverEnvironment
    Wait-HttpHealth -BaseUrl $baseUrl
    Wait-TcpPort -Port 5002
    Wait-TcpPort -Port $httpsPort

    $enrollment = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'https-e2e-client'; platform = 'linux' } | ConvertTo-Json)
    $login = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/login" `
        -SessionVariable webSession -ContentType 'application/json' `
        -Body (@{ username = 'admin'; password = $adminPassword } | ConvertTo-Json)
    if (-not $login.expires_unix_seconds) { throw 'Administrator login failed.' }

    $route = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/http-routes" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body (@{
            client_id = $enrollment.client_id
            name = 'https-e2e'
            hostname = $hostname
            target_addr = "127.0.0.1:$backendPort"
            max_connections = 32
        } | ConvertTo-Json)

    $configPath = Join-Path $runRoot 'client.toml'
    $clientConfig = @"
[[http_routes]]
name = "https-e2e"
control = "127.0.0.1:$controlPort"
client_id = "$($enrollment.client_id)"
client_token = "$($enrollment.client_token)"
hostname = "$hostname"
target = "127.0.0.1:$backendPort"
"@
    [System.IO.File]::WriteAllText($configPath, $clientConfig, [Text.UTF8Encoding]::new($false))
    $clientProcess = Start-ChildProcess -FilePath $clientPath -Arguments @('run', '--config', $configPath)
    $null = Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession -RouteId $route.id -Expected $true
    $baselineMetrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession

    $tlsPolicy = Invoke-RestMethod -Method Put -Uri "$baseUrl/api/v1/http-routes/$($route.id)/tls" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body (@{ mode = 'acme'; redirect_http_to_https = $true } | ConvertTo-Json)
    if ($tlsPolicy.mode -ne 'acme' -or -not $tlsPolicy.redirect_http_to_https) {
        throw 'Route ACME TLS policy was not enabled.'
    }

    $acmeConfig = Invoke-RestMethod -Method Put -Uri "$baseUrl/api/v1/acme/config" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body (@{
            enabled = $true
            environment = 'custom'
            directory_url = 'https://localhost:14000/dir'
            contact_email = 'https-e2e@linklake.test'
            terms_accepted = $true
            renew_before_days = 30
        } | ConvertTo-Json)
    if ($acmeConfig.environment -ne 'custom' -or
        $acmeConfig.directory_url -ne 'https://localhost:14000/dir' -or
        -not $acmeConfig.enabled) {
        throw 'Custom Pebble ACME configuration was not saved.'
    }

    $issueResponse = Invoke-WebRequest -Method Post `
        -Uri "$baseUrl/api/v1/http-routes/$($route.id)/certificate/issue" -WebSession $webSession `
        -SkipHttpErrorCheck
    if ([int]$issueResponse.StatusCode -ne 202) {
        $issueError = $issueResponse.Content | ConvertFrom-Json
        if ([int]$issueResponse.StatusCode -ne 409 -or
            $issueError.code -notin @(
                'certificate_operation_in_progress',
                'certificate_operation_cooldown',
                'certificate_already_valid'
            )) {
            throw "Certificate issue request failed with HTTP $($issueResponse.StatusCode): $($issueResponse.Content)"
        }
    }
    $activeRoute = Wait-RouteTlsStatus -BaseUrl $baseUrl -Session $webSession `
        -RouteId $route.id -ExpectedStatus 'active' -ExpectedOnline $true
    if ($activeRoute.tls.mode -ne 'acme' -or -not $activeRoute.tls.not_after_unix_seconds) {
        throw 'Issued certificate metadata is incomplete.'
    }

    $certificatePath = Join-Path $dataDirectory "certificates/$hostname/fullchain.pem"
    if (-not (Test-Path -LiteralPath $certificatePath)) { throw 'Issued certificate was not persisted.' }
    $firstCertificateHash = (Get-FileHash -LiteralPath $certificatePath -Algorithm SHA256).Hash
    $firstSuccess = [int64]$activeRoute.tls.last_success_unix_seconds

    $getResponse = Invoke-CurlRequest -Scheme https -Port $httpsPort -ServerName $hostname `
        -Path '/secure?value=1'
    Assert-Status -Response $getResponse -Expected 200 -Context 'HTTPS GET'
    $getPayload = $getResponse.Content | ConvertFrom-Json
    if ($getPayload.method -ne 'GET' -or $getPayload.target -ne '/secure?value=1') {
        throw 'HTTPS GET method or target was not preserved.'
    }
    if ($getPayload.forwarded_proto -ne 'https') {
        throw 'HTTPS request did not set X-Forwarded-Proto to https.'
    }
    $expectedForwardedHost = "${hostname}:${httpsPort}"
    if ($getPayload.forwarded_host -ne $expectedForwardedHost) {
        throw "HTTPS request did not preserve X-Forwarded-Host. Expected $expectedForwardedHost, got $($getPayload.forwarded_host)."
    }

    $postBody = 'LinkLake HTTPS body round trip 20260730'
    $postResponse = Invoke-CurlRequest -Scheme https -Port $httpsPort -ServerName $hostname `
        -Path '/submit' -Method POST -Body $postBody
    Assert-Status -Response $postResponse -Expected 200 -Context 'HTTPS POST'
    $postPayload = $postResponse.Content | ConvertFrom-Json
    if ($postPayload.method -ne 'POST' -or $postPayload.body -ne $postBody -or
        $postPayload.forwarded_proto -ne 'https') {
        throw 'HTTPS POST body or forwarding metadata was not preserved.'
    }

    $misdirected = Invoke-CurlRequest -Scheme https -Port $httpsPort -ServerName $hostname `
        -Path '/wrong-host' -HostHeader "${unknownHostname}:${httpsPort}"
    Assert-Status -Response $misdirected -Expected 421 -Context 'SNI and Host mismatch'

    $null = Invoke-CurlRequest -Scheme https -Port $httpsPort -ServerName $unknownHostname `
        -Path '/' -ExpectFailure
    Wait-TcpPort -Port $httpsPort

    $redirect = Invoke-CurlRequest -Scheme http -Port 5002 -ServerName $hostname `
        -Path '/redirected?value=1'
    Assert-Status -Response $redirect -Expected 308 -Context 'HTTP to HTTPS redirect'
    if ($redirect.Headers -notmatch "(?im)^location:\s*https://$([regex]::Escape($hostname))/redirected\?value=1\s*$") {
        throw "HTTP redirect Location is incorrect: $($redirect.Headers)"
    }

    Start-Sleep -Seconds 2
    $renewResponse = Invoke-WebRequest -Method Post `
        -Uri "$baseUrl/api/v1/http-routes/$($route.id)/certificate/renew" -WebSession $webSession
    if ([int]$renewResponse.StatusCode -ne 202) { throw 'Certificate renewal request was not accepted.' }
    $renewedRoute = Wait-RouteTlsStatus -BaseUrl $baseUrl -Session $webSession `
        -RouteId $route.id -ExpectedStatus 'active' -ExpectedOnline $true
    $renewDeadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $renewedCertificateHash = (Get-FileHash -LiteralPath $certificatePath -Algorithm SHA256).Hash
        if ($renewedCertificateHash -ne $firstCertificateHash) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $renewDeadline)
    if ($renewedCertificateHash -eq $firstCertificateHash) {
        throw 'Certificate renewal did not persist a new certificate.'
    }
    if ([int64]$renewedRoute.tls.last_success_unix_seconds -le $firstSuccess) {
        throw 'Certificate renewal did not update its successful completion time.'
    }

    $metrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if ([uint64]$metrics.acme_orders_total -lt ([uint64]$baselineMetrics.acme_orders_total + 2) -or
        [uint64]$metrics.acme_renewals_total -lt ([uint64]$baselineMetrics.acme_renewals_total + 1) -or
        [uint64]$metrics.acme_http01_challenges_total -lt ([uint64]$baselineMetrics.acme_http01_challenges_total + 1) -or
        [uint64]$metrics.https_requests_total -lt ([uint64]$baselineMetrics.https_requests_total + 3) -or
        [uint64]$metrics.https_handshake_failures_total -lt ([uint64]$baselineMetrics.https_handshake_failures_total + 1) -or
        [uint64]$metrics.certificates_active -lt 1) {
        throw 'HTTPS, ACME, certificate, or handshake metrics did not increase as expected.'
    }

    Stop-ChildProcess -Process $serverProcess
    $serverProcess = $null
    $serverProcess = Start-LinkLakeServer -Environment $serverEnvironment
    Wait-HttpHealth -BaseUrl $baseUrl
    Wait-TcpPort -Port $httpsPort
    $loginAfterRestart = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/login" `
        -SessionVariable restartedSession -ContentType 'application/json' `
        -Body (@{ username = 'admin'; password = $adminPassword } | ConvertTo-Json)
    if (-not $loginAfterRestart.expires_unix_seconds) { throw 'Administrator login after restart failed.' }
    $null = Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $restartedSession `
        -RouteId $route.id -Expected $true
    $restoredRoute = Wait-RouteTlsStatus -BaseUrl $baseUrl -Session $restartedSession `
        -RouteId $route.id -ExpectedStatus 'active' -ExpectedOnline $true -Seconds 30
    $restoredResponse = Invoke-CurlRequest -Scheme https -Port $httpsPort -ServerName $hostname `
        -Path '/restored'
    Assert-Status -Response $restoredResponse -Expected 200 -Context 'HTTPS after server restart'
    if ((Get-FileHash -LiteralPath $certificatePath -Algorithm SHA256).Hash -ne $renewedCertificateHash) {
        throw 'Server restart did not reuse the persisted renewed certificate.'
    }
    if (-not $restoredRoute.tls.https_online) { throw 'Restored certificate was not loaded into SNI.' }

    $null = Invoke-CurlRequest -Scheme https -Port $httpsPort -ServerName $unknownHostname `
        -Path '/' -ExpectFailure
    $disabledPolicy = Invoke-RestMethod -Method Put `
        -Uri "$baseUrl/api/v1/http-routes/$($route.id)/tls" -WebSession $restartedSession `
        -ContentType 'application/json' `
        -Body (@{ mode = 'disabled'; redirect_http_to_https = $false } | ConvertTo-Json)
    if ($disabledPolicy.mode -ne 'disabled') { throw 'Route TLS policy was not disabled.' }
    $null = Wait-RouteTlsStatus -BaseUrl $baseUrl -Session $restartedSession `
        -RouteId $route.id -ExpectedStatus 'disabled' -ExpectedOnline $false -Seconds 20
    $null = Invoke-CurlRequest -Scheme https -Port $httpsPort -ServerName $hostname `
        -Path '/' -ExpectFailure
    Wait-TcpPort -Port $httpsPort

    $finalMetrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $restartedSession
    if ([uint64]$finalMetrics.https_handshake_failures_total -lt 2 -or
        [uint64]$finalMetrics.https_requests_total -lt 1) {
        throw 'HTTPS metrics after restart did not record restored traffic and rejected handshakes.'
    }

    Write-Host 'LinkLake HTTPS and Pebble ACME end-to-end tests passed.'
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
    & docker rm --force $pebbleContainer $challengeContainer 2>$null | Out-Null
    Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
}
