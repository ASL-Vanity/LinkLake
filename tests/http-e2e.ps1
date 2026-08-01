param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['Invoke-RestMethod:Headers'] = @{ 'X-LinkLake-CSRF' = '1' }
Add-Type -AssemblyName System.Net.Http
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target\e2e'
$serverPath = Join-Path $targetRoot 'debug\linklake-server.exe'
$clientPath = Join-Path $targetRoot 'debug\linklake-client.exe'
$runRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('linklake-http-e2e-' + [guid]::NewGuid())
$serverProcess = $null
$clientProcess = $null
$backendProcess = $null
$routeHttpClient = $null
$stage = 'initialization'
$testPassed = $false

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Get-FreePublicPort {
    foreach ($candidate in (32000..32999 | Sort-Object { Get-Random })) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $candidate)
        try {
            $listener.Start()
            return $candidate
        } catch {
        } finally {
            try { $listener.Stop() } catch {}
        }
    }
    throw 'No free public TCP port is available in 32000-32999.'
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

function Wait-TcpPort {
    param([int]$Port, [int]$Seconds = 20)
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
        [int]$Seconds = 30
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $route = Get-HttpRoute -BaseUrl $BaseUrl -Session $Session -RouteId $RouteId
        if ($null -ne $route -and [bool]$route.online -eq $Expected) { return }
        Start-Sleep -Milliseconds 200
    }
    throw "The HTTP route online state did not become $Expected."
}

function Get-HttpProxy {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$ProxyId
    )
    $proxies = Invoke-RestMethod -Uri "$BaseUrl/api/v1/http-proxies" -WebSession $Session
    return $proxies | Where-Object { $_.id -eq $ProxyId } | Select-Object -First 1
}

function Wait-HttpProxyOnline {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$ProxyId,
        [bool]$Expected,
        [int]$Seconds = 30
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $proxy = Get-HttpProxy -BaseUrl $BaseUrl -Session $Session -ProxyId $ProxyId
        if ($null -ne $proxy -and [bool]$proxy.online -eq $Expected) { return }
        Start-Sleep -Milliseconds 200
    }
    throw "The HTTP proxy online state did not become $Expected."
}

function Wait-HttpProxyIdle {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$ProxyId,
        [int]$Seconds = 10
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $proxy = Get-HttpProxy -BaseUrl $BaseUrl -Session $Session -ProxyId $ProxyId
        if ($null -ne $proxy -and $proxy.active_connections -eq 0) { return }
        Start-Sleep -Milliseconds 100
    }
    $active = if ($null -eq $proxy) { 'missing policy' } else { [string]$proxy.active_connections }
    throw "The HTTP proxy connection permit was not released during ${script:stage}; active=$active."
}

function Get-ProxyAuthorization {
    param([string]$Username, [string]$Password)
    return [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))
}

function Invoke-RawProxyRequest {
    param([string]$RequestText, [int]$ReceiveTimeout = 10000)
    $client = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $proxyPort)
    try {
        $client.ReceiveTimeout = $ReceiveTimeout
        $stream = $client.GetStream()
        $requestBytes = [Text.Encoding]::ASCII.GetBytes($RequestText)
        $stream.Write($requestBytes, 0, $requestBytes.Length)
        $stream.Flush()
        try {
            $head = Read-ProxyResponseHead -Stream $stream
            $contentLength = 0
            if ($head -match '(?im)^Content-Length:\s*(\d+)\s*$') {
                $contentLength = [int]$Matches[1]
            }
            $body = [byte[]]::new($contentLength)
            $offset = 0
            while ($offset -lt $contentLength) {
                $read = $stream.Read($body, $offset, $contentLength - $offset)
                if ($read -eq 0) { throw 'The HTTP proxy response body closed early.' }
                $offset += $read
            }
            return $head + [Text.Encoding]::UTF8.GetString($body)
        } catch {
            throw "HTTP proxy request failed during ${script:stage}: $($_.Exception.Message)"
        }
    } finally {
        $client.Dispose()
    }
}

function Read-ProxyResponseHead {
    param([System.IO.Stream]$Stream)
    $bytes = [System.Collections.Generic.List[byte]]::new()
    while ($bytes.Count -lt 65536) {
        $value = $Stream.ReadByte()
        if ($value -lt 0) { throw 'The HTTP proxy closed before returning a complete response head.' }
        $bytes.Add([byte]$value)
        if ($bytes.Count -ge 4 -and $bytes[$bytes.Count - 4] -eq 13 -and
            $bytes[$bytes.Count - 3] -eq 10 -and $bytes[$bytes.Count - 2] -eq 13 -and
            $bytes[$bytes.Count - 1] -eq 10) {
            return [Text.Encoding]::ASCII.GetString($bytes.ToArray())
        }
    }
    throw 'The HTTP proxy response head exceeded 65536 bytes.'
}

function Invoke-RouteRequest {
    param(
        [string]$Method = 'GET',
        [string]$Path = '/',
        [string]$HostHeader,
        [string]$Body,
        [hashtable]$Headers = @{}
    )
    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($Method),
        "http://127.0.0.1:$httpPort$Path"
    )
    try {
        $request.Headers.Host = $HostHeader
        foreach ($entry in $Headers.GetEnumerator()) {
            $null = $request.Headers.TryAddWithoutValidation([string]$entry.Key, [string]$entry.Value)
        }
        if ($PSBoundParameters.ContainsKey('Body')) {
            $request.Content = [System.Net.Http.StringContent]::new(
                $Body,
                [Text.Encoding]::UTF8,
                'text/plain'
            )
        }
        $response = $script:routeHttpClient.SendAsync($request).GetAwaiter().GetResult()
        try {
            return [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                Content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $request.Dispose()
    }
}

function Invoke-RawHttpRequest {
    param([string]$RequestText)
    $client = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $httpPort)
    try {
        $client.ReceiveTimeout = 10000
        $stream = $client.GetStream()
        $requestBytes = [Text.Encoding]::ASCII.GetBytes($RequestText)
        $stream.Write($requestBytes, 0, $requestBytes.Length)
        $stream.Flush()
        $buffer = [byte[]]::new(16384)
        $response = [System.IO.MemoryStream]::new()
        try {
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $response.Write($buffer, 0, $read)
            }
            return [Text.Encoding]::UTF8.GetString($response.ToArray())
        } finally {
            $response.Dispose()
        }
    } finally {
        $client.Dispose()
    }
}

function Assert-RawHttpStatus {
    param([string]$Response, [int]$Expected, [string]$Context)
    if ($Response -notmatch "^HTTP/1\.[01] $Expected(?: |`r`n)") {
        throw "$Context did not return HTTP $Expected. Response: $Response"
    }
}

function Assert-Status {
    param($Response, [int]$Expected, [string]$Context)
    if ($Response.StatusCode -ne $Expected) {
        throw "$Context returned HTTP $($Response.StatusCode), expected $Expected. Body: $($Response.Content)"
    }
}

function Wait-HttpMetrics {
    param(
        [string]$BaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [uint64]$MinimumRequests,
        [uint64]$MinimumBytesFromPublic
    )
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        $metrics = Invoke-RestMethod -Uri "$BaseUrl/api/v1/metrics" -WebSession $Session
        if ($metrics.http_requests_total -ge $MinimumRequests -and
            $metrics.http_bytes_from_public -ge $MinimumBytesFromPublic -and
            $metrics.http_bytes_to_public -gt 0) {
            return $metrics
        }
        Start-Sleep -Milliseconds 100
    }
    throw 'HTTP metrics did not reach the expected values.'
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
    $httpPort = Get-FreePort
    $proxyPort = Get-FreePublicPort
    $backendPort = Get-FreePort
    $baseUrl = "http://127.0.0.1:$managementPort"
    $hostname = 'site.e2e.test'
    $enrollmentToken = [guid]::NewGuid().ToString()
    $adminPassword = 'LinkLake-HTTP-E2E-Password-123!'

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
            if ($requestParts.Count -lt 2) { continue }
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
            if ($headers.ContainsKey('Content-Length')) {
                $contentLength = [int]$headers['Content-Length']
            }
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
                proxy_authorization = [string]$headers['Proxy-Authorization']
                body = $body
            } | ConvertTo-Json -Compress
            $payloadBytes = [Text.Encoding]::UTF8.GetBytes($payload)
            $responseHead = "HTTP/1.1 200 OK`r`nContent-Type: application/json; charset=utf-8`r`nContent-Length: $($payloadBytes.Length)`r`nConnection: close`r`n`r`n"
            $responseHeadBytes = [Text.Encoding]::ASCII.GetBytes($responseHead)
            $stream.Write($responseHeadBytes, 0, $responseHeadBytes.Length)
            $stream.Write($payloadBytes, 0, $payloadBytes.Length)
            $stream.Flush()
        } catch {
            # 测试后端继续接受后续连接，由主测试负责断言响应。
        } finally {
            $client.Dispose()
        }
    }
} finally {
    $listener.Stop()
}
'@.Replace('__BACKEND_PORT__', [string]$backendPort)
    $backendCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($backendScript))
    $backendProcess = Start-HiddenProcess -FilePath 'powershell.exe' -Arguments @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $backendCommand
    )
    Wait-TcpPort -Port $backendPort

    $oldEnvironment = @{
        LINKLAKE_BIND = $env:LINKLAKE_BIND
        LINKLAKE_CONTROL_BIND = $env:LINKLAKE_CONTROL_BIND
        LINKLAKE_HTTP_BIND = $env:LINKLAKE_HTTP_BIND
        LINKLAKE_ENROLLMENT_TOKEN = $env:LINKLAKE_ENROLLMENT_TOKEN
        LINKLAKE_DATA_DIR = $env:LINKLAKE_DATA_DIR
        LINKLAKE_ADMIN_USERNAME = $env:LINKLAKE_ADMIN_USERNAME
        LINKLAKE_ADMIN_PASSWORD = $env:LINKLAKE_ADMIN_PASSWORD
    }
    try {
        $env:LINKLAKE_BIND = "127.0.0.1:$managementPort"
        $env:LINKLAKE_CONTROL_BIND = "127.0.0.1:$controlPort"
        $env:LINKLAKE_HTTP_BIND = "127.0.0.1:$httpPort"
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
    Wait-TcpPort -Port $httpPort
    $enrollment = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" `
        -Headers @{ Authorization = "Bearer $enrollmentToken" } -ContentType 'application/json' `
        -Body (@{ name = 'http-e2e-client'; platform = 'windows' } | ConvertTo-Json)
    $login = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/login" `
        -SessionVariable webSession -ContentType 'application/json' `
        -Body (@{ username = 'admin'; password = $adminPassword } | ConvertTo-Json)
    if (-not $login.expires_unix_seconds) { throw 'Administrator login failed.' }

    $route = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/http-routes" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body (@{
            client_id = $enrollment.client_id
            name = 'http-e2e'
            hostname = $hostname
            target_addr = "127.0.0.1:$backendPort"
            max_connections = 64
        } | ConvertTo-Json)
    $proxy = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/http-proxies" `
        -WebSession $webSession -ContentType 'application/json' `
        -Body (@{
            client_id = $enrollment.client_id
            name = 'http-forward-e2e'
            public_port = $proxyPort
            username = 'proxy-user'
            max_connections = 1
        } | ConvertTo-Json)
    if ($proxy.password -notmatch '^llh_[0-9a-f]{64}$') {
        throw 'The generated HTTP proxy password has an invalid format.'
    }
    $listedProxyJson = Invoke-RestMethod -Uri "$baseUrl/api/v1/http-proxies" -WebSession $webSession |
        ConvertTo-Json -Depth 8
    if ($listedProxyJson -match 'password' -or $listedProxyJson -match [regex]::Escape($proxy.password)) {
        throw 'The one-time HTTP proxy password leaked through the list API.'
    }
    Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession -RouteId $route.id -Expected $false
    Wait-HttpProxyOnline -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id -Expected $false

    $configPath = Join-Path $runRoot 'client.toml'
    $clientConfig = @"
[client]
control = "127.0.0.1:$controlPort"
client_id = "$($enrollment.client_id)"
client_token = "$($enrollment.client_token)"
config_mode = "local"

[[http_routes]]
name = "http-e2e"
hostname = "$hostname"
target = "127.0.0.1:$backendPort"

[[http_proxies]]
name = "http-forward-e2e"
public_port = $proxyPort
"@
    [System.IO.File]::WriteAllText($configPath, $clientConfig, [Text.UTF8Encoding]::new($false))
    $clientArguments = @('run', '--config', "`"$configPath`"")
    $clientProcess = Start-HiddenProcess -FilePath $clientPath -Arguments $clientArguments
    Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession -RouteId $route.id -Expected $true
    Wait-HttpProxyOnline -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id -Expected $true

    $routeHttpClient = [System.Net.Http.HttpClient]::new()
    $routeHttpClient.Timeout = [TimeSpan]::FromSeconds(60)
    $baselineMetrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession

    $proxyAuth = Get-ProxyAuthorization -Username $proxy.username -Password $proxy.password
    $stage = 'missing authentication'
    $noAuthResponse = Invoke-RawProxyRequest -RequestText "GET http://127.0.0.1:$backendPort/no-auth HTTP/1.1`r`nHost: 127.0.0.1:$backendPort`r`nConnection: close`r`n`r`n"
    Assert-RawHttpStatus -Response $noAuthResponse -Expected 407 -Context 'HTTP proxy missing authentication'

    $stage = 'wrong authentication'
    $wrongAuth = Get-ProxyAuthorization -Username $proxy.username -Password ("llh_" + ('0' * 64))
    $wrongAuthResponse = Invoke-RawProxyRequest -RequestText "GET http://127.0.0.1:$backendPort/wrong-auth HTTP/1.1`r`nHost: 127.0.0.1:$backendPort`r`nProxy-Authorization: Basic $wrongAuth`r`nConnection: close`r`n`r`n"
    Assert-RawHttpStatus -Response $wrongAuthResponse -Expected 407 -Context 'HTTP proxy wrong authentication'

    $stage = 'absolute-form GET'
    $forwardResponse = Invoke-RawProxyRequest -RequestText "GET http://127.0.0.1:$backendPort/proxy-get?value=1 HTTP/1.1`r`nHost: 127.0.0.1:$backendPort`r`nProxy-Authorization: Basic $proxyAuth`r`nProxy-Connection: keep-alive`r`nX-Proxy-Test: yes`r`n`r`n"
    Assert-RawHttpStatus -Response $forwardResponse -Expected 200 -Context 'Authenticated HTTP forward proxy GET'
    $forwardPayload = $forwardResponse.Substring($forwardResponse.IndexOf("`r`n`r`n") + 4) | ConvertFrom-Json
    if ($forwardPayload.target -ne '/proxy-get?value=1' -or $forwardPayload.host -ne "127.0.0.1:$backendPort") {
        throw 'The HTTP proxy did not convert the absolute URI to origin-form.'
    }
    if (-not [string]::IsNullOrEmpty($forwardPayload.proxy_authorization)) {
        throw 'Proxy-Authorization leaked to the target HTTP service.'
    }
    Wait-HttpProxyIdle -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id

    $stage = 'absolute-form POST'
    $proxyPostBody = 'LinkLake HTTP forward proxy body 20260730'
    $proxyPostLength = [Text.Encoding]::UTF8.GetByteCount($proxyPostBody)
    $proxyPostResponse = Invoke-RawProxyRequest -RequestText "POST http://127.0.0.1:$backendPort/proxy-post HTTP/1.1`r`nHost: 127.0.0.1:$backendPort`r`nProxy-Authorization: Basic $proxyAuth`r`nContent-Length: $proxyPostLength`r`n`r`n$proxyPostBody"
    Assert-RawHttpStatus -Response $proxyPostResponse -Expected 200 -Context 'Authenticated HTTP forward proxy POST'
    $proxyPostPayload = $proxyPostResponse.Substring($proxyPostResponse.IndexOf("`r`n`r`n") + 4) | ConvertFrom-Json
    if ($proxyPostPayload.body -ne $proxyPostBody) { throw 'The HTTP proxy POST body was corrupted.' }
    Wait-HttpProxyIdle -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id

    $stage = 'ambiguous framing'
    $ambiguousResponse = Invoke-RawProxyRequest -RequestText "POST http://127.0.0.1:$backendPort/smuggling HTTP/1.1`r`nHost: 127.0.0.1:$backendPort`r`nProxy-Authorization: Basic $proxyAuth`r`nContent-Length: 1`r`nTransfer-Encoding: chunked`r`n`r`n0`r`n`r`n"
    Assert-RawHttpStatus -Response $ambiguousResponse -Expected 400 -Context 'Ambiguous HTTP proxy message framing'

    $stage = 'CONNECT'
    $connectClient = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $proxyPort)
    try {
        $connectClient.ReceiveTimeout = 10000
        $connectStream = $connectClient.GetStream()
        $connectRequest = "CONNECT 127.0.0.1:$backendPort HTTP/1.1`r`nHost: 127.0.0.1:$backendPort`r`nProxy-Authorization: Basic $proxyAuth`r`n`r`n"
        $connectBytes = [Text.Encoding]::ASCII.GetBytes($connectRequest)
        $connectStream.Write($connectBytes, 0, $connectBytes.Length)
        $connectStream.Flush()
        $connectHead = Read-ProxyResponseHead -Stream $connectStream
        Assert-RawHttpStatus -Response $connectHead -Expected 200 -Context 'HTTP proxy CONNECT'

        $limitEnforced = $false
        try {
            $limitedResponse = Invoke-RawProxyRequest -RequestText "GET http://127.0.0.1:$backendPort/limited HTTP/1.1`r`nHost: 127.0.0.1:$backendPort`r`nProxy-Authorization: Basic $proxyAuth`r`n`r`n" -ReceiveTimeout 2000
            $limitEnforced = [string]::IsNullOrEmpty($limitedResponse)
        } catch {
            $limitEnforced = $true
        }
        if (-not $limitEnforced) { throw 'The HTTP proxy connection limit was not enforced.' }

        $tunneledRequest = "GET /through-connect HTTP/1.1`r`nHost: 127.0.0.1:$backendPort`r`nConnection: close`r`n`r`n"
        $tunneledBytes = [Text.Encoding]::ASCII.GetBytes($tunneledRequest)
        $connectStream.Write($tunneledBytes, 0, $tunneledBytes.Length)
        $connectStream.Flush()
        $tunneledHead = Read-ProxyResponseHead -Stream $connectStream
        if ($tunneledHead -notmatch '(?im)^Content-Length:\s*(\d+)\s*$') {
            throw 'The tunneled HTTP response did not include Content-Length.'
        }
        $tunneledLength = [int]$Matches[1]
        $tunneledBody = [byte[]]::new($tunneledLength)
        $offset = 0
        while ($offset -lt $tunneledLength) {
            $read = $connectStream.Read($tunneledBody, $offset, $tunneledLength - $offset)
            if ($read -eq 0) { throw 'The tunneled HTTP response body closed early.' }
            $offset += $read
        }
        $tunneledResponse = $tunneledHead + [Text.Encoding]::UTF8.GetString($tunneledBody)
        Assert-RawHttpStatus -Response $tunneledResponse -Expected 200 -Context 'HTTP request through CONNECT tunnel'
        $tunneledPayload = $tunneledResponse.Substring($tunneledResponse.IndexOf("`r`n`r`n") + 4) | ConvertFrom-Json
        if ($tunneledPayload.target -ne '/through-connect') { throw 'CONNECT tunnel payload was corrupted.' }
    } finally {
        if ($connectStream) { $connectStream.Dispose() }
        $connectClient.Dispose()
    }

    Wait-HttpProxyIdle -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id

    $getResponse = Invoke-RouteRequest -Path '/hello?value=1' -HostHeader $hostname -Headers @{
        'X-Real-IP' = '198.51.100.44'
        'X-Forwarded-For' = '203.0.113.10'
        'X-Forwarded-Host' = 'spoofed.invalid'
        'X-Forwarded-Proto' = 'https'
    }
    Assert-Status -Response $getResponse -Expected 200 -Context 'Exact Host GET'
    $getPayload = $getResponse.Content | ConvertFrom-Json
    if ($getPayload.method -ne 'GET' -or $getPayload.target -ne '/hello?value=1') {
        throw 'The GET method or request target was not preserved.'
    }
    if ($getPayload.host -ne $hostname) { throw 'The Host header was not preserved.' }
    if ($getPayload.forwarded_for -ne '198.51.100.44') { throw 'X-Forwarded-For was not replaced with the trusted reverse-proxy client address.' }
    if ($getPayload.forwarded_host -ne $hostname) { throw 'X-Forwarded-Host did not preserve the original Host.' }
    if ($getPayload.forwarded_proto -ne 'https') { throw 'The trusted reverse-proxy protocol was not preserved.' }

    $caseResponse = Invoke-RouteRequest -Path '/case' -HostHeader $hostname.ToUpperInvariant()
    Assert-Status -Response $caseResponse -Expected 200 -Context 'Case-insensitive Host GET'
    $casePayload = $caseResponse.Content | ConvertFrom-Json
    if ($casePayload.forwarded_host -ne $hostname.ToUpperInvariant()) { throw 'Uppercase Host was not preserved.' }

    $portResponse = Invoke-RouteRequest -Path '/with-port' -HostHeader "${hostname}:$httpPort"
    Assert-Status -Response $portResponse -Expected 200 -Context 'Host with port GET'
    $portPayload = $portResponse.Content | ConvertFrom-Json
    if ($portPayload.forwarded_host -ne "${hostname}:$httpPort") { throw 'Host with port was not preserved.' }

    $unknownResponse = Invoke-RouteRequest -Path '/missing' -HostHeader 'unknown.e2e.test'
    Assert-Status -Response $unknownResponse -Expected 404 -Context 'Unknown Host'

    $duplicateHost = Invoke-RawHttpRequest -RequestText "GET /duplicate HTTP/1.1`r`nHost: $hostname`r`nHost: unknown.e2e.test`r`nConnection: close`r`n`r`n"
    Assert-RawHttpStatus -Response $duplicateHost -Expected 400 -Context 'Duplicate Host'

    $conflictingAuthority = Invoke-RawHttpRequest -RequestText "GET http://unknown.e2e.test/conflict HTTP/1.1`r`nHost: $hostname`r`nConnection: close`r`n`r`n"
    Assert-RawHttpStatus -Response $conflictingAuthority -Expected 400 -Context 'Conflicting absolute-form authority'

    $matchingAuthority = Invoke-RawHttpRequest -RequestText "GET http://$hostname/absolute?value=1 HTTP/1.1`r`nHost: $hostname`r`nConnection: close`r`n`r`n"
    Assert-RawHttpStatus -Response $matchingAuthority -Expected 200 -Context 'Matching absolute-form authority'
    $matchingAuthorityBody = $matchingAuthority.Substring($matchingAuthority.IndexOf("`r`n`r`n") + 4) | ConvertFrom-Json
    if ($matchingAuthorityBody.target -ne '/absolute?value=1') {
        throw 'The absolute-form request target was not converted to origin-form.'
    }

    $postBody = 'LinkLake HTTP body round trip 20260729'
    $postResponse = Invoke-RouteRequest -Method POST -Path '/submit' -HostHeader $hostname -Body $postBody
    Assert-Status -Response $postResponse -Expected 200 -Context 'POST body'
    $postPayload = $postResponse.Content | ConvertFrom-Json
    if ($postPayload.method -ne 'POST' -or $postPayload.body -ne $postBody) {
        throw 'The POST method or body was not preserved.'
    }

    $concurrentRequests = [System.Collections.Generic.List[System.Net.Http.HttpRequestMessage]]::new()
    $concurrentTasks = [System.Collections.Generic.List[System.Threading.Tasks.Task[System.Net.Http.HttpResponseMessage]]]::new()
    for ($index = 0; $index -lt 20; $index++) {
        $request = [System.Net.Http.HttpRequestMessage]::new(
            [System.Net.Http.HttpMethod]::Get,
            "http://127.0.0.1:$httpPort/concurrent/$index"
        )
        $request.Headers.Host = $hostname
        $concurrentRequests.Add($request)
        $concurrentTasks.Add($routeHttpClient.SendAsync($request))
    }
    try {
        for ($index = 0; $index -lt $concurrentTasks.Count; $index++) {
            $response = $concurrentTasks[$index].GetAwaiter().GetResult()
            try {
                if ([int]$response.StatusCode -ne 200) {
                    throw "Concurrent HTTP request $index returned $([int]$response.StatusCode)."
                }
                $payload = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
                if ($payload.target -ne "/concurrent/$index") {
                    throw "Concurrent HTTP response $index was routed to the wrong request target."
                }
            } finally {
                $response.Dispose()
            }
        }
    } finally {
        foreach ($request in $concurrentRequests) { $request.Dispose() }
    }

    $minimumRequests = [uint64]$baselineMetrics.http_requests_total + 24
    $minimumBytes = [uint64]$baselineMetrics.http_bytes_from_public + [Text.Encoding]::UTF8.GetByteCount($postBody)
    $metrics = Wait-HttpMetrics -BaseUrl $baseUrl -Session $webSession `
        -MinimumRequests $minimumRequests -MinimumBytesFromPublic $minimumBytes
    $routeView = Get-HttpRoute -BaseUrl $baseUrl -Session $webSession -RouteId $route.id
    if ($routeView.requests_total -lt 24 -or $routeView.bytes_from_public -lt [Text.Encoding]::UTF8.GetByteCount($postBody) -or $routeView.bytes_to_public -eq 0) {
        throw 'Per-route HTTP metrics were not updated.'
    }
    $proxyView = Get-HttpProxy -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id
    $proxyMetrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if ($proxyView.requests_total -lt 3 -or $proxyView.connect_requests -lt 1 -or
        $proxyView.authentication_failures -lt 2 -or $proxyView.malformed_requests -lt 1 -or
        $proxyView.rejected_connections -lt 1 -or $proxyView.bytes_from_public -eq 0 -or
        $proxyView.bytes_to_public -eq 0 -or $proxyMetrics.http_proxy_requests_total -lt 3 -or
        $proxyMetrics.http_proxy_connect_requests -lt 1) {
        throw 'HTTP forward proxy policy or aggregate metrics were not updated.'
    }

    Stop-Process -Id $clientProcess.Id -Force
    $clientProcess.WaitForExit()
    Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession -RouteId $route.id -Expected $false
    Wait-HttpProxyOnline -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id -Expected $false
    $offlineResponse = Invoke-RouteRequest -Path '/offline' -HostHeader $hostname
    Assert-Status -Response $offlineResponse -Expected 503 -Context 'Offline HTTP route'

    $clientProcess = Start-HiddenProcess -FilePath $clientPath -Arguments $clientArguments
    Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession -RouteId $route.id -Expected $true -Seconds 40
    Wait-HttpProxyOnline -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id -Expected $true -Seconds 40
    $recoveredResponse = Invoke-RouteRequest -Path '/recovered' -HostHeader $hostname
    Assert-Status -Response $recoveredResponse -Expected 200 -Context 'Recovered HTTP route'
    $reconnectMetrics = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics" -WebSession $webSession
    if ($reconnectMetrics.tunnel_reconnects_total -lt 1) { throw 'The HTTP route reconnect metric was not updated.' }

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/http-routes/$($route.id)/enabled" `
        -WebSession $webSession -ContentType 'application/json' -Body '{"enabled":false}'
    Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession -RouteId $route.id -Expected $false
    $disabledResponse = Invoke-RouteRequest -Path '/disabled' -HostHeader $hostname
    Assert-Status -Response $disabledResponse -Expected 404 -Context 'Disabled HTTP route'

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/http-routes/$($route.id)/enabled" `
        -WebSession $webSession -ContentType 'application/json' -Body '{"enabled":true}'
    Wait-HttpRouteOnline -BaseUrl $baseUrl -Session $webSession -RouteId $route.id -Expected $true -Seconds 40
    $enabledResponse = Invoke-RouteRequest -Path '/enabled' -HostHeader $hostname
    Assert-Status -Response $enabledResponse -Expected 200 -Context 'Re-enabled HTTP route'

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/http-proxies/$($proxy.id)/enabled" `
        -WebSession $webSession -ContentType 'application/json' -Body '{"enabled":false}'
    Wait-HttpProxyOnline -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id -Expected $false
    $disabledProxyRejected = $false
    try {
        $null = Invoke-RawProxyRequest -RequestText "GET http://127.0.0.1:$backendPort/disabled-proxy HTTP/1.1`r`nHost: 127.0.0.1:$backendPort`r`nProxy-Authorization: Basic $proxyAuth`r`n`r`n" -ReceiveTimeout 2000
    } catch {
        $disabledProxyRejected = $true
    }
    if (-not $disabledProxyRejected) { throw 'The disabled HTTP proxy still accepted connections.' }

    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/http-proxies/$($proxy.id)/enabled" `
        -WebSession $webSession -ContentType 'application/json' -Body '{"enabled":true}'
    Wait-HttpProxyOnline -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id -Expected $true -Seconds 40
    $recoveredProxy = Invoke-RawProxyRequest -RequestText "GET http://127.0.0.1:$backendPort/recovered-proxy HTTP/1.1`r`nHost: 127.0.0.1:$backendPort`r`nProxy-Authorization: Basic $proxyAuth`r`n`r`n"
    Assert-RawHttpStatus -Response $recoveredProxy -Expected 200 -Context 'Re-enabled HTTP proxy'

    Invoke-RestMethod -Method Delete -Uri "$baseUrl/api/v1/http-routes/$($route.id)" -WebSession $webSession
    $deleted = Get-HttpRoute -BaseUrl $baseUrl -Session $webSession -RouteId $route.id
    if ($null -ne $deleted) { throw 'The deleted HTTP route remained in the management API.' }
    $deletedResponse = Invoke-RouteRequest -Path '/deleted' -HostHeader $hostname
    Assert-Status -Response $deletedResponse -Expected 404 -Context 'Deleted HTTP route'

    Invoke-RestMethod -Method Delete -Uri "$baseUrl/api/v1/http-proxies/$($proxy.id)" -WebSession $webSession
    $deletedProxy = Get-HttpProxy -BaseUrl $baseUrl -Session $webSession -ProxyId $proxy.id
    if ($null -ne $deletedProxy) { throw 'The deleted HTTP proxy remained in the management API.' }

    Write-Host 'HTTP E2E passed: host routing plus authenticated forward proxy, absolute-form rewrite, CONNECT, smuggling rejection, limits, metrics, reconnect, and lifecycle.'
    $testPassed = $true
} finally {
    if ($routeHttpClient) { $routeHttpClient.Dispose() }
    foreach ($process in @($clientProcess, $serverProcess, $backendProcess)) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
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
        Write-Warning "HTTP E2E artifacts were preserved at $runRoot"
    }
}
