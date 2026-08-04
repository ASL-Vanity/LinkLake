param(
    [string]$ServerExe = "",
    [int]$ManagementPort = 39210,
    [int]$ControlPort = 39211,
    [int]$UdpRelayPort = 39212,
    [ValidateSet('chromium', 'firefox', 'webkit')][string]$BrowserEngine = 'chromium',
    [string]$BrowserPath = '',
    [string]$BrowserLabel = 'Playwright Chromium',
    [ValidatePattern('^[A-Za-z0-9._-]+$')][string]$OutputName = 'webui-smoke',
    [switch]$KeepData,
    [switch]$KeepServer
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($ServerExe)) {
    $ServerExe = Join-Path $projectRoot 'target\debug\linklake-server.exe'
    if (-not (Test-Path -LiteralPath $ServerExe -PathType Leaf)) {
        & cargo build --locked -p linklake-server
        if ($LASTEXITCODE -ne 0) { throw 'Could not build the WebUI smoke-test server.' }
    }
}
$ServerExe = (Resolve-Path -LiteralPath $ServerExe).Path
$dataDir = Join-Path $projectRoot '.tmp-webui-smoke-data'
$tlsDir = Join-Path $projectRoot '.tmp-webui-smoke-tls'
$outputDir = Join-Path $projectRoot "target\$OutputName"
$serverLog = Join-Path $outputDir 'server.log'
$baseUrl = "http://127.0.0.1:$ManagementPort"
$adminUsername = 'admin'
$adminPassword = 'LinkLake-Smoke-2026!'
$enrollmentToken = 'linklake-smoke-enrollment'
$managementToken = 'linklake-smoke-management'
$controlCertificate = Join-Path $tlsDir 'control-cert.pem'
$controlPrivateKey = Join-Path $tlsDir 'control-key.pem'
$serverProcess = $null

function Remove-SmokeDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedName
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $expectedParent = (Resolve-Path -LiteralPath $projectRoot).Path
    if ((Split-Path -Parent $resolved) -ne $expectedParent -or (Split-Path -Leaf $resolved) -ne $ExpectedName) {
        throw "Refusing to delete unexpected smoke-test path: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Remove-SmokeData {
    param([string]$Path)
    Remove-SmokeDirectory -Path $Path -ExpectedName '.tmp-webui-smoke-data'
}

function Reset-SmokeOutput {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $expectedParent = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'target'))
    if ((Split-Path -Parent $resolved) -ne $expectedParent -or (Split-Path -Leaf $resolved) -ne $OutputName) {
        throw "Refusing to delete unexpected WebUI output path: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Invoke-LinkLakeJson {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Headers,
        [Parameter(Mandatory = $true)]$Body
    )
    Invoke-RestMethod -Method $Method -Uri "$baseUrl$Path" -Headers $Headers -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 8 -Compress)
}

try {
    Reset-SmokeOutput -Path $outputDir
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    Remove-SmokeData -Path $dataDir
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    Remove-SmokeDirectory -Path $tlsDir -ExpectedName '.tmp-webui-smoke-tls'
    New-Item -ItemType Directory -Force -Path $tlsDir | Out-Null
    & cargo run --quiet --locked -p linklake-server --example generate_localhost_certificate -- $tlsDir
    if ($LASTEXITCODE -ne 0 -or
        -not (Test-Path -LiteralPath $controlCertificate -PathType Leaf) -or
        -not (Test-Path -LiteralPath $controlPrivateKey -PathType Leaf)) {
        throw 'Could not generate the WebUI smoke-test control certificate.'
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $ServerExe
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables['LINKLAKE_BIND'] = "127.0.0.1:$ManagementPort"
    $startInfo.EnvironmentVariables['LINKLAKE_CONTROL_BIND'] = "127.0.0.1:$ControlPort"
    $startInfo.EnvironmentVariables['LINKLAKE_CONTROL_CERT_PATH'] = $controlCertificate
    $startInfo.EnvironmentVariables['LINKLAKE_CONTROL_KEY_PATH'] = $controlPrivateKey
    $startInfo.EnvironmentVariables['LINKLAKE_UDP_RELAY_BIND'] = "127.0.0.1:$UdpRelayPort"
    $startInfo.EnvironmentVariables['LINKLAKE_UDP_RELAY_ENDPOINT'] = "127.0.0.1:$UdpRelayPort"
    $startInfo.EnvironmentVariables['LINKLAKE_UDP_RELAY_SERVER_NAME'] = 'localhost'
    $startInfo.EnvironmentVariables['LINKLAKE_PUBLIC_PORT_RANGES'] = '18080-18081,32900-32999'
    $startInfo.EnvironmentVariables['LINKLAKE_RESERVED_TCP_PORTS'] = '18081'
    $startInfo.EnvironmentVariables['LINKLAKE_DATA_DIR'] = $dataDir
    $startInfo.EnvironmentVariables['LINKLAKE_ADMIN_USERNAME'] = $adminUsername
    $startInfo.EnvironmentVariables['LINKLAKE_ADMIN_PASSWORD'] = $adminPassword
    $startInfo.EnvironmentVariables['LINKLAKE_ENROLLMENT_TOKEN'] = $enrollmentToken
    $startInfo.EnvironmentVariables['LINKLAKE_MANAGEMENT_TOKEN'] = $managementToken
    if ($KeepServer) {
        $startInfo.RedirectStandardOutput = $false
        $startInfo.RedirectStandardError = $false
        $serverProcess = [System.Diagnostics.Process]::Start($startInfo)
    } else {
        $serverProcess = [System.Diagnostics.Process]::Start($startInfo)
    }

    $ready = $false
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($serverProcess.HasExited) { throw "LinkLake server exited early with code $($serverProcess.ExitCode)" }
        try {
            $health = Invoke-RestMethod -Uri "$baseUrl/api/v1/health" -TimeoutSec 1
            if ($health.status -eq 'ok') { $ready = $true; break }
        } catch {}
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw 'Timed out waiting for the LinkLake local server.' }

    $enrollmentHeaders = @{ Authorization = "Bearer $enrollmentToken" }
    $managementHeaders = @{ Authorization = "Bearer $managementToken" }
    $portPolicy = Invoke-RestMethod -Uri "$baseUrl/api/v1/public-port-policy" -Headers $managementHeaders
    if ($portPolicy.tcp_allowed -ne '18080-18081,32900-32999' -or $portPolicy.udp_allowed -ne '18080-18081,32900-32999') {
        throw "Public port policy did not match server configuration: $($portPolicy | ConvertTo-Json -Compress)"
    }
    if ([string]$portPolicy.tcp_reserved -notmatch '18081') {
        throw "TCP reserved-port policy omitted the configured port: $($portPolicy.tcp_reserved)"
    }
    $client = Invoke-LinkLakeJson -Method Post -Path '/api/v1/clients/enroll' -Headers $enrollmentHeaders -Body @{ name = 'smoke-client'; platform = 'windows' }
    $clientId = [string]$client.client_id
    Invoke-LinkLakeJson -Method Post -Path '/api/v1/clients/enroll' -Headers $enrollmentHeaders -Body @{ name = 'unused-client'; platform = 'linux' } | Out-Null

    $policies = @(
        @{ Path = '/api/v1/tcp-tunnels'; Body = @{ client_id = $clientId; name = 'smoke-tcp'; public_port = 18080; target_addr = '127.0.0.1:18001'; max_connections = 64; bandwidth_limit_bps = $null } },
        @{ Path = '/api/v1/udp-tunnels'; Body = @{ client_id = $clientId; name = 'smoke-udp'; public_port = 32902; target_addr = '127.0.0.1:18002'; max_sessions = 256; session_idle_timeout_seconds = 120; bandwidth_limit_bps = $null } },
        @{ Path = '/api/v1/port-groups'; Body = @{ client_id = $clientId; name = 'smoke-ports'; protocol = 'tcp'; public_ports = '32910-32911'; target_host = '127.0.0.1'; target_ports = '18110-18111'; max_connections = 64; max_sessions = $null; session_idle_timeout_seconds = $null; bandwidth_limit_bps = $null } },
        @{ Path = '/api/v1/http-routes'; Body = @{ client_id = $clientId; name = 'smoke-http'; hostname = 'smoke.linklake.test'; target_addr = '127.0.0.1:18080'; max_connections = 64 } },
        @{ Path = '/api/v1/sni-routes'; Body = @{ client_id = $clientId; name = 'smoke-sni'; hostname = 'sni-smoke.linklake.test'; target_addr = '127.0.0.1:18443'; max_connections = 64; bandwidth_limit_bps = $null } },
        @{ Path = '/api/v1/secret-tunnels'; Body = @{ provider_client_id = $clientId; allowed_client_id = $null; name = 'smoke-secret'; target_addr = '127.0.0.1:13389'; max_connections = 32; bandwidth_limit_bps = $null } },
        @{ Path = '/api/v1/socks5-proxies'; Body = @{ client_id = $clientId; name = 'smoke-socks5'; public_port = 32903; username = 'smoke_socks5'; max_connections = 64; bandwidth_limit_bps = $null } },
        @{ Path = '/api/v1/http-proxies'; Body = @{ client_id = $clientId; name = 'smoke-http-proxy'; public_port = 32904; username = 'smoke_http'; max_connections = 64; bandwidth_limit_bps = $null } }
    )
    foreach ($policy in $policies) {
        Invoke-LinkLakeJson -Method Post -Path $policy.Path -Headers $managementHeaders -Body $policy.Body | Out-Null
    }

    $env:LINKLAKE_SMOKE_BASE_URL = $baseUrl
    $env:LINKLAKE_SMOKE_USERNAME = $adminUsername
    $env:LINKLAKE_SMOKE_PASSWORD = $adminPassword
    $env:LINKLAKE_SMOKE_BROWSER_ENGINE = $BrowserEngine
    $env:LINKLAKE_SMOKE_BROWSER_LABEL = $BrowserLabel
    Remove-Item Env:NODE_PATH -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($BrowserPath)) {
        Remove-Item Env:LINKLAKE_SMOKE_CHROME -ErrorAction SilentlyContinue
    } else {
        $env:LINKLAKE_SMOKE_CHROME = (Resolve-Path -LiteralPath $BrowserPath).Path
    }
    $env:LINKLAKE_SMOKE_OUTPUT = $outputDir
    $node = (Get-Command node -ErrorAction Stop).Source
    & $node (Join-Path $PSScriptRoot 'webui-smoke.mjs')
    if ($LASTEXITCODE -ne 0) { throw "WebUI $BrowserLabel smoke test failed with exit code $LASTEXITCODE" }
} finally {
    if (-not $KeepServer -and $serverProcess -and -not $serverProcess.HasExited) {
        $serverProcess.Kill()
        $serverProcess.WaitForExit()
    }
    if (-not $KeepServer -and $serverProcess) {
        ($serverProcess.StandardOutput.ReadToEnd() + $serverProcess.StandardError.ReadToEnd()) | Set-Content -LiteralPath $serverLog -Encoding utf8
        $serverProcess.Dispose()
    }
    if ($KeepServer -and $serverProcess) {
        Write-Host "LinkLake WebUI QA server PID: $($serverProcess.Id)"
        Write-Host "LinkLake WebUI QA URL: $baseUrl"
    }
    if (-not $KeepServer) {
        Remove-SmokeDirectory -Path $tlsDir -ExpectedName '.tmp-webui-smoke-tls'
    }
    if (-not $KeepData -and -not $KeepServer) { Remove-SmokeData -Path $dataDir }
}
