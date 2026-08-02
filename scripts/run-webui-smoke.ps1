param(
    [string]$ServerExe = "",
    [int]$ManagementPort = 39210,
    [int]$ControlPort = 39211,
    [int]$UdpRelayPort = 39212,
    [ValidateSet('chromium', 'firefox', 'webkit')][string]$BrowserEngine = 'chromium',
    [string]$BrowserPath = 'C:\Program Files\Google\Chrome\Application\chrome.exe',
    [string]$BrowserLabel = 'Chrome',
    [ValidatePattern('^[A-Za-z0-9._-]+$')][string]$OutputName = 'webui-smoke',
    [switch]$KeepData,
    [switch]$KeepServer
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($ServerExe)) {
    $ServerExe = Join-Path $projectRoot 'target\release\linklake-server.exe'
}
$ServerExe = (Resolve-Path -LiteralPath $ServerExe).Path
$dataDir = Join-Path $projectRoot '.tmp-webui-smoke-data'
$outputDir = Join-Path $projectRoot "target\$OutputName"
$serverLog = Join-Path $outputDir 'server.log'
$baseUrl = "http://127.0.0.1:$ManagementPort"
$adminUsername = 'admin'
$adminPassword = 'LinkLake-Smoke-2026!'
$enrollmentToken = 'linklake-smoke-enrollment'
$managementToken = 'linklake-smoke-management'
$controlCertificate = Join-Path $projectRoot '.tmp-tls-test\control-cert.pem'
$controlPrivateKey = Join-Path $projectRoot '.tmp-tls-test\control-key.pem'
$serverProcess = $null

if (-not (Test-Path -LiteralPath $controlCertificate) -or -not (Test-Path -LiteralPath $controlPrivateKey)) {
    throw 'WebUI 冒烟测试需要 .tmp-tls-test 中的 localhost 控制通道证书与私钥'
}

function Remove-SmokeData {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $expectedParent = (Resolve-Path -LiteralPath $projectRoot).Path
    if ((Split-Path -Parent $resolved) -ne $expectedParent -or (Split-Path -Leaf $resolved) -ne '.tmp-webui-smoke-data') {
        throw "拒绝删除意外路径：$resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Reset-SmokeOutput {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $expectedParent = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'target'))
    if ((Split-Path -Parent $resolved) -ne $expectedParent -or (Split-Path -Leaf $resolved) -ne $OutputName) {
        throw "拒绝删除意外的 WebUI 输出路径：$resolved"
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

Reset-SmokeOutput -Path $outputDir
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
Remove-SmokeData -Path $dataDir
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

try {
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
        if ($serverProcess.HasExited) { throw "LinkLake 服务提前退出，代码 $($serverProcess.ExitCode)" }
        try {
            $health = Invoke-RestMethod -Uri "$baseUrl/api/v1/health" -TimeoutSec 1
            if ($health.status -eq 'ok') { $ready = $true; break }
        } catch {}
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw '等待 LinkLake 本地服务启动超时' }

    $enrollmentHeaders = @{ Authorization = "Bearer $enrollmentToken" }
    $managementHeaders = @{ Authorization = "Bearer $managementToken" }
    $portPolicy = Invoke-RestMethod -Uri "$baseUrl/api/v1/public-port-policy" -Headers $managementHeaders
    if ($portPolicy.tcp_allowed -ne '18080-18081,32900-32999' -or $portPolicy.udp_allowed -ne '18080-18081,32900-32999') {
        throw "公网端口允许策略未按服务端配置返回：$($portPolicy | ConvertTo-Json -Compress)"
    }
    if ([string]$portPolicy.tcp_reserved -notmatch '18081') {
        throw "TCP 保留端口策略未包含显式保留端口：$($portPolicy.tcp_reserved)"
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

    $env:NODE_PATH = 'C:\Users\Laker\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\node_modules'
    $env:LINKLAKE_SMOKE_BASE_URL = $baseUrl
    $env:LINKLAKE_SMOKE_USERNAME = $adminUsername
    $env:LINKLAKE_SMOKE_PASSWORD = $adminPassword
    $env:LINKLAKE_SMOKE_BROWSER_ENGINE = $BrowserEngine
    $env:LINKLAKE_SMOKE_BROWSER_LABEL = $BrowserLabel
    if ([string]::IsNullOrWhiteSpace($BrowserPath)) {
        Remove-Item Env:LINKLAKE_SMOKE_CHROME -ErrorAction SilentlyContinue
    } else {
        $env:LINKLAKE_SMOKE_CHROME = (Resolve-Path -LiteralPath $BrowserPath).Path
    }
    $env:LINKLAKE_SMOKE_OUTPUT = $outputDir
    $node = 'C:\Users\Laker\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
    & $node (Join-Path $PSScriptRoot 'webui-smoke.mjs')
    if ($LASTEXITCODE -ne 0) { throw "WebUI $BrowserLabel 冒烟测试失败，退出码 $LASTEXITCODE" }
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
    if (-not $KeepData -and -not $KeepServer) { Remove-SmokeData -Path $dataDir }
}
