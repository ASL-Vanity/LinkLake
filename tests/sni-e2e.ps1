param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target\e2e'
$serverPath = Join-Path $targetRoot 'debug\linklake-server.exe'
$clientPath = Join-Path $targetRoot 'debug\linklake-client.exe'
$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('linklake-sni-e2e-' + [guid]::NewGuid())
$processes = [Collections.Generic.List[Diagnostics.Process]]::new()
$succeeded = $false

function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Start-HiddenProcess([string]$FilePath, [string[]]$Arguments = @(), [hashtable]$Environment = @{}) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $FilePath
    $info.Arguments = $Arguments -join ' '
    $info.WorkingDirectory = $projectRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    if ([IO.Path]::GetFileNameWithoutExtension($FilePath).StartsWith('linklake-')) {
        $info.EnvironmentVariables['LINKLAKE_LOG_DIR'] = (Join-Path $runRoot 'logs')
        $info.EnvironmentVariables['RUST_LOG'] = 'linklake_client=debug,linklake_server=debug'
    }
    foreach ($entry in $Environment.GetEnumerator()) { $info.EnvironmentVariables[$entry.Key] = [string]$entry.Value }
    $process = [Diagnostics.Process]::Start($info)
    $processes.Add($process)
    return $process
}

function Wait-ForCondition([scriptblock]$Condition, [string]$Failure, [int]$Seconds = 30) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try { if (& $Condition) { return } } catch {}
        Start-Sleep -Milliseconds 200
    }
    throw $Failure
}

function Test-TcpListener([int]$Port) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.Connect('127.0.0.1', $Port)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Invoke-TlsEcho([int]$Port, [string]$ServerName, [string]$Message) {
    $tcp = [Net.Sockets.TcpClient]::new('127.0.0.1', $Port)
    try {
        $ssl = [Net.Security.SslStream]::new($tcp.GetStream(), $false, { $true })
        try {
            $ssl.AuthenticateAsClient($ServerName)
            $payload = [Text.Encoding]::UTF8.GetBytes($Message)
            $ssl.Write($payload, 0, $payload.Length)
            $ssl.Flush()
            $response = [byte[]]::new($payload.Length)
            $offset = 0
            while ($offset -lt $response.Length) {
                $read = $ssl.Read($response, $offset, $response.Length - $offset)
                if ($read -eq 0) { throw 'TLS SNI target closed early.' }
                $offset += $read
            }
            if ([Text.Encoding]::UTF8.GetString($response) -ne $Message) { throw 'TLS SNI echo was corrupted.' }
        } finally { $ssl.Dispose() }
    } finally { $tcp.Dispose() }
}

function Assert-TlsRejected([int]$Port, [string]$ServerName) {
    try {
        Invoke-TlsEcho -Port $Port -ServerName $ServerName -Message 'must-fail'
    } catch { return }
    throw "TLS SNI $ServerName was unexpectedly accepted."
}

New-Item -ItemType Directory -Path $runRoot | Out-Null
try {
    if (-not $SkipBuild) {
        $oldTarget = $env:CARGO_TARGET_DIR
        try {
            $env:CARGO_TARGET_DIR = $targetRoot
            & cargo build --workspace
            if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
        } finally { $env:CARGO_TARGET_DIR = $oldTarget }
    }
    if (-not (Test-Path $serverPath) -or -not (Test-Path $clientPath)) { throw 'E2E binaries are missing.' }

    $managementPort = Get-FreePort
    $controlPort = Get-FreePort
    $sniPort = Get-FreePort
    $targetPort = Get-FreePort
    $baseUrl = "http://127.0.0.1:$managementPort"
    $enrollmentToken = [guid]::NewGuid().ToString()
    $managementToken = [guid]::NewGuid().ToString()
    $hostname = 'passthrough.example.test'
    $targetLog = Join-Path $runRoot 'tls-target.log'

    $tlsTarget = @"
`$rsa = [Security.Cryptography.RSA]::Create(2048)
`$request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=$hostname', `$rsa, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
`$generated = `$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddDays(1))
`$password = [guid]::NewGuid().ToString()
`$pfx = `$generated.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, `$password)
`$generated.Dispose()
`$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
  `$pfx,
  `$password,
  [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
)
`$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $targetPort)
`$listener.Start()
try {
  while (`$true) {
    `$client = `$listener.AcceptTcpClient()
    try {
      `$ssl = [Net.Security.SslStream]::new(`$client.GetStream(), `$false)
      `$ssl.AuthenticateAsServer(`$cert, `$false, [Security.Authentication.SslProtocols]::Tls12, `$false)
      `$buffer = [byte[]]::new(4096)
      while ((`$read = `$ssl.Read(`$buffer, 0, `$buffer.Length)) -gt 0) { `$ssl.Write(`$buffer, 0, `$read); `$ssl.Flush() }
    } catch {
      [IO.File]::AppendAllText('$targetLog', `$_.Exception.ToString() + [Environment]::NewLine)
    } finally { `$client.Dispose() }
  }
} finally { `$listener.Stop(); `$cert.Dispose(); `$rsa.Dispose() }
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($tlsTarget))
    Start-HiddenProcess 'powershell.exe' @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) | Out-Null
    Wait-ForCondition { Test-TcpListener $targetPort } 'TLS echo target did not become ready.'

    $server = Start-HiddenProcess $serverPath @() @{
        LINKLAKE_BIND = "127.0.0.1:$managementPort"
        LINKLAKE_CONTROL_BIND = "127.0.0.1:$controlPort"
        LINKLAKE_TLS_PASSTHROUGH_BIND = "127.0.0.1:$sniPort"
        LINKLAKE_ENROLLMENT_TOKEN = $enrollmentToken
        LINKLAKE_MANAGEMENT_TOKEN = $managementToken
        LINKLAKE_DATA_DIR = (Join-Path $runRoot 'data')
        LINKLAKE_ADMIN_USERNAME = 'admin'
        LINKLAKE_ADMIN_PASSWORD = 'SNI-E2E-Password-123!'
    }
    Wait-ForCondition { (Invoke-RestMethod "$baseUrl/api/v1/health").status -eq 'ok' } 'Server did not become healthy.'
    $headers = @{ Authorization = "Bearer $managementToken" }
    $enrollment = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/clients/enroll" -Headers @{Authorization="Bearer $enrollmentToken"} -ContentType 'application/json' -Body (@{name='sni-provider';platform='windows'}|ConvertTo-Json)
    $policy = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/sni-routes" -Headers $headers -ContentType 'application/json' -Body (@{client_id=$enrollment.client_id;name='tls-echo';hostname=$hostname;target_addr="127.0.0.1:$targetPort";max_connections=4;bandwidth_limit_bps=$null}|ConvertTo-Json)
    $configPath = Join-Path $runRoot 'client.toml'
    [IO.File]::WriteAllText($configPath, @"
[client]
control = "127.0.0.1:$controlPort"
client_id = "$($enrollment.client_id)"
client_token = "$($enrollment.client_token)"
config_mode = "server_managed"
"@, [Text.UTF8Encoding]::new($false))
    Start-HiddenProcess $clientPath @('run','--config',('"'+$configPath+'"')) | Out-Null
    try {
        Wait-ForCondition {
            $route = Invoke-RestMethod "$baseUrl/api/v1/sni-routes" -Headers $headers | Where-Object { $_.id -eq $policy.id }
            $null -ne $route -and $route.online -eq $true
        } 'SNI route did not become online.'
    } catch {
        Write-Host ((Invoke-RestMethod "$baseUrl/api/v1/sni-routes" -Headers $headers) | ConvertTo-Json -Depth 8)
        Write-Host ((Invoke-RestMethod "$baseUrl/api/v1/clients" -Headers $headers) | ConvertTo-Json -Depth 8)
        throw
    }
    try {
        Invoke-TlsEcho $sniPort $hostname 'tls-sni-pass-through'
    } catch {
        Write-Host ((Invoke-RestMethod "$baseUrl/api/v1/sni-routes" -Headers $headers) | ConvertTo-Json -Depth 8)
        Write-Host ((Invoke-RestMethod "$baseUrl/api/v1/metrics" -Headers $headers) | ConvertTo-Json -Depth 8)
        Start-Sleep -Seconds 1
        throw
    }
    Assert-TlsRejected $sniPort 'unknown.example.test'
    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/sni-routes/$($policy.id)/enabled" -Headers $headers -ContentType 'application/json' -Body '{"enabled":false}' | Out-Null
    Wait-ForCondition {
        $route = Invoke-RestMethod "$baseUrl/api/v1/sni-routes" -Headers $headers | Where-Object { $_.id -eq $policy.id }
        $null -ne $route -and $route.online -eq $false
    } 'SNI route did not stop.'
    Assert-TlsRejected $sniPort $hostname
    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/sni-routes/$($policy.id)/enabled" -Headers $headers -ContentType 'application/json' -Body '{"enabled":true}' | Out-Null
    Wait-ForCondition {
        $route = Invoke-RestMethod "$baseUrl/api/v1/sni-routes" -Headers $headers | Where-Object { $_.id -eq $policy.id }
        $null -ne $route -and $route.online -eq $true
    } 'SNI route did not recover.'
    Invoke-TlsEcho $sniPort $hostname 'tls-sni-reenabled'
    $metrics = Invoke-RestMethod "$baseUrl/api/v1/metrics" -Headers $headers
    if ($metrics.sni_connections_total -lt 2 -or $metrics.sni_unknown_hostname -lt 1) { throw 'SNI metrics were not updated.' }
    Invoke-RestMethod -Method Delete -Uri "$baseUrl/api/v1/sni-routes/$($policy.id)" -Headers $headers | Out-Null
    Assert-TlsRejected $sniPort $hostname
    $succeeded = $true
    Write-Host 'TLS SNI E2E passed: real TLS handshake pass-through, unknown SNI rejection, lifecycle, reconnect, and metrics.'
} finally {
    foreach ($process in $processes) { if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } }
    if ($succeeded -and (Resolve-Path $runRoot -ErrorAction SilentlyContinue) -and $runRoot.StartsWith([IO.Path]::GetTempPath())) {
        Remove-Item $runRoot -Recurse -Force -ErrorAction SilentlyContinue
    } elseif (-not $succeeded) {
        Write-Host "SNI E2E artifacts preserved at $runRoot"
    }
}
