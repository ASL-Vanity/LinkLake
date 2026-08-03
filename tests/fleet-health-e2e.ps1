param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['Invoke-RestMethod:Headers'] = @{ 'X-LinkLake-CSRF' = '1' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot 'target'
$serverPath = Join-Path $targetRoot 'debug\linklake-server.exe'
$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('linklake-fleet-health-e2e-' + [guid]::NewGuid())
$serverProcess = $null

function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Start-HiddenProcess {
    param([string]$FilePath)
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    return [Diagnostics.Process]::Start($startInfo)
}

function Wait-ForCondition {
    param([scriptblock]$Condition, [string]$Failure, [int]$Seconds = 25)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            if (& $Condition) { return }
        } catch {
            # Retry transient failures while the service starts or changes state.
        }
        Start-Sleep -Milliseconds 200
    }
    throw $Failure
}

function Start-TestServer {
    param([int]$ManagementPort, [int]$ControlPort, [string]$ManagementToken, [string]$DataDir)
    $names = @(
        'LINKLAKE_BIND', 'LINKLAKE_CONTROL_BIND', 'LINKLAKE_ENROLLMENT_TOKEN',
        'LINKLAKE_MANAGEMENT_TOKEN', 'LINKLAKE_DATA_DIR', 'LINKLAKE_ADMIN_USERNAME',
        'LINKLAKE_ADMIN_PASSWORD', 'LINKLAKE_FLEET_SELF_TOKEN',
        'LINKLAKE_FLEET_PROBE_INTERVAL_SECONDS'
    )
    $old = @{}
    foreach ($name in $names) { $old[$name] = [Environment]::GetEnvironmentVariable($name) }
    try {
        $env:LINKLAKE_BIND = "127.0.0.1:$ManagementPort"
        $env:LINKLAKE_CONTROL_BIND = "127.0.0.1:$ControlPort"
        $env:LINKLAKE_ENROLLMENT_TOKEN = [guid]::NewGuid().ToString()
        $env:LINKLAKE_MANAGEMENT_TOKEN = $ManagementToken
        $env:LINKLAKE_DATA_DIR = $DataDir
        $env:LINKLAKE_ADMIN_USERNAME = 'admin'
        $env:LINKLAKE_ADMIN_PASSWORD = 'LinkLake-Fleet-Health-E2E-123!'
        $env:LINKLAKE_FLEET_SELF_TOKEN = $ManagementToken
        $env:LINKLAKE_FLEET_PROBE_INTERVAL_SECONDS = '5'
        return Start-HiddenProcess -FilePath $serverPath
    } finally {
        foreach ($name in $names) {
            if ($null -eq $old[$name]) {
                Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
            } else {
                Set-Item -Path "Env:$name" -Value $old[$name]
            }
        }
    }
}

function Stop-TestServer {
    param([Diagnostics.Process]$Process)
    if ($Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force
        $null = $Process.WaitForExit(5000)
    }
}

New-Item -ItemType Directory -Path $runRoot | Out-Null
try {
    if (-not $SkipBuild) {
        $previousTarget = $env:CARGO_TARGET_DIR
        try {
            $env:CARGO_TARGET_DIR = $targetRoot
            & cargo build -p linklake-server --locked
            if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
        } finally {
            $env:CARGO_TARGET_DIR = $previousTarget
        }
    }
    if (-not (Test-Path -LiteralPath $serverPath)) {
        throw 'The Fleet health E2E server binary does not exist. Run without -SkipBuild first.'
    }

    $managementPort = Get-FreePort
    $controlPort = Get-FreePort
    $baseUrl = "http://127.0.0.1:$managementPort"
    $managementToken = [guid]::NewGuid().ToString()
    $headers = @{ Authorization = "Bearer $managementToken"; 'X-LinkLake-CSRF' = '1' }
    $dataDir = Join-Path $runRoot 'data'
    $serverProcess = Start-TestServer -ManagementPort $managementPort -ControlPort $controlPort `
        -ManagementToken $managementToken -DataDir $dataDir
    Wait-ForCondition -Failure 'The first LinkLake server did not become ready.' -Condition {
        (Invoke-RestMethod -Uri "$baseUrl/readyz" -TimeoutSec 2).status -eq 'ready'
    }

    $peer = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/fleet/peers" -Headers $headers `
        -ContentType 'application/json' -Body (@{
            name = 'Self'
            url = $baseUrl
            region = 'local'
            weight = 100
            priority = 10
            token_env = 'LINKLAKE_FLEET_SELF_TOKEN'
            enabled = $true
        } | ConvertTo-Json)
    $healthConfig = Invoke-RestMethod -Method Put `
        -Uri "$baseUrl/api/v1/fleet/peers/$($peer.id)/health-config" -Headers $headers `
        -ContentType 'application/json' -Body (@{
            success_threshold = 1
            failure_threshold = 2
            cooldown_seconds = 0
        } | ConvertTo-Json)
    if ($healthConfig.config.success_threshold -ne 1 -or $healthConfig.config.failure_threshold -ne 2) {
        throw 'Fleet health configuration was not persisted by the API.'
    }

    Wait-ForCondition -Failure 'The self Fleet peer did not become healthy.' -Seconds 20 -Condition {
        $script:overview = Invoke-RestMethod -Uri "$baseUrl/api/v1/fleet/overview" -Headers $headers
        $script:overview.peers[0].health.state -eq 'healthy'
    }
    if (-not $overview.peers[0].dns_eligible -or $overview.failover_order[0] -ne $peer.id) {
        throw 'Fleet preferred/failover ordering did not use the persisted healthy state.'
    }

    $rawSecretRejected = $false
    try {
        Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/fleet/dns-failovers" `
            -Headers $headers -ContentType 'application/json' -Body (@{
                name = 'Rejected raw secret'
                hostname = 'rejected.example.com'
                record_type = 'A'
                zone_id = '0123456789abcdef0123456789abcdef'
                record_id = 'fedcba9876543210fedcba9876543210'
                token_env = 'LINKLAKE_FLEET_HEALTH_E2E_PROVIDER_TOKEN'
                token = 'must-not-be-accepted'
                ttl = 60
                enabled = $false
                cooldown_seconds = 30
                targets = @(@{ peer_id = $peer.id; value = '127.0.0.1' })
            } | ConvertTo-Json -Depth 5)
    } catch {
        $rawSecretRejected = $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 422
    }
    if (-not $rawSecretRejected) {
        throw 'The Fleet DNS API did not reject a raw provider secret field.'
    }

    $dnsBody = @{
        name = 'Public entry'
        hostname = 'link.example.com'
        record_type = 'A'
        zone_id = '0123456789abcdef0123456789abcdef'
        record_id = 'fedcba9876543210fedcba9876543210'
        token_env = 'LINKLAKE_FLEET_HEALTH_E2E_PROVIDER_TOKEN'
        ttl = 60
        proxied = $false
        enabled = $false
        cooldown_seconds = 30
        targets = @(@{ peer_id = $peer.id; value = '127.0.0.1' })
    }
    $dns = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/fleet/dns-failovers" `
        -Headers $headers -ContentType 'application/json' `
        -Body ($dnsBody | ConvertTo-Json -Depth 5)
    if ($dns.token_configured -or $dns.PSObject.Properties.Name -contains 'token') {
        throw 'The DNS API exposed or accepted a raw provider token field.'
    }
    $switchEvents = Invoke-RestMethod `
        -Uri "$baseUrl/api/v1/fleet/dns-failovers/$($dns.id)/events" -Headers $headers
    if ($switchEvents.Count -ne 0) {
        $unexpectedEvents = $switchEvents | ConvertTo-Json -Depth 5 -Compress
        throw "A newly created disabled DNS failover unexpectedly had switch events: $unexpectedEvents"
    }
    $dnsBody.enabled = $true
    $dns = Invoke-RestMethod -Method Put -Uri "$baseUrl/api/v1/fleet/dns-failovers/$($dns.id)" `
        -Headers $headers -ContentType 'application/json' `
        -Body ($dnsBody | ConvertTo-Json -Depth 5)
    $null = Invoke-RestMethod -Method Post `
        -Uri "$baseUrl/api/v1/fleet/dns-failovers/$($dns.id)/reconcile" -Headers $headers `
        -ContentType 'application/json' -Body '{}'
    Wait-ForCondition -Failure 'The missing provider token did not produce an auditable DNS failure.' -Condition {
        $script:switchEvents = Invoke-RestMethod `
            -Uri "$baseUrl/api/v1/fleet/dns-failovers/$($dns.id)/events" -Headers $headers
        $script:switchEvents.Count -ge 1
    }
    $afterFailure = Invoke-RestMethod -Uri "$baseUrl/api/v1/fleet/overview" -Headers $headers
    $failedDns = @($afterFailure.dns_failovers | Where-Object { $_.id -eq $dns.id })[0]
    if ($failedDns.current_peer_id -or $failedDns.current_target -or
        -not $failedDns.last_error_summary -or $switchEvents[0].applied) {
        throw 'A failed DNS provider update advanced current state instead of rolling back.'
    }
    $frozen = Invoke-RestMethod -Method Post `
        -Uri "$baseUrl/api/v1/fleet/dns-failovers/$($dns.id)/freeze" -Headers $headers `
        -ContentType 'application/json' -Body (@{ reason = 'e2e maintenance' } | ConvertTo-Json)
    if (-not $frozen.frozen -or $frozen.freeze_reason -ne 'e2e maintenance') {
        throw 'Fleet DNS manual freeze did not persist its reason.'
    }
    $resumed = Invoke-RestMethod -Method Post `
        -Uri "$baseUrl/api/v1/fleet/dns-failovers/$($dns.id)/resume" -Headers $headers `
        -ContentType 'application/json' -Body '{}'
    if ($resumed.frozen) { throw 'Fleet DNS resume did not clear the frozen state.' }
    $null = Invoke-RestMethod -Method Post `
        -Uri "$baseUrl/api/v1/fleet/dns-failovers/$($dns.id)/freeze" -Headers $headers `
        -ContentType 'application/json' -Body (@{ reason = 'restart proof' } | ConvertTo-Json)

    $prometheus = Invoke-RestMethod -Uri "$baseUrl/api/v1/metrics/prometheus" -Headers $headers
    if ($prometheus -notmatch 'linklake_fleet_peers_healthy 1' -or
        $prometheus -notmatch 'linklake_fleet_dns_failovers_frozen 1' -or
        $prometheus -notmatch 'linklake_fleet_dns_switch_failures_total 1') {
        throw 'Fleet health or DNS state was not exported through Prometheus metrics.'
    }

    Stop-TestServer -Process $serverProcess
    $serverProcess = $null
    Start-Sleep -Milliseconds 300
    $serverProcess = Start-TestServer -ManagementPort $managementPort -ControlPort $controlPort `
        -ManagementToken $managementToken -DataDir $dataDir
    Wait-ForCondition -Failure 'The restarted LinkLake server did not become ready.' -Condition {
        (Invoke-RestMethod -Uri "$baseUrl/readyz" -TimeoutSec 2).status -eq 'ready'
    }
    $restarted = Invoke-RestMethod -Uri "$baseUrl/api/v1/fleet/overview" -Headers $headers
    if ($restarted.peers[0].health.state -ne 'healthy' -or
        $restarted.dns_failovers[0].freeze_reason -ne 'restart proof' -or
        $restarted.dns_failovers[0].current_peer_id -or
        -not $restarted.dns_failovers[0].last_error_summary) {
        throw 'Fleet health or DNS freeze state did not survive server restart.'
    }
    $audit = @(Invoke-RestMethod -Uri "$baseUrl/api/v1/audit?limit=100" -Headers $headers)
    foreach ($action in @(
        'fleet.peer.health_config_updated',
        'fleet.peer.health_changed',
        'fleet.dns_failover.created',
        'fleet.dns_failover.switch_failed',
        'fleet.dns_failover.frozen',
        'fleet.dns_failover.resumed'
    )) {
        if (-not ($audit | Where-Object { $_.action -eq $action })) {
            throw "Fleet audit action $action was not recorded."
        }
    }

    Write-Host 'Fleet health E2E passed: state machine API, persisted restart state, cooldown eligibility, DNS failure rollback, freeze/resume, metrics, audit ledger, and secret-safe contract.'
} finally {
    Stop-TestServer -Process $serverProcess
    $resolvedRunRoot = [IO.Path]::GetFullPath($runRoot)
    $resolvedTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolvedRunRoot.StartsWith($resolvedTempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedRunRoot).StartsWith('linklake-fleet-health-e2e-')) {
        for ($attempt = 0; $attempt -lt 10 -and (Test-Path -LiteralPath $resolvedRunRoot); $attempt++) {
            try { Remove-Item -LiteralPath $resolvedRunRoot -Recurse -Force }
            catch {
                if ($attempt -eq 9) { throw }
                Start-Sleep -Milliseconds 200
            }
        }
    }
}
