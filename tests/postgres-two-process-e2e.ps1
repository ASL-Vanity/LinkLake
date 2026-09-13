param(
    [switch]$RunVerification,
    [string]$PostgresBinDir,
    [string]$PostgresImage = 'postgres:16-alpine',
    [string]$ServerPath,
    [string]$ClientPath
)

. (Join-Path $PSScriptRoot 'postgres-harness-common.ps1')
if (-not $RunVerification) { throw 'No verification was executed. Pass -RunVerification explicitly.' }
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $ServerPath) { $ServerPath = Join-Path $projectRoot 'target/verification-v1/debug/linklake-server.exe' }
if (-not $ClientPath) { $ClientPath = Join-Path $projectRoot 'target/verification-v1/debug/linklake-client.exe' }
$ServerPath = (Resolve-Path -LiteralPath $ServerPath).Path
$ClientPath = (Resolve-Path -LiteralPath $ClientPath).Path
$runRoot = Join-Path $projectRoot ('logs/dev/pg-two-process-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $runRoot
$PSDefaultParameterValues['Invoke-RestMethod:Headers'] = @{ 'X-LinkLake-CSRF' = '1' }
$postgres = $null
$serverA = $null
$serverB = $null
$clientA = $null
$clientB = $null
$backend = $null

function Wait-LinkLakeCondition {
    param([scriptblock]$Condition, [string]$Failure, [int]$Seconds = 40, $Process)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process -and $Process.Process.HasExited) { throw "$Failure Child exited; logs: $runRoot" }
        try { if (& $Condition) { return } } catch { }
        Start-Sleep -Milliseconds 150
    }
    throw "$Failure Logs: $runRoot"
}

function Stop-LinkLakeE2EChild {
    param($Child, [string]$Name)
    if (-not $Child) { return }
    if (-not $Child.Process.HasExited) { $Child.Process.Kill($true); $Child.Process.WaitForExit() }
    $null = Complete-LinkLakeTestProcess -Child $Child -LogPrefix (Join-Path $runRoot $Name) -TimeoutSeconds 10
}

function Invoke-LinkLakeForwardedHttp {
    param([int]$Port)
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/ha-contract" -Headers @{ Host = 'ha-process.example.test' } -TimeoutSec 3 -SkipHttpErrorCheck
    return $response.StatusCode -eq 200 -and ([string]$response.Content).Trim() -eq 'linklake-real-ha-forwarding'
}

try {
    $postgres = Start-LinkLakeDisposablePostgres -RunRoot $runRoot -PostgresBinDir $PostgresBinDir -PostgresImage $PostgresImage
    $managementA = Get-LinkLakeTestPort
    $managementB = Get-LinkLakeTestPort
    $controlA = Get-LinkLakeTestPort
    $controlB = Get-LinkLakeTestPort
    $httpA = Get-LinkLakeTestPort
    $httpB = Get-LinkLakeTestPort
    $backendPort = Get-LinkLakeTestPort
    $baseA = "http://127.0.0.1:$managementA"
    $baseB = "http://127.0.0.1:$managementB"
    $enrollmentToken = [guid]::NewGuid().ToString()
    $adminPassword = 'LinkLake-HA-Test-' + [guid]::NewGuid().ToString('N') + '!'
    $common = @{
        LINKLAKE_STORAGE_BACKEND='postgres'; LINKLAKE_POSTGRES_URL=$postgres.Url
        LINKLAKE_POSTGRES_ALLOW_INSECURE_LOOPBACK='true'; LINKLAKE_POSTGRES_POOL_SIZE='16'
        LINKLAKE_HA_MEMBER_LEASE_SECONDS='12'; LINKLAKE_HA_LEADER_LEASE_SECONDS='6'
        LINKLAKE_HA_HEARTBEAT_SECONDS='1'; LINKLAKE_HA_RESOURCE_LEASE_SECONDS='8'
        LINKLAKE_ADMIN_USERNAME='admin'; LINKLAKE_ADMIN_PASSWORD=$adminPassword
        LINKLAKE_ENROLLMENT_TOKEN=$enrollmentToken; RUST_LOG='info'
    }
    $initialization = Invoke-LinkLakeTestCommand -FilePath $ServerPath -Arguments @('initialize-postgres') -Environment $common -RunRoot $runRoot -Name 'initialize-schema'
    if (($initialization.Stdout | ConvertFrom-Json).schema_version -ne 22) { throw 'Expected PostgreSQL schema v22.' }
    $envA = $common.Clone()
    $envA.LINKLAKE_DATA_DIR=Join-Path $runRoot 'server-a-data'
    $envA.LINKLAKE_BIND="127.0.0.1:$managementA"
    $envA.LINKLAKE_CONTROL_BIND="127.0.0.1:$controlA"
    $envA.LINKLAKE_HTTP_BIND="127.0.0.1:$httpA"
    $envA.LINKLAKE_HA_INSTANCE_ID='e2e-server-a'
    $envB = $common.Clone()
    $envB.LINKLAKE_DATA_DIR=Join-Path $runRoot 'server-b-data'
    $envB.LINKLAKE_BIND="127.0.0.1:$managementB"
    $envB.LINKLAKE_CONTROL_BIND="127.0.0.1:$controlB"
    $envB.LINKLAKE_HTTP_BIND="127.0.0.1:$httpB"
    $envB.LINKLAKE_HA_INSTANCE_ID='e2e-server-b'
    $serverA = Start-LinkLakeTestProcess -FilePath $ServerPath -Arguments @() -WorkingDirectory $projectRoot -Environment $envA
    Wait-LinkLakeCondition -Process $serverA -Failure 'Server A did not become leader.' -Condition { (Invoke-RestMethod -Uri "$baseA/leaderz" -TimeoutSec 2).status -eq 'leader' }
    $serverB = Start-LinkLakeTestProcess -FilePath $ServerPath -Arguments @() -WorkingDirectory $projectRoot -Environment $envB
    Wait-LinkLakeCondition -Process $serverB -Failure 'Server B did not become ready.' -Condition { (Invoke-RestMethod -Uri "$baseB/readyz" -TimeoutSec 2).status -eq 'ready' }
    if ($serverA.Process.Id -eq $serverB.Process.Id) { throw 'Expected two distinct server processes.' }
    $login = Invoke-RestMethod -Method Post -Uri "$baseA/api/v1/auth/login" -SessionVariable webSession -ContentType 'application/json' -Body (@{username='admin';password=$adminPassword}|ConvertTo-Json)
    if ($login.role -ne 'administrator') { throw 'Shared administrator login failed.' }
    $overviewA=Invoke-RestMethod -Uri "$baseA/api/v1/ha/overview" -WebSession $webSession
    $overviewB=Invoke-RestMethod -Uri "$baseB/api/v1/ha/overview" -WebSession $webSession
    if (-not $overviewA.local_is_leader -or $overviewB.local_is_leader -or @($overviewB.members).Count -ne 2) { throw 'Expected A leader, B follower and two shared members.' }
    $oldFence=[uint64]$overviewA.local_fencing_token
    $enrollment=Invoke-RestMethod -Method Post -Uri "$baseA/api/v1/clients/enroll" -Headers @{Authorization="Bearer $enrollmentToken";'X-LinkLake-CSRF'='1'} -ContentType 'application/json' -Body (@{name='two-process-agent';platform='windows'}|ConvertTo-Json)
    $routeBody=@{client_id=$enrollment.client_id;name='two-process-http';hostname='ha-process.example.test';target_addr="127.0.0.1:$backendPort";max_connections=16}|ConvertTo-Json
    $route=Invoke-RestMethod -Method Post -Uri "$baseA/api/v1/http-routes" -WebSession $webSession -ContentType 'application/json' -Body $routeBody
    $shared=Invoke-RestMethod -Uri "$baseB/api/v1/http-routes" -WebSession $webSession
    if (-not ($shared|Where-Object {$_.id -eq $route.id})) { throw 'Follower did not read the shared HTTP policy.' }
    $rejected=Invoke-WebRequest -Method Post -Uri "$baseB/api/v1/http-routes" -WebSession $webSession -Headers @{'X-LinkLake-CSRF'='1'} -ContentType 'application/json' -Body $routeBody -SkipHttpErrorCheck
    if ($rejected.StatusCode -ne 503 -or ($rejected.Content|ConvertFrom-Json).code -ne 'ha_leader_required') { throw 'Follower mutation was not fenced.' }
    # 真实loopback HTTP目标，无URLACL、系统服务或外部网络。
    $backendScript=@'
param([int]$Port)
$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$Port)
$listener.Start()
try {
    while ($true) {
        $client=$listener.AcceptTcpClient()
        try {
            $client.ReceiveTimeout=3000
            $stream=$client.GetStream()
            $bytes=[byte[]]::new(4096)
            $request=''
            while ($request -notmatch "`r`n`r`n") {
                $read=$stream.Read($bytes,0,$bytes.Length)
                if ($read -le 0) { break }
                $request += [Text.Encoding]::ASCII.GetString($bytes,0,$read)
            }
            $body='linklake-real-ha-forwarding'
            $reply=[Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body")
            $stream.Write($reply,0,$reply.Length)
        } catch { } finally { $client.Dispose() }
    }
} finally { $listener.Stop() }
'@
    $backendPath=Join-Path $runRoot 'http-backend.ps1'
    [IO.File]::WriteAllText($backendPath,$backendScript)
    $backend=Start-LinkLakeTestProcess -FilePath (Get-Command pwsh).Source -Arguments @('-NoProfile','-File',$backendPath,'-Port',"$backendPort") -WorkingDirectory $runRoot
    $agentArgs=@('http-agent','--client-id',$enrollment.client_id,'--token',$enrollment.client_token,'--hostname','ha-process.example.test','--target',"127.0.0.1:$backendPort",'--name','two-process-http')
    $clientA=Start-LinkLakeTestProcess -FilePath $ClientPath -Arguments ($agentArgs+@('--control',"127.0.0.1:$controlA")) -WorkingDirectory $runRoot -Environment @{LINKLAKE_AGENT_IDENTITY_PATH=(Join-Path $runRoot 'agent-identity.json')}
    Wait-LinkLakeCondition -Process $clientA -Failure 'Real HTTP forwarding through leader A failed.' -Condition { Invoke-LinkLakeForwardedHttp -Port $httpA }
    $leaderPid=$serverA.Process.Id
    # 注入真实进程终止，不用SQL直接改租约；数据库时钟自然到期后由B接管。
    Stop-LinkLakeE2EChild -Child $serverA -Name 'server-a-before-crash'
    $serverA=$null
    Stop-LinkLakeE2EChild -Child $clientA -Name 'client-a'
    $clientA=$null
    Wait-LinkLakeCondition -Process $serverB -Failure 'Follower did not take over after the leader process exited.' -Condition { (Invoke-RestMethod -Uri "$baseB/leaderz" -TimeoutSec 2).status -eq 'leader' }
    $newOverview=Invoke-RestMethod -Uri "$baseB/api/v1/ha/overview" -WebSession $webSession
    if ([uint64]$newOverview.local_fencing_token -le $oldFence) { throw 'Leader takeover did not advance the fencing token.' }
    # 保留原client ID/token和策略；测试显式将客户端端点切到新Leader。
    $clientB=Start-LinkLakeTestProcess -FilePath $ClientPath -Arguments ($agentArgs+@('--control',"127.0.0.1:$controlB")) -WorkingDirectory $runRoot -Environment @{LINKLAKE_AGENT_IDENTITY_PATH=(Join-Path $runRoot 'agent-identity.json')}
    Wait-LinkLakeCondition -Process $clientB -Failure 'Original client credentials did not recover real HTTP forwarding through leader B.' -Condition { Invoke-LinkLakeForwardedHttp -Port $httpB }
    $changedBody=@{client_id=$enrollment.client_id;name='after-failover';hostname='after-failover.example.test';target_addr="127.0.0.1:$backendPort";max_connections=8}|ConvertTo-Json
    $afterRoute=Invoke-RestMethod -Method Post -Uri "$baseB/api/v1/http-routes" -WebSession $webSession -ContentType 'application/json' -Body $changedBody
    # 旧incarnation的成员租约也须自然到期，才能用相同实例名启动新进程。
    Wait-LinkLakeCondition -Failure 'The exited server member lease did not expire.' -Condition {
        $oldMembers=@((Invoke-RestMethod -Uri "$baseB/api/v1/ha/members" -WebSession $webSession)|Where-Object {$_.instance_id -eq 'e2e-server-a'})
        $oldMembers.Count -eq 0 -or $oldMembers[0].lease_remaining_seconds -eq 0
    }
    $serverA=Start-LinkLakeTestProcess -FilePath $ServerPath -Arguments @() -WorkingDirectory $projectRoot -Environment $envA
    Wait-LinkLakeCondition -Process $serverA -Failure 'Original server failed to restart as a follower.' -Condition { (Invoke-RestMethod -Uri "$baseA/readyz" -TimeoutSec 2).status -eq 'ready' }
    $restarted=Invoke-RestMethod -Uri "$baseA/api/v1/ha/overview" -WebSession $webSession
    if ($restarted.local_is_leader -or $restarted.current_leader.instance_id -ne 'e2e-server-b') { throw 'Restarted old server incorrectly reclaimed leadership.' }
    $sharedAfter=Invoke-RestMethod -Uri "$baseA/api/v1/http-routes" -WebSession $webSession
    if (-not ($sharedAfter|Where-Object {$_.id -eq $afterRoute.id})) { throw 'Restarted follower did not load the policy written after failover.' }
    $rejected=Invoke-WebRequest -Method Post -Uri "$baseA/api/v1/http-routes" -WebSession $webSession -Headers @{'X-LinkLake-CSRF'='1'} -ContentType 'application/json' -Body $changedBody -SkipHttpErrorCheck
    if ($rejected.StatusCode -ne 503 -or ($rejected.Content|ConvertFrom-Json).code -ne 'ha_leader_required') { throw 'Restarted follower mutation was not fenced.' }
    if (-not (Invoke-LinkLakeForwardedHttp -Port $httpB)) { throw 'Leader B lost forwarding after old server restart.' }
    [ordered]@{passed=$true;suite='postgres_two_process_e2e';initialLeaderPid=$leaderPid;newLeaderPid=$serverB.Process.Id;restartedFollowerPid=$serverA.Process.Id;oldFence=$oldFence;newFence=$newOverview.local_fencing_token;evidence=@('independent_server_processes','shared_admin_session','shared_client_and_http_policy','follower_mutation_rejected','real_http_forwarding','leader_process_kill','lease_expiry_takeover','fence_advanced','original_client_credentials_reused','restarted_follower_reads_and_rejects_writes');limits=@('Harness explicitly changes the client control endpoint; automatic endpoint discovery/load-balancer failover is not certified.','HTTP only; this does not certify every data-plane protocol, network partitions, COMMIT response loss or ACME renewal.');completedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $runRoot 'result.json')
    Write-Output "Real PostgreSQL two-process HTTP failover passed. Evidence: $runRoot"
} finally {
    Stop-LinkLakeE2EChild -Child $clientA -Name 'client-a'
    Stop-LinkLakeE2EChild -Child $clientB -Name 'client-b'
    Stop-LinkLakeE2EChild -Child $serverA -Name 'server-a-final'
    Stop-LinkLakeE2EChild -Child $serverB -Name 'server-b'
    Stop-LinkLakeE2EChild -Child $backend -Name 'http-backend'
    Stop-LinkLakeDisposablePostgres -Context $postgres
}
