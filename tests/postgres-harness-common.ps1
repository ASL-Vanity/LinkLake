# 仅供显式验收的子进程和临时 PostgreSQL 工具；不会修改全局环境或注册服务。
$ErrorActionPreference = 'Stop'

function Get-LinkLakeTestPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Start-LinkLakeTestProcess {
    param([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory, [hashtable]$Environment = @{})
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    foreach ($name in @($start.Environment.Keys)) {
        if ($name -like 'LINKLAKE_*' -or $name -like 'PG*') { $null = $start.Environment.Remove($name) }
    }
    foreach ($name in $Environment.Keys) { $start.Environment[$name] = $Environment[$name] }
    $process = [Diagnostics.Process]::Start($start)
    return [pscustomobject]@{ Process = $process; Stdout = $process.StandardOutput.ReadToEndAsync(); Stderr = $process.StandardError.ReadToEndAsync() }
}

function Complete-LinkLakeTestProcess {
    param($Child, [string]$LogPrefix, [int]$TimeoutSeconds = 60)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not $Child.Process.WaitForExit(200)) {
        if ([DateTime]::UtcNow -ge $deadline) {
            $Child.Process.Kill($true)
            $Child.Process.WaitForExit()
            [IO.File]::WriteAllText("$LogPrefix.stdout.log", $Child.Stdout.GetAwaiter().GetResult())
            [IO.File]::WriteAllText("$LogPrefix.stderr.log", $Child.Stderr.GetAwaiter().GetResult())
            throw "Validation child process timed out; logs: $LogPrefix"
        }
    }
    $stdout = $Child.Stdout.GetAwaiter().GetResult()
    $stderr = $Child.Stderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText("$LogPrefix.stdout.log", $stdout)
    [IO.File]::WriteAllText("$LogPrefix.stderr.log", $stderr)
    return [pscustomobject]@{ ExitCode = $Child.Process.ExitCode; Stdout = $stdout; Stderr = $stderr }
}

function Invoke-LinkLakeTestCommand {
    param([string]$FilePath, [string[]]$Arguments, [string]$RunRoot, [string]$Name, [hashtable]$Environment = @{}, [int]$TimeoutSeconds = 60)
    $child = Start-LinkLakeTestProcess -FilePath $FilePath -Arguments $Arguments -WorkingDirectory $RunRoot -Environment $Environment
    $result = Complete-LinkLakeTestProcess -Child $child -LogPrefix (Join-Path $RunRoot $Name) -TimeoutSeconds $TimeoutSeconds
    if ($result.ExitCode -ne 0) { throw "Validation command $Name failed ($($result.ExitCode)); logs: $RunRoot" }
    return $result
}

function Start-LinkLakeDisposablePostgres {
    param([string]$RunRoot, [string]$PostgresBinDir, [string]$PostgresImage = 'postgres:16-alpine', [string]$DisposablePostgresUrl)
    if ($DisposablePostgresUrl) {
        if ($DisposablePostgresUrl -notmatch '^postgres(?:ql)?://linklake@127\.0\.0\.1:[0-9]+/linklake_ha_test_[A-Za-z0-9_]+(?:\?sslmode=disable)?$') {
            throw 'Only explicitly disposable loopback linklake_ha_test_ databases with the linklake test user are accepted.'
        }
        return [pscustomobject]@{ Backend = 'external-disposable'; Url = $DisposablePostgresUrl; RunRoot = $RunRoot }
    }
    $id = [guid]::NewGuid().ToString('N')
    $database = "linklake_ha_test_$id"
    $port = Get-LinkLakeTestPort
    if ($PostgresBinDir) {
        $bin = (Resolve-Path -LiteralPath $PostgresBinDir).Path
        foreach ($name in @('postgres.exe','initdb.exe','pg_ctl.exe','createdb.exe')) {
            if (-not (Test-Path -LiteralPath (Join-Path $bin $name))) { throw "Missing local PostgreSQL binary: $name" }
        }
        $data = Join-Path $RunRoot 'postgres-data'
        $null = Invoke-LinkLakeTestCommand -FilePath (Join-Path $bin 'initdb.exe') -Arguments @('-D',$data,'-U','linklake','--auth=trust','--encoding=UTF8','--no-locale') -RunRoot $RunRoot -Name 'initdb'
        # 唯一可达接口是IPv4 loopback；trust只适用于本次可销毁实例。
        # Windows的postmaster会继承pg_ctl的重定向管道，ReadToEnd因而不会到EOF。
        # 启动器不捕获管道；服务器日志由pg_ctl的-l参数写入本次目录。
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = Join-Path $bin 'pg_ctl.exe'
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.WorkingDirectory = $RunRoot
        foreach ($argument in @('-D',$data,'-l',(Join-Path $RunRoot 'postgres.log'),'-o',"-h 127.0.0.1 -p $port -F",'-w','-t','30','start')) { $start.ArgumentList.Add($argument) }
        foreach ($name in @($start.Environment.Keys)) { if ($name -like 'PG*') { $null = $start.Environment.Remove($name) } }
        $starter = [Diagnostics.Process]::Start($start)
        if (-not $starter.WaitForExit(40000)) { $starter.Kill($true); throw 'The local PostgreSQL startup process timed out.' }
        if ($starter.ExitCode -ne 0) { throw "Local PostgreSQL startup failed; logs: $RunRoot" }
        $context = [pscustomobject]@{ Backend = 'local'; Url = "postgresql://linklake@127.0.0.1:$port/$database`?sslmode=disable"; RunRoot = $RunRoot; Bin = $bin; Data = $data; Port = $port; Database = $database }
        try {
            $null = Invoke-LinkLakeTestCommand -FilePath (Join-Path $bin 'createdb.exe') -Arguments @('-h','127.0.0.1','-p',"$port",'-U','linklake',$database) -RunRoot $RunRoot -Name 'createdb'
        } catch { Stop-LinkLakeDisposablePostgres -Context $context; throw }
        return $context
    }
    $docker = (Get-Command docker -ErrorAction Stop).Source
    $name = "linklake-validation-$id"
    $null = Invoke-LinkLakeTestCommand -FilePath $docker -Arguments @('run','--detach','--rm','--name',$name,'--publish',"127.0.0.1:${port}:5432",'--env','POSTGRES_HOST_AUTH_METHOD=trust','--env','POSTGRES_USER=linklake','--env',"POSTGRES_DB=$database",$PostgresImage) -RunRoot $RunRoot -Name 'docker-start' -TimeoutSeconds 180
    $context = [pscustomobject]@{ Backend = 'docker'; Url = "postgresql://linklake@127.0.0.1:$port/$database`?sslmode=disable"; RunRoot = $RunRoot; Docker = $docker; Container = $name }
    try {
        $ready = $false
        for ($attempt = 0; $attempt -lt 60; $attempt++) {
            $child = Start-LinkLakeTestProcess -FilePath $docker -Arguments @('exec',$name,'pg_isready','--username','linklake','--dbname',$database) -WorkingDirectory $RunRoot
            $result = Complete-LinkLakeTestProcess -Child $child -LogPrefix (Join-Path $RunRoot 'pg-ready') -TimeoutSeconds 10
            if ($result.ExitCode -eq 0) { $ready = $true; break }
            Start-Sleep -Milliseconds 500
        }
        if (-not $ready) { throw 'The isolated PostgreSQL container did not become ready.' }
    } catch { Stop-LinkLakeDisposablePostgres -Context $context; throw }
    return $context
}

function Stop-LinkLakeDisposablePostgres {
    param($Context)
    if ($null -eq $Context) { return }
    if ($Context.Backend -eq 'local') {
        $null = Invoke-LinkLakeTestCommand -FilePath (Join-Path $Context.Bin 'pg_ctl.exe') -Arguments @('-D',$Context.Data,'-m','fast','-w','-t','30','stop') -RunRoot $Context.RunRoot -Name 'pg-stop'
    } elseif ($Context.Backend -eq 'docker') {
        $null = Invoke-LinkLakeTestCommand -FilePath $Context.Docker -Arguments @('logs',$Context.Container) -RunRoot $Context.RunRoot -Name 'postgres'
        $null = Invoke-LinkLakeTestCommand -FilePath $Context.Docker -Arguments @('rm','--force',$Context.Container) -RunRoot $Context.RunRoot -Name 'docker-stop'
    }
}

function Invoke-LinkLakePostgresRustSuite {
    param([switch]$RunVerification, [string]$PostgresBinDir, [string]$PostgresImage = 'postgres:16-alpine', [string]$DisposablePostgresUrl,
        [string]$TestBinaryPath, [int]$TimeoutSeconds = 900, [string]$Suite, [string]$EvidenceMarker, [string[]]$Evidence, [string]$ArtifactPrefix)
    if (-not $RunVerification) { throw 'No verification was executed. Pass -RunVerification explicitly.' }
    if ($TimeoutSeconds -lt 60 -or $TimeoutSeconds -gt 3600) { throw 'TimeoutSeconds must be between 60 and 3600.' }
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $runRoot = Join-Path $projectRoot ("logs/dev/$ArtifactPrefix-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $runRoot
    $postgres = $null
    $child = $null
    try {
        $postgres = Start-LinkLakeDisposablePostgres -RunRoot $runRoot -PostgresBinDir $PostgresBinDir -PostgresImage $PostgresImage -DisposablePostgresUrl $DisposablePostgresUrl
        $environment = @{
            LINKLAKE_PG_TEST_ALLOW_DISPOSABLE = '1'; LINKLAKE_PG_TEST_ARTIFACT_DIR = $runRoot
            LINKLAKE_STORAGE_BACKEND = 'postgres'; LINKLAKE_POSTGRES_URL = $postgres.Url
            LINKLAKE_POSTGRES_ALLOW_INSECURE_LOOPBACK = 'true'; LINKLAKE_POSTGRES_POOL_SIZE = '16'
            LINKLAKE_POSTGRES_ACQUIRE_TIMEOUT_SECONDS = '30'; LINKLAKE_HA_MEMBER_LEASE_SECONDS = '300'
            LINKLAKE_HA_LEADER_LEASE_SECONDS = '120'; LINKLAKE_HA_HEARTBEAT_SECONDS = '1'
        }
        if ($TestBinaryPath) {
            $program = (Resolve-Path -LiteralPath $TestBinaryPath).Path
            $arguments = @($Suite,'--ignored','--nocapture','--test-threads=1')
        } else {
            $program = (Get-Command cargo -ErrorAction Stop).Source
            $arguments = @('test','-p','linklake-server','--locked',$Suite,'--','--ignored','--nocapture','--test-threads=1')
        }
        # 未覆盖CARGO_TARGET_DIR；可复用调用方已经编译好的隔离target。
        $child = Start-LinkLakeTestProcess -FilePath $program -Arguments $arguments -WorkingDirectory $projectRoot -Environment $environment
        $result = Complete-LinkLakeTestProcess -Child $child -LogPrefix (Join-Path $runRoot 'test') -TimeoutSeconds $TimeoutSeconds
        if ($result.ExitCode -ne 0) { throw "Real PostgreSQL suite failed; logs: $runRoot" }
        if ($result.Stdout -notmatch ([regex]::Escape($Suite)+'\s+\.\.\.\s+ok') -or $result.Stderr -notmatch [regex]::Escape($EvidenceMarker)) {
            throw "The named test or completion evidence is missing; zero-test success is rejected. Logs: $runRoot"
        }
        [ordered]@{ suite=$Suite; passed=$true; postgresBackend=$postgres.Backend; evidence=$Evidence; completedUtc=[DateTime]::UtcNow.ToString('o'); limits=@('Two HA runtimes in one test process. Separate process/network and live TLS/ACME acceptance is required.') } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runRoot 'result.json')
        Write-Output "Real PostgreSQL $Suite passed. Evidence: $runRoot"
    } finally {
        if ($child -and -not $child.Process.HasExited) { $child.Process.Kill($true); $child.Process.WaitForExit() }
        Stop-LinkLakeDisposablePostgres -Context $postgres
    }
}
