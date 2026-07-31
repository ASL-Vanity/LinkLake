param(
    [int]$TcpPort = 18081,
    [int[]]$UdpPorts = @(19091, 19092, 19093),
    [int]$HttpPort = 18082,
    [int]$TlsPort = 18443,
    [string]$TlsHostname = 'sni.linklake.odelake.com',
    [string]$InstallDirectory = "$env:ProgramData\LinkLake\acceptance-targets",
    [string]$StatePath = "$env:ProgramData\LinkLake\acceptance-targets.json"
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Install-TargetTask {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$Script
    )
    $scriptPath = Join-Path $InstallDirectory "$TaskName.ps1"
    [IO.File]::WriteAllText($scriptPath, $Script, [Text.UTF8Encoding]::new($true))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $scriptPath
    )
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    [pscustomobject]@{ task_name = $TaskName; script_path = $scriptPath }
}

function Remove-TargetTask {
    param([Parameter(Mandatory)][string]$TaskName)
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

$tcpTaskName = "LinkLake-Acceptance-TCP-$TcpPort"
$udpTaskNames = @($UdpPorts | ForEach-Object { "LinkLake-Acceptance-UDP-$_" })
$httpTaskName = "LinkLake-Acceptance-HTTP-$HttpPort"
$tlsTaskName = "LinkLake-Acceptance-TLS-$TlsPort"
$taskNames = @($tcpTaskName) + $udpTaskNames + @($httpTaskName, $tlsTaskName)
$tcpPorts = @($TcpPort, $HttpPort, $TlsPort)
foreach ($taskName in $taskNames) { Remove-TargetTask -TaskName $taskName }
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    $remainingTcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object LocalPort -in $tcpPorts)
    $remainingUdp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Where-Object LocalPort -in $UdpPorts)
    if (-not $remainingTcp -and -not $remainingUdp) { break }
    Start-Sleep -Milliseconds 250
}

$occupiedTcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object LocalPort -in $tcpPorts)
$occupiedUdp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
    Where-Object LocalPort -in $UdpPorts)
if ($occupiedTcp -or $occupiedUdp) {
    throw 'An acceptance target port is already in use.'
}

New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null

$tcpScript = @"
`$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $TcpPort)
`$listener.Start()
try {
    while (`$true) {
        `$client = `$listener.AcceptTcpClient()
        try {
            `$stream = `$client.GetStream()
            `$buffer = [byte[]]::new(65536)
            while ((`$read = `$stream.Read(`$buffer, 0, `$buffer.Length)) -gt 0) {
                `$stream.Write(`$buffer, 0, `$read)
                `$stream.Flush()
            }
        } finally { `$client.Dispose() }
    }
} finally { `$listener.Stop() }
"@

$httpBody = 'linklake-http-acceptance'
$httpScript = @"
`$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $HttpPort)
`$listener.Start()
`$body = [Text.Encoding]::UTF8.GetBytes('$httpBody')
try {
    while (`$true) {
        `$client = `$listener.AcceptTcpClient()
        try {
            `$stream = `$client.GetStream()
            `$stream.ReadTimeout = 5000
            `$buffer = [byte[]]::new(4096)
            `$null = `$stream.Read(`$buffer, 0, `$buffer.Length)
            `$crlf = [string][char]13 + [char]10
            `$headers = "HTTP/1.1 200 OK`$crlf" +
                "Content-Type: text/plain; charset=utf-8`$crlf" +
                "Content-Length: `$(`$body.Length)`$crlf" +
                "Connection: close`$crlf`$crlf"
            `$headerBytes = [Text.Encoding]::ASCII.GetBytes(`$headers)
            `$stream.Write(`$headerBytes, 0, `$headerBytes.Length)
            `$stream.Write(`$body, 0, `$body.Length)
            `$stream.Flush()
        } finally { `$client.Dispose() }
    }
} finally { `$listener.Stop() }
"@

$tlsScript = @"
`$rsa = [Security.Cryptography.RSA]::Create(2048)
`$request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=$TlsHostname', `$rsa, [Security.Cryptography.HashAlgorithmName]::SHA256,
    [Security.Cryptography.RSASignaturePadding]::Pkcs1
)
`$generated = `$request.CreateSelfSigned(
    [DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddDays(7)
)
`$password = [guid]::NewGuid().ToString()
`$pfx = `$generated.Export(
    [Security.Cryptography.X509Certificates.X509ContentType]::Pfx, `$password
)
`$generated.Dispose()
`$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
    `$pfx,
    `$password,
    [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
        [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
)
`$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $TlsPort)
`$listener.Start()
try {
    while (`$true) {
        `$client = `$listener.AcceptTcpClient()
        try {
            `$ssl = [Net.Security.SslStream]::new(`$client.GetStream(), `$false)
            `$ssl.AuthenticateAsServer(
                `$certificate, `$false, [Security.Authentication.SslProtocols]::Tls12, `$false
            )
            `$buffer = [byte[]]::new(65536)
            while ((`$read = `$ssl.Read(`$buffer, 0, `$buffer.Length)) -gt 0) {
                `$ssl.Write(`$buffer, 0, `$read)
                `$ssl.Flush()
            }
        } catch {
        } finally { `$client.Dispose() }
    }
} finally {
    `$listener.Stop()
    `$certificate.Dispose()
    `$rsa.Dispose()
}
"@

$installedTasks = @()
try {
    $tcpTask = Install-TargetTask -TaskName $tcpTaskName -Script $tcpScript
    $installedTasks += $tcpTask

    $udpTasks = @()
    for ($index = 0; $index -lt $UdpPorts.Count; $index++) {
        $udpPort = $UdpPorts[$index]
        $udpScript = @"
`$udp = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $udpPort))
try {
    while (`$true) {
        `$source = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
        `$payload = `$udp.Receive([ref]`$source)
        `$null = `$udp.Send(`$payload, `$payload.Length, `$source)
    }
} finally { `$udp.Dispose() }
"@
        $udpTask = Install-TargetTask -TaskName $udpTaskNames[$index] -Script $udpScript
        $udpTasks += $udpTask
        $installedTasks += $udpTask
    }

    $httpTask = Install-TargetTask -TaskName $httpTaskName -Script $httpScript
    $installedTasks += $httpTask
    $tlsTask = Install-TargetTask -TaskName $tlsTaskName -Script $tlsScript
    $installedTasks += $tlsTask

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $tcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object LocalPort -in $tcpPorts)
        $udpListeners = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
            Where-Object LocalPort -in $UdpPorts)
        $listeningTcp = @($tcpListeners | Select-Object -ExpandProperty LocalPort)
        $listeningUdp = @($udpListeners | Select-Object -ExpandProperty LocalPort)
        if (($tcpPorts | Where-Object { $_ -notin $listeningTcp }).Count -eq 0 -and
            ($UdpPorts | Where-Object { $_ -notin $listeningUdp }).Count -eq 0) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    if (($tcpPorts | Where-Object { $_ -notin $listeningTcp }).Count -ne 0 -or
        ($UdpPorts | Where-Object { $_ -notin $listeningUdp }).Count -ne 0) {
        throw 'The acceptance targets did not become ready in time.'
    }

    $state = [ordered]@{
        started_utc = [DateTime]::UtcNow.ToString('O')
        tcp = @{
            port = $TcpPort
            pid = ($tcpListeners | Where-Object LocalPort -eq $TcpPort | Select-Object -First 1).OwningProcess
            task_name = $tcpTask.task_name
        }
        udp = @(for ($index = 0; $index -lt $UdpPorts.Count; $index++) {
            $port = $UdpPorts[$index]
            @{
                port = $port
                pid = ($udpListeners | Where-Object LocalPort -eq $port | Select-Object -First 1).OwningProcess
                task_name = $udpTasks[$index].task_name
            }
        })
        http = @{
            port = $HttpPort
            pid = ($tcpListeners | Where-Object LocalPort -eq $HttpPort | Select-Object -First 1).OwningProcess
            task_name = $httpTask.task_name
            expected_body = $httpBody
        }
        tls = @{
            port = $TlsPort
            pid = ($tcpListeners | Where-Object LocalPort -eq $TlsPort | Select-Object -First 1).OwningProcess
            task_name = $tlsTask.task_name
            hostname = $TlsHostname
        }
    }
    [IO.File]::WriteAllText(
        $StatePath,
        ($state | ConvertTo-Json -Depth 6),
        [Text.UTF8Encoding]::new($true)
    )
    $state | ConvertTo-Json -Depth 6
} catch {
    foreach ($task in $installedTasks) {
        Remove-TargetTask -TaskName $task.task_name
    }
    throw
}
