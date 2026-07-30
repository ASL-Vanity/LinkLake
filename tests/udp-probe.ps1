param(
    [Parameter(Mandatory)][Alias('Host')][string]$HostName,
    [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
    [ValidateRange(1, 1000000)][int]$Count = 100,
    [ValidateRange(1, 100000)][int]$PacketsPerSecond = 50,
    [ValidateRange(0.0, 1.0)][double]$MinimumDeliveryRatio = 0.99,
    [ValidateRange(16, 65507)][int]$PayloadBytes = 256,
    [ValidateRange(1, 120)][int]$TimeoutSeconds = 5,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function New-ProbePayload {
    param([int]$Sequence, [int]$Length)
    $payload = [byte[]]::new($Length)
    $payload[0] = [byte][char]'L'
    $payload[1] = [byte][char]'L'
    $payload[2] = [byte][char]'P'
    $payload[3] = [byte][char]'R'
    [BitConverter]::GetBytes($Sequence).CopyTo($payload, 4)
    for ($index = 8; $index -lt $payload.Length; $index++) {
        $payload[$index] = [byte](($Sequence + $index * 17) % 251)
    }
    return $payload
}

function Get-Percentile {
    param([double[]]$Values, [double]$Percentile)
    if ($Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $index = [int][Math]::Ceiling(($sorted.Count - 1) * $Percentile)
    return [Math]::Round([double]$sorted[$index], 3)
}

$addresses = @([Net.Dns]::GetHostAddresses($HostName) | Where-Object {
    $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
})
if ($addresses.Count -eq 0) {
    throw "Host '$HostName' did not resolve to an IPv4 address."
}
$remote = [System.Net.IPEndPoint]::new($addresses[0], $Port)
$socket = [System.Net.Sockets.Socket]::new(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Dgram,
    [System.Net.Sockets.ProtocolType]::Udp
)
$socket.ReceiveBufferSize = 4 * 1024 * 1024
$socket.SendBufferSize = 4 * 1024 * 1024
$socket.Blocking = $false
$socket.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0))

$expectedHashes = New-Object 'string[]' $Count
$sentAtMilliseconds = New-Object 'double[]' $Count
$received = [Collections.Generic.HashSet[int]]::new()
$sha256 = [Security.Cryptography.SHA256]::Create()
$duplicates = 0
$corrupt = 0
$rtt = [Collections.Generic.List[double]]::new()
$receiveBuffer = [byte[]]::new(65507)
$stopwatch = [Diagnostics.Stopwatch]::StartNew()
$startedUtc = [DateTime]::UtcNow
$sent = 0
$intervalMilliseconds = 1000.0 / $PacketsPerSecond
$lastSendMilliseconds = 0.0

try {
    while ($true) {
        $now = $stopwatch.Elapsed.TotalMilliseconds
        while ($sent -lt $Count -and $now + 0.01 -ge $sent * $intervalMilliseconds) {
            $payload = New-ProbePayload -Sequence $sent -Length $PayloadBytes
            $expectedHashes[$sent] = [Convert]::ToBase64String($sha256.ComputeHash($payload))
            $sentAtMilliseconds[$sent] = $stopwatch.Elapsed.TotalMilliseconds
            $null = $socket.SendTo($payload, $remote)
            $sent++
            $lastSendMilliseconds = $stopwatch.Elapsed.TotalMilliseconds
            $now = $stopwatch.Elapsed.TotalMilliseconds
        }

        while ($socket.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead)) {
            $source = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            try {
                $length = $socket.ReceiveFrom($receiveBuffer, 0, $receiveBuffer.Length,
                    [System.Net.Sockets.SocketFlags]::None, [ref]$source)
            } catch [System.Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::WouldBlock) {
                    break
                }
                throw
            }
            if ($length -lt 8 -or $receiveBuffer[0] -ne [byte][char]'L' -or
                $receiveBuffer[1] -ne [byte][char]'L' -or $receiveBuffer[2] -ne [byte][char]'P' -or
                $receiveBuffer[3] -ne [byte][char]'R') {
                $corrupt++
                continue
            }
            $sequence = [BitConverter]::ToInt32($receiveBuffer, 4)
            if ($sequence -lt 0 -or $sequence -ge $Count -or $length -ne $PayloadBytes) {
                $corrupt++
                continue
            }
            $actual = [byte[]]::new($length)
            [Array]::Copy($receiveBuffer, 0, $actual, 0, $length)
            $actualHash = [Convert]::ToBase64String($sha256.ComputeHash($actual))
            if ($actualHash -ne $expectedHashes[$sequence]) {
                $corrupt++
                continue
            }
            if (-not $received.Add($sequence)) {
                $duplicates++
                continue
            }
            $rtt.Add($stopwatch.Elapsed.TotalMilliseconds - $sentAtMilliseconds[$sequence])
        }

        if ($sent -eq $Count) {
            if ($received.Count -eq $Count) { break }
            if ($stopwatch.Elapsed.TotalMilliseconds - $lastSendMilliseconds -ge $TimeoutSeconds * 1000) {
                break
            }
        }
        Start-Sleep -Milliseconds 1
    }
} finally {
    $stopwatch.Stop()
    $sha256.Dispose()
    $socket.Dispose()
}

$deliveryRatio = $received.Count / [double]$Count
$rttArray = [double[]]$rtt.ToArray()
$result = [ordered]@{
    host = $HostName
    resolved_address = $remote.Address.ToString()
    port = $Port
    payload_bytes = $PayloadBytes
    requested_packets_per_second = $PacketsPerSecond
    sent = $Count
    received_unique = $received.Count
    lost = $Count - $received.Count
    duplicates = $duplicates
    corrupt = $corrupt
    delivery_ratio = [Math]::Round($deliveryRatio, 6)
    rtt_ms = [ordered]@{
        minimum = Get-Percentile -Values $rttArray -Percentile 0.0
        p50 = Get-Percentile -Values $rttArray -Percentile 0.50
        p95 = Get-Percentile -Values $rttArray -Percentile 0.95
        p99 = Get-Percentile -Values $rttArray -Percentile 0.99
        maximum = Get-Percentile -Values $rttArray -Percentile 1.0
        average = if ($rttArray.Count -eq 0) { $null } else {
            [Math]::Round(($rttArray | Measure-Object -Average).Average, 3)
        }
    }
    started_utc = $startedUtc.ToString('o')
    finished_utc = [DateTime]::UtcNow.ToString('o')
}
$json = $result | ConvertTo-Json -Depth 4
if ($OutputPath) {
    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory) {
        New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    }
    [IO.File]::WriteAllText($OutputPath, $json, [Text.UTF8Encoding]::new($false))
}
$json

if ($deliveryRatio -lt $MinimumDeliveryRatio -or $duplicates -ne 0 -or $corrupt -ne 0) {
    throw "UDP probe failed: delivery=$deliveryRatio duplicates=$duplicates corrupt=$corrupt"
}
