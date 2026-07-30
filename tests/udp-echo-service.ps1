param(
    [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
    [Parameter(Mandatory)][string]$ObservationPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$directory = Split-Path -Parent $ObservationPath
if ($directory) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}

$encoding = [Text.UTF8Encoding]::new($false)
$writer = [IO.StreamWriter]::new($ObservationPath, $false, $encoding)
$socket = [System.Net.Sockets.UdpClient]::new(
    [System.Net.Sockets.AddressFamily]::InterNetwork
)
$socket.Client.ReceiveBufferSize = 4 * 1024 * 1024
$socket.Client.SendBufferSize = 4 * 1024 * 1024
$socket.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $Port))
$sha256 = [Security.Cryptography.SHA256]::Create()

try {
    $writer.WriteLine((@{
        event = 'ready'
        port = $Port
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Compress))
    $writer.Flush()

    while ($true) {
        $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $payload = $socket.Receive([ref]$remote)
        $hash = [BitConverter]::ToString($sha256.ComputeHash($payload)).Replace('-', '')
        $writer.WriteLine((@{
            event = 'datagram'
            timestamp_utc = [DateTime]::UtcNow.ToString('o')
            remote_ip = $remote.Address.ToString()
            remote_port = $remote.Port
            length = $payload.Length
            sha256 = $hash
        } | ConvertTo-Json -Compress))
        $writer.Flush()
        $sent = $socket.Send($payload, $payload.Length, $remote)
        if ($sent -ne $payload.Length) {
            throw "UDP echo sent only $sent of $($payload.Length) bytes."
        }
    }
} finally {
    $sha256.Dispose()
    $socket.Dispose()
    $writer.Dispose()
}
