param(
    [string]$HostName = '127.0.0.1',
    [Parameter(Mandatory = $true)][int]$Port,
    [int]$Connections = 8,
    [int]$BytesPerConnection = 131072,
    [int]$ChunkBytes = 1024,
    [int]$DelayMilliseconds = 0,
    [int]$TimeoutMilliseconds = 60000
)

$ErrorActionPreference = 'Stop'
if ($Connections -lt 1 -or $Connections -gt 512) { throw 'Connections must be in 1-512.' }
if ($BytesPerConnection -lt 1 -or $BytesPerConnection -gt 67108864) { throw 'BytesPerConnection must be in 1-67108864.' }
if ($ChunkBytes -lt 1 -or $ChunkBytes -gt 1048576) { throw 'ChunkBytes must be in 1-1048576.' }

if (-not ('LinkLakeTcpLoadProbe' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

public static class LinkLakeTcpLoadProbe
{
    public static string Run(string host, int port, int connections, int bytesPerConnection,
        int chunkBytes, int delayMilliseconds, int timeoutMilliseconds)
    {
        var stopwatch = Stopwatch.StartNew();
        var tasks = new List<Task>();
        for (var worker = 0; worker < connections; worker++)
        {
            var workerId = worker;
            tasks.Add(Task.Run(() => RunWorker(host, port, workerId, bytesPerConnection,
                chunkBytes, delayMilliseconds, timeoutMilliseconds)));
        }
        Task.WaitAll(tasks.ToArray(), timeoutMilliseconds);
        if (tasks.Any(task => !task.IsCompleted))
            throw new TimeoutException("TCP load probe timed out.");
        stopwatch.Stop();
        var totalBytes = (long)connections * bytesPerConnection * 2L;
        var mibPerSecond = totalBytes / 1048576.0 / Math.Max(stopwatch.Elapsed.TotalSeconds, 0.001);
        return "{\"connections\":" + connections + ",\"bytes_each\":" + bytesPerConnection +
            ",\"round_trip_bytes\":" + totalBytes + ",\"elapsed_ms\":" + stopwatch.ElapsedMilliseconds +
            ",\"mib_per_second\":" + mibPerSecond.ToString("F3", System.Globalization.CultureInfo.InvariantCulture) + "}";
    }

    private static void RunWorker(string host, int port, int workerId, int bytesPerConnection,
        int chunkBytes, int delayMilliseconds, int timeoutMilliseconds)
    {
        var payload = new byte[bytesPerConnection];
        new Random(20260730 + workerId).NextBytes(payload);
        var received = new byte[payload.Length];
        using (var client = new TcpClient())
        {
            client.SendTimeout = timeoutMilliseconds;
            client.ReceiveTimeout = timeoutMilliseconds;
            client.Connect(host, port);
            using (var stream = client.GetStream())
            {
                var offset = 0;
                while (offset < payload.Length)
                {
                    var count = Math.Min(chunkBytes, payload.Length - offset);
                    stream.Write(payload, offset, count);
                    offset += count;
                    if (delayMilliseconds > 0) Thread.Sleep(delayMilliseconds);
                }
                offset = 0;
                while (offset < received.Length)
                {
                    var count = stream.Read(received, offset, received.Length - offset);
                    if (count == 0) throw new InvalidOperationException("TCP echo closed early.");
                    offset += count;
                }
            }
        }
        using (var sha = SHA256.Create())
        {
            if (!sha.ComputeHash(payload).SequenceEqual(sha.ComputeHash(received)))
                throw new InvalidOperationException("TCP echo payload was corrupted.");
        }
    }
}
'@
}

[LinkLakeTcpLoadProbe]::Run(
    $HostName,
    $Port,
    $Connections,
    $BytesPerConnection,
    $ChunkBytes,
    $DelayMilliseconds,
    $TimeoutMilliseconds
) | Write-Output
