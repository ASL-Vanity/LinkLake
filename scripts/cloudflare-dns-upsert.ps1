param(
    [Parameter(Mandatory=$true)][string]$ApiToken,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$ZoneId,
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$Content,
    [ValidateSet('A','AAAA','CNAME')][string]$Type = 'A',
    [bool]$Proxied = $false,
    [int]$Ttl = 1
)

$ErrorActionPreference = 'Stop'
$headers = @{ Authorization = "Bearer $ApiToken"; 'Content-Type' = 'application/json' }
$base = "https://api.cloudflare.com/client/v4/zones/$ZoneId/dns_records"
$query = "$base?type=$([uri]::EscapeDataString($Type))&name=$([uri]::EscapeDataString($Name))"
$existing = Invoke-RestMethod -Method Get -Uri $query -Headers $headers
if (-not $existing.success) { throw 'Cloudflare DNS lookup failed.' }
$body = @{ type = $Type; name = $Name; content = $Content; ttl = $Ttl; proxied = $Proxied } | ConvertTo-Json -Compress
if ($existing.result.Count -gt 1) { throw "Multiple matching DNS records exist for $Name/$Type." }
if ($existing.result.Count -eq 1) {
    $recordId = $existing.result[0].id
    $result = Invoke-RestMethod -Method Put -Uri "$base/$recordId" -Headers $headers -Body $body
} else {
    $result = Invoke-RestMethod -Method Post -Uri $base -Headers $headers -Body $body
}
if (-not $result.success) { throw 'Cloudflare DNS update failed.' }
$result.result | Select-Object id,type,name,content,proxied,ttl
