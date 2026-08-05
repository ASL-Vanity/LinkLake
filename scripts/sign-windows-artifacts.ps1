param(
    [ValidateSet('none', 'pfx', 'cloud')]
    [string]$Mode = 'none',
    [Parameter(Mandatory = $true)]
    [string[]]$Path
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-LinkLakeSignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $kitsRoot = $null
    foreach ($registryPath in @(
            'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots'
        )) {
        try {
            $candidate = (Get-ItemProperty -LiteralPath $registryPath -Name KitsRoot10 -ErrorAction Stop).KitsRoot10
            if ($candidate) { $kitsRoot = $candidate; break }
        }
        catch { }
    }
    if (-not $kitsRoot) { throw 'Windows SDK SignTool was not found.' }

    $candidates = Get-ChildItem -LiteralPath (Join-Path $kitsRoot 'bin') -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+(?:\.\d+){2,3}$' } |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
        Where-Object { Test-Path -LiteralPath $_ }
    $selected = @($candidates | Select-Object -First 1)
    if ($selected.Count -ne 1) { throw 'Windows SDK SignTool was not found.' }
    return $selected[0]
}

function Get-LinkLakeCertificateSha256 {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($Certificate.RawData)
        return (([BitConverter]::ToString($digest)) -replace '-', '').ToLowerInvariant()
    }
    finally { $sha256.Dispose() }
}

$secretNames = @(
    'LINKLAKE_WINDOWS_SIGNING_PFX_B64',
    'LINKLAKE_WINDOWS_SIGNING_PFX_PASSWORD',
    'LINKLAKE_WINDOWS_SIGNING_CERT_SHA256'
)
$configured = @($secretNames | Where-Object { -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_)) })
switch ($Mode) {
    'none' {
        if ($configured.Count -ne 0) {
            throw 'Unsigned Windows package mode refuses Authenticode credentials. Select -Mode pfx explicitly in a future approved signing workflow.'
        }
        Write-Host 'Windows packages are intentionally unsigned by release policy; SHA-256, GitHub attestations, and Ed25519 verification remain required.'
        return
    }
    'cloud' {
        throw 'Cloud Windows signing is reserved but not implemented; refusing to create a signed package.'
    }
    'pfx' {
        # PFX 后端仅供未来经审核的可选签名工作流显式调用，正式发布工作流不会选择此模式。
    }
}
foreach ($name in $secretNames) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "Windows Authenticode signing requires environment variable $name."
    }
}

$expectedFingerprint = $env:LINKLAKE_WINDOWS_SIGNING_CERT_SHA256.Replace(':', '').Trim().ToLowerInvariant()
if ($expectedFingerprint -notmatch '^[0-9a-f]{64}$') {
    throw 'LINKLAKE_WINDOWS_SIGNING_CERT_SHA256 must contain exactly 64 hexadecimal characters.'
}
$timestampUrl = if ([string]::IsNullOrWhiteSpace($env:LINKLAKE_WINDOWS_TIMESTAMP_URL)) {
    'http://timestamp.digicert.com'
}
else { $env:LINKLAKE_WINDOWS_TIMESTAMP_URL.Trim() }
$timestampUri = $null
if (-not [Uri]::TryCreate($timestampUrl, [UriKind]::Absolute, [ref]$timestampUri) -or
    $timestampUri.Scheme -notin @('http', 'https')) {
    throw 'LINKLAKE_WINDOWS_TIMESTAMP_URL must be an absolute HTTP or HTTPS URL.'
}

$resolvedPaths = [Collections.Generic.List[string]]::new()
foreach ($candidate in $Path) {
    $item = Get-Item -Force -LiteralPath $candidate -ErrorAction Stop
    if (-not $item.PSIsContainer -and $item.Extension.ToLowerInvariant() -in @('.exe', '.dll')) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to sign a reparse-point file: $($item.FullName)"
        }
        $resolvedPaths.Add($item.FullName)
    }
    else { throw "Only regular PE executables and libraries can be signed: $candidate" }
}
if ($resolvedPaths.Count -eq 0) { throw 'At least one Windows artifact must be supplied for signing.' }

$signTool = Get-LinkLakeSignTool
$storeName = "LinkLakeRelease$([guid]::NewGuid().ToString('N'))"
$storePath = "Cert:\CurrentUser\$storeName"
$pfxPath = Join-Path ([IO.Path]::GetTempPath()) "linklake-release-$([guid]::NewGuid().ToString('N')).pfx"
$pfxBytes = $null
$importedCertificates = @()
try {
    try { $pfxBytes = [Convert]::FromBase64String($env:LINKLAKE_WINDOWS_SIGNING_PFX_B64.Trim()) }
    catch { throw 'LINKLAKE_WINDOWS_SIGNING_PFX_B64 is not valid base64.' }
    if ($pfxBytes.Length -eq 0 -or $pfxBytes.Length -gt 4MB) {
        throw 'The Windows signing certificate archive has an invalid size.'
    }
    [IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $pfxPath -AclObject $acl

    $temporaryStore = [Security.Cryptography.X509Certificates.X509Store]::new(
        $storeName,
        [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    $temporaryStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $temporaryStore.Close()

    $securePassword = ConvertTo-SecureString $env:LINKLAKE_WINDOWS_SIGNING_PFX_PASSWORD -AsPlainText -Force
    $importedCertificates = @(Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation $storePath -Password $securePassword)
    $codeSigningOid = '1.3.6.1.5.5.7.3.3'
    $candidates = @($importedCertificates | Where-Object {
            $_.HasPrivateKey -and
            @($_.EnhancedKeyUsageList | ForEach-Object { $_.Value }) -contains $codeSigningOid
        })
    $matching = @($candidates | Where-Object { (Get-LinkLakeCertificateSha256 $_) -eq $expectedFingerprint })
    if ($matching.Count -ne 1) {
        throw 'The PFX must contain exactly one private code-signing certificate matching the pinned SHA-256 fingerprint.'
    }
    $certificate = $matching[0]
    $now = [DateTime]::UtcNow
    if ($certificate.NotBefore.ToUniversalTime() -gt $now -or $certificate.NotAfter.ToUniversalTime() -le $now) {
        throw 'The Windows code-signing certificate is not currently valid.'
    }

    foreach ($artifact in $resolvedPaths) {
        & $signTool sign /fd SHA256 /td SHA256 /tr $timestampUri.AbsoluteUri `
            /s $storeName /sha1 $certificate.Thumbprint /d LinkLake $artifact
        if ($LASTEXITCODE -ne 0) { throw "SignTool failed while signing $artifact." }
        & $signTool verify /pa /all $artifact
        if ($LASTEXITCODE -ne 0) { throw "SignTool verification failed for $artifact." }
        $signature = Get-AuthenticodeSignature -LiteralPath $artifact
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
            $null -eq $signature.SignerCertificate -or
            $null -eq $signature.TimeStamperCertificate) {
            throw "Authenticode or RFC 3161 timestamp verification failed for $artifact."
        }
    }
    Write-Host "Authenticode-signed and verified $($resolvedPaths.Count) Windows artifacts."
}
finally {
    if ($pfxBytes) { [Array]::Clear($pfxBytes, 0, $pfxBytes.Length) }
    if (Test-Path -LiteralPath $pfxPath) { Remove-Item -LiteralPath $pfxPath -Force }
    try {
        $cleanupStore = [Security.Cryptography.X509Certificates.X509Store]::new(
            $storeName,
            [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        $cleanupStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        foreach ($certificate in @($cleanupStore.Certificates)) { $cleanupStore.Remove($certificate) }
        $cleanupStore.Close()
    }
    catch { }
    $registryStore = "HKCU:\Software\Microsoft\SystemCertificates\$storeName"
    if ($storeName -match '^LinkLakeRelease[0-9a-f]{32}$' -and (Test-Path -LiteralPath $registryStore)) {
        Remove-Item -LiteralPath $registryStore -Recurse -Force
    }
}
