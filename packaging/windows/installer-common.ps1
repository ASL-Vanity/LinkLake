Set-StrictMode -Version Latest

function Assert-LinkLakeAdministrator {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this installer from an elevated PowerShell window.'
    }
}

function Test-LinkLakeReservedPathComponent {
    param([Parameter(Mandatory)][string]$Component)

    $trimmed = $Component.TrimEnd([char]32, [char]46)
    if ($trimmed -ne $Component -or -not $trimmed) { return $true }
    $stem = $trimmed.Split('.')[0]
    return $stem -match '^(?i:CON|PRN|AUX|NUL|CLOCK\$|COM[1-9]|LPT[1-9])$'
}

function Resolve-LinkLakeSafePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [switch]$AllowReparsePoint,
        [switch]$RequireLocalDrive
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Name must not be blank." }
    if ($Path.IndexOfAny([char[]]@([char]0, [char]10, [char]13, [char]34)) -ge 0 -or
        $Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\') -or $Path.StartsWith('\??\')) {
        throw "$Name contains an unsafe control character or quote."
    }
    $isLocalDrive = $Path -match '^[A-Za-z]:[\\/]'
    $isUnc = $Path -match '^\\\\[^\\/]+[\\/][^\\/]+(?:[\\/]|$)'
    if (-not $isLocalDrive -and -not $isUnc) {
        throw "$Name must be a fully qualified absolute path."
    }
    if ($RequireLocalDrive -and -not $isLocalDrive) {
        throw "$Name must be located on a local drive."
    }
    if ($isLocalDrive -and $Path.Substring(2).Contains(':')) {
        throw "$Name must not use an alternate data stream."
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.TrimEnd([char]92, [char]47) -eq $root.TrimEnd([char]92, [char]47)) {
        throw "$Name must not be a filesystem root."
    }
    foreach ($component in ($fullPath.Substring($root.Length) -split '[\\/]')) {
        if ($component -and (Test-LinkLakeReservedPathComponent $component)) {
            throw "$Name contains a reserved or ambiguous Windows path component: $component"
        }
    }

    if (-not $AllowReparsePoint) {
        $cursor = $fullPath
        while ($cursor -and -not (Test-Path -LiteralPath $cursor)) {
            $cursor = [IO.Path]::GetDirectoryName($cursor)
        }
        while ($cursor -and $cursor -ne $root) {
            $item = Get-Item -Force -LiteralPath $cursor
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Name traverses a reparse point: $cursor"
            }
            $cursor = [IO.Path]::GetDirectoryName($cursor)
        }
    }
    return $fullPath.TrimEnd([char]92, [char]47)
}

function Test-LinkLakePathAtOrBelow {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    if ($Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    $prefix = $Root.TrimEnd([char]92, [char]47) + [IO.Path]::DirectorySeparatorChar
    return $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-LinkLakePathsDoNotOverlap {
    param(
        [Parameter(Mandatory)][string]$Left,
        [Parameter(Mandatory)][string]$LeftName,
        [Parameter(Mandatory)][string]$Right,
        [Parameter(Mandatory)][string]$RightName
    )
    if ((Test-LinkLakePathAtOrBelow $Left $Right) -or (Test-LinkLakePathAtOrBelow $Right $Left)) {
        throw "$LeftName and $RightName must not overlap."
    }
}

function Assert-LinkLakeSafeValue {
    param(
        [AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][string]$Name,
        [int]$MaximumLength = 8192
    )
    if ($null -eq $Value) { return }
    if ($Value.Length -gt $MaximumLength) { throw "$Name exceeds the length limit." }
    if (@($Value.ToCharArray() | Where-Object { [int]$_ -lt 32 -or [int]$_ -eq 127 }).Count -gt 0) {
        throw "$Name contains an unsafe control character."
    }
}

function Split-LinkLakeHostPort {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Name)
    Assert-LinkLakeSafeValue $Value $Name 512
    $match = if ($Value.StartsWith('[')) {
        [regex]::Match($Value, '^\[(?<host>[^\]]+)\]:(?<port>[0-9]{1,5})$')
    }
    else {
        [regex]::Match($Value, '^(?<host>[^:\s]+):(?<port>[0-9]{1,5})$')
    }
    if (-not $match.Success) { throw "$Name must use host:port or [IPv6]:port syntax." }
    $port = [int]$match.Groups['port'].Value
    if ($port -lt 1 -or $port -gt 65535) { throw "$Name contains an invalid port." }
    return [pscustomobject]@{ Host = $match.Groups['host'].Value; Port = $port }
}

function ConvertFrom-LinkLakeSocketAddress {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Name)
    $endpoint = Split-LinkLakeHostPort $Value $Name
    $address = $null
    if (-not [Net.IPAddress]::TryParse($endpoint.Host, [ref]$address)) {
        throw "$Name must contain a numeric IPv4 or IPv6 address."
    }
    return [pscustomobject]@{ Address = $address; Port = $endpoint.Port }
}

function Assert-LinkLakeHostPort {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Name)
    $endpoint = Split-LinkLakeHostPort $Value $Name
    $address = $null
    if (-not [Net.IPAddress]::TryParse($endpoint.Host, [ref]$address) -and
        [Uri]::CheckHostName($endpoint.Host) -ne [UriHostNameType]::Dns) {
        throw "$Name contains an invalid host name."
    }
}

function Assert-LinkLakeServerName {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Name)
    Assert-LinkLakeSafeValue $Value $Name 253
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$address) -and
        [Uri]::CheckHostName($Value) -ne [UriHostNameType]::Dns) {
        throw "$Name contains an invalid TLS server name."
    }
}

function Assert-LinkLakePemFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('certificate', 'private-key')][string]$Kind,
        [Parameter(Mandatory)][string]$Name
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Name was not found: $Path" }
    $length = (Get-Item -Force -LiteralPath $Path).Length
    if ($length -le 0 -or $length -gt 4MB) { throw "$Name has an invalid size." }
    $content = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Path))
    try {
        if ($Kind -eq 'certificate') {
            $blocks = [regex]::Matches(
                $content,
                '(?s)-----BEGIN CERTIFICATE-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----'
            )
            if ($blocks.Count -eq 0) { throw "$Name is not a supported PEM certificate file." }
            foreach ($block in $blocks) {
                try { $der = [Convert]::FromBase64String(($block.Groups['body'].Value -replace '\s', '')) }
                catch { throw "$Name contains invalid PEM certificate base64." }
                try { $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($der) }
                catch { throw "$Name contains an invalid X.509 certificate." }
                finally {
                    if ($certificate) { $certificate.Dispose() }
                    $certificate = $null
                    $der = $null
                }
            }
        }
        else {
            $blocks = [regex]::Matches(
                $content,
                '(?s)-----BEGIN (?<label>(?:RSA |EC )?PRIVATE KEY)-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END \k<label>-----'
            )
            if ($blocks.Count -ne 1) { throw "$Name must contain exactly one unencrypted PEM private key." }
            try { $der = [Convert]::FromBase64String(($blocks[0].Groups['body'].Value -replace '\s', '')) }
            catch { throw "$Name contains invalid PEM private-key base64." }
            if ($der.Length -eq 0) { throw "$Name contains an empty PEM private key." }
            $der = $null
        }
    }
    finally { $content = $null }
}

function Assert-LinkLakeUtf8ConfigFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Name was not found: $Path" }
    $length = (Get-Item -Force -LiteralPath $Path).Length
    if ($length -le 0 -or $length -gt 16MB) { throw "$Name has an invalid size." }
    try {
        $encoding = [Text.UTF8Encoding]::new($false, $true)
        $text = $encoding.GetString([IO.File]::ReadAllBytes($Path))
    }
    catch { throw "$Name must contain valid UTF-8 text." }
    if ([string]::IsNullOrWhiteSpace($text) -or $text.IndexOf([char]0) -ge 0) {
        throw "$Name must contain non-empty TOML text without NUL bytes."
    }
    $text = $null
}

function Test-LinkLakeSemVer {
    param([Parameter(Mandatory)][string]$Version)
    if ($Version.Length -gt 128 -or -not [regex]::IsMatch(
            $Version,
            '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$'
        )) {
        return $false
    }
    $withoutBuild = $Version.Split('+')[0]
    $separator = $withoutBuild.IndexOf('-')
    if ($separator -ge 0) {
        foreach ($identifier in $withoutBuild.Substring($separator + 1).Split('.')) {
            if ($identifier.Length -gt 1 -and $identifier[0] -eq '0' -and
                [regex]::IsMatch($identifier, '^[0-9]+$')) {
                return $false
            }
        }
    }
    return $true
}

function Compare-LinkLakeNumericIdentifier {
    param([Parameter(Mandatory)][string]$Left, [Parameter(Mandatory)][string]$Right)
    if ($Left.Length -lt $Right.Length) { return -1 }
    if ($Left.Length -gt $Right.Length) { return 1 }
    return [Math]::Sign([string]::CompareOrdinal($Left, $Right))
}

function Compare-LinkLakeSemVer {
    param([Parameter(Mandatory)][string]$Left, [Parameter(Mandatory)][string]$Right)
    if (-not (Test-LinkLakeSemVer $Left) -or -not (Test-LinkLakeSemVer $Right)) {
        throw 'Cannot compare an invalid semantic version.'
    }
    $pattern = '^(?<major>[0-9]+)\.(?<minor>[0-9]+)\.(?<patch>[0-9]+)(?:-(?<pre>[^+]+))?'
    $leftMatch = [regex]::Match($Left, $pattern)
    $rightMatch = [regex]::Match($Right, $pattern)
    foreach ($part in @('major', 'minor', 'patch')) {
        $comparison = Compare-LinkLakeNumericIdentifier $leftMatch.Groups[$part].Value $rightMatch.Groups[$part].Value
        if ($comparison -ne 0) { return $comparison }
    }
    $leftPre = $leftMatch.Groups['pre'].Value
    $rightPre = $rightMatch.Groups['pre'].Value
    if (-not $leftPre -and -not $rightPre) { return 0 }
    if (-not $leftPre) { return 1 }
    if (-not $rightPre) { return -1 }
    $leftParts = $leftPre.Split('.')
    $rightParts = $rightPre.Split('.')
    for ($index = 0; $index -lt [Math]::Min($leftParts.Count, $rightParts.Count); $index++) {
        $leftPart = $leftParts[$index]
        $rightPart = $rightParts[$index]
        $leftNumeric = $leftPart -match '^[0-9]+$'
        $rightNumeric = $rightPart -match '^[0-9]+$'
        if ($leftNumeric -and $rightNumeric) {
            $comparison = Compare-LinkLakeNumericIdentifier $leftPart $rightPart
            if ($comparison -ne 0) { return $comparison }
        }
        elseif ($leftNumeric) { return -1 }
        elseif ($rightNumeric) { return 1 }
        else {
            $comparison = [string]::CompareOrdinal($leftPart, $rightPart)
            if ($comparison -lt 0) { return -1 }
            if ($comparison -gt 0) { return 1 }
        }
    }
    return [Math]::Sign($leftParts.Count - $rightParts.Count)
}

function Read-LinkLakeReleaseIdentity {
    param([Parameter(Mandatory)][string]$PackageRoot, [Parameter(Mandatory)][string]$ExpectedTarget)
    $manifestPath = Join-Path $PackageRoot 'release.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Package identity manifest was not found: $manifestPath"
    }
    $manifestText = [IO.File]::ReadAllText($manifestPath, [Text.Encoding]::UTF8)
    if (-not $manifestText -or $manifestText.Length -gt 4096) { throw 'Package identity manifest has an invalid size.' }
    try { $manifest = $manifestText | ConvertFrom-Json }
    catch { throw 'Package identity manifest is not valid JSON.' }
    if ($null -eq $manifest -or $manifest -is [Array] -or $manifest -is [string] -or $manifest -is [ValueType]) {
        throw 'Package identity manifest must be a JSON object.'
    }
    $expectedFields = @('product', 'version', 'target', 'built_unix_seconds', 'commit')
    $actualFields = @($manifest.PSObject.Properties.Name)
    if (@(Compare-Object $expectedFields $actualFields).Count -ne 0) {
        throw 'Package identity manifest has missing or unknown fields.'
    }
    foreach ($field in @('product', 'version', 'target', 'commit')) {
        if ($manifest.$field -isnot [string]) { throw "Package identity field $field must be a string." }
    }
    if ($manifest.product -ne 'LinkLake') { throw 'Package identity has an unexpected product.' }
    if (-not (Test-LinkLakeSemVer $manifest.version)) { throw 'Package identity has an invalid version.' }
    if ($manifest.target -ne $ExpectedTarget) { throw 'Package identity targets another platform.' }
    if ($manifest.commit -notmatch '^[0-9a-f]{7,40}$') { throw 'Package identity has an invalid commit.' }
    if ($manifest.built_unix_seconds -is [string]) { throw 'Package identity has an invalid build time.' }
    try { $builtUnixSeconds = [Int64]$manifest.built_unix_seconds }
    catch { throw 'Package identity has an invalid build time.' }
    $latestAllowed = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 86400
    if ($builtUnixSeconds -le 0 -or $builtUnixSeconds -gt $latestAllowed) {
        throw 'Package identity has an invalid build time.'
    }
    return $manifest
}

function Get-LinkLakePackageInventory {
    param([Parameter(Mandatory)][string]$PackageRoot)

    $pending = [Collections.Generic.Queue[IO.DirectoryInfo]]::new()
    $pending.Enqueue([IO.DirectoryInfo]::new($PackageRoot))
    $files = [Collections.Generic.List[object]]::new()
    $entries = 0
    $totalBytes = [UInt64]0
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        foreach ($item in $directory.EnumerateFileSystemInfos()) {
            $entries++
            if ($entries -gt 4096) { throw 'Package contains too many filesystem entries.' }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Package contains a reparse point: $($item.FullName)"
            }
            if (($item.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                $pending.Enqueue([IO.DirectoryInfo]$item)
                continue
            }
            $file = [IO.FileInfo]$item
            if ($file.Length -gt 512MB) { throw "Package file exceeds the size limit: $($file.FullName)" }
            $totalBytes += [UInt64]$file.Length
            if ($totalBytes -gt 1GB) { throw 'Package exceeds the total uncompressed size limit.' }
            $files.Add($file)
        }
    }
    return @($files)
}

function Read-LinkLakeSha256Sidecar {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedFileName
    )
    $Path = Resolve-LinkLakeSafePath $Path 'SHA-256 sidecar'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing checksum: $Path" }
    $length = (Get-Item -Force -LiteralPath $Path).Length
    if ($length -le 0 -or $length -gt 512) { throw 'SHA-256 sidecar has an invalid size.' }
    $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::ASCII)
    $match = [regex]::Match($text, '^(?<hash>[0-9a-f]{64})  (?<name>[A-Za-z0-9][A-Za-z0-9._-]{0,255})(?:\r?\n)?$')
    if (-not $match.Success -or $match.Groups['name'].Value -cne $ExpectedFileName) {
        throw 'SHA-256 sidecar has an invalid or mismatched entry.'
    }
    return $match.Groups['hash'].Value
}

function Expand-LinkLakeZipArchiveSafely {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$DestinationPath
    )
    $ArchivePath = Resolve-LinkLakeSafePath $ArchivePath 'Windows release archive'
    $DestinationPath = Resolve-LinkLakeSafePath $DestinationPath 'archive extraction directory' -RequireLocalDrive
    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) { throw "Missing archive: $ArchivePath" }
    if ((Get-Item -Force -LiteralPath $ArchivePath).Length -gt 1GB) { throw 'Windows release archive exceeds the size limit.' }
    $destinationExisted = Test-Path -LiteralPath $DestinationPath
    if ($destinationExisted -and (Get-ChildItem -Force -LiteralPath $DestinationPath | Select-Object -First 1)) {
        throw 'Archive extraction directory must be empty.'
    }

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    $entries = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $totalLength = [UInt64]0
    try {
        foreach ($entry in $archive.Entries) {
            if ($entries.Count -ge 4096) { throw 'Windows release archive contains too many entries.' }
            $name = $entry.FullName.Replace([char]92, [char]47)
            if (-not $name -or [regex]::IsMatch($name, '[\x00-\x1F<>"|?*]') -or
                $name.StartsWith('/') -or $name -match '^[A-Za-z]:' -or $name.Contains(':') -or
                $name.Contains('//')) {
                throw "Windows release archive contains an unsafe entry: $name"
            }
            $isDirectory = $name.EndsWith('/')
            $components = @($name.TrimEnd('/').Split('/'))
            if ($components.Count -eq 0 -or @($components | Where-Object {
                        -not $_ -or $_ -in @('.', '..') -or (Test-LinkLakeReservedPathComponent $_)
                    }).Count -gt 0) {
                throw "Windows release archive contains an unsafe entry: $name"
            }
            $identity = $name.TrimEnd('/')
            if (-not $seen.Add($identity)) { throw "Windows release archive repeats entry $identity." }
            if ($entry.Length -lt 0 -or $entry.Length -gt 512MB) {
                throw "Windows release archive entry exceeds the size limit: $name"
            }
            $totalLength += [UInt64]$entry.Length
            if ($totalLength -gt 1GB) { throw 'Windows release archive exceeds the uncompressed size limit.' }
            if ($entry.Length -gt 10MB -and
                ($entry.CompressedLength -le 0 -or ($entry.Length / [double]$entry.CompressedLength) -gt 1000)) {
                throw "Windows release archive entry has an unsafe compression ratio: $name"
            }
            $target = [IO.Path]::GetFullPath((Join-Path $DestinationPath $name.Replace([char]47, [IO.Path]::DirectorySeparatorChar)))
            $prefix = $DestinationPath.TrimEnd([char]92, [char]47) + [IO.Path]::DirectorySeparatorChar
            if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Windows release archive entry escapes the destination: $name"
            }
            $entries.Add([pscustomobject]@{ Entry = $entry; Name = $identity; Target = $target; IsDirectory = $isDirectory })
        }

        New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
        $actualTotal = [UInt64]0
        foreach ($item in $entries) {
            if ($item.IsDirectory) {
                New-Item -ItemType Directory -Force -Path $item.Target | Out-Null
                continue
            }
            $parent = Split-Path -Parent $item.Target
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
            $source = $item.Entry.Open()
            $destination = [IO.File]::Open($item.Target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $buffer = New-Object byte[] 65536
                $written = [UInt64]0
                while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $written += [UInt64]$read
                    $actualTotal += [UInt64]$read
                    if ($written -gt 512MB -or $actualTotal -gt 1GB -or $written -gt [UInt64]$item.Entry.Length) {
                        throw "Windows release archive expanded beyond its declared limits: $($item.Name)"
                    }
                    $destination.Write($buffer, 0, $read)
                }
                if ($written -ne [UInt64]$item.Entry.Length) {
                    throw "Windows release archive entry length changed during extraction: $($item.Name)"
                }
            }
            finally {
                $destination.Dispose()
                $source.Dispose()
            }
        }
        return [pscustomobject]@{ Entries = [string[]]@($entries | ForEach-Object { $_.Name }); TotalBytes = $actualTotal }
    }
    catch {
        if (Test-Path -LiteralPath $DestinationPath) {
            Remove-Item -LiteralPath $DestinationPath -Recurse -Force
            if ($destinationExisted) { New-Item -ItemType Directory -Path $DestinationPath | Out-Null }
        }
        throw
    }
    finally {
        $archive.Dispose()
    }
}

function Assert-LinkLakePackageChecksums {
    param([Parameter(Mandatory)][string]$PackageRoot)
    $PackageRoot = Resolve-LinkLakeSafePath $PackageRoot 'package root'
    $manifestPath = Resolve-LinkLakeSafePath (Join-Path $PackageRoot 'checksums.sha256') 'package checksum manifest'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Package checksum manifest was not found: $manifestPath"
    }
    $manifest = [IO.File]::ReadAllText($manifestPath, [Text.Encoding]::ASCII)
    if (-not $manifest -or $manifest.Length -gt 4MB) { throw 'Package checksum manifest has an invalid size.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $rootPrefix = $PackageRoot.TrimEnd([char]92, [char]47) + [IO.Path]::DirectorySeparatorChar
    foreach ($line in ($manifest -split "`r?`n")) {
        if (-not $line) { continue }
        if ($seen.Count -ge 4096 -or $line.Length -gt 1024) {
            throw 'Package checksum manifest exceeds its entry limits.'
        }
        if ($line -notmatch '^(?<hash>[0-9a-f]{64})  (?<path>[A-Za-z0-9][A-Za-z0-9._/-]*)$') {
            throw 'Package checksum manifest contains an invalid line.'
        }
        $expectedHash = $Matches.hash
        $relative = $Matches.path
        if ($relative.Contains('//') -or $relative.Contains('/./') -or
            $relative.StartsWith('/') -or $relative.Split('/') -contains '..') {
            throw 'Package checksum manifest contains an unsafe path.'
        }
        if (-not $seen.Add($relative)) { throw "Package checksum manifest repeats $relative." }
        $candidate = [IO.Path]::GetFullPath((Join-Path $PackageRoot ($relative.Replace([char]47, [IO.Path]::DirectorySeparatorChar))))
        if (-not $candidate.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Package checksum path escapes the package root.'
        }
        $candidate = Resolve-LinkLakeSafePath $candidate "package entry $relative"
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Package entry is missing: $relative" }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidate).Hash.ToLowerInvariant()
        if ($actual -ne $expectedHash) { throw "Package entry failed SHA-256 validation: $relative" }
    }
    foreach ($required in @(
            'bin/linklake-server.exe', 'bin/linklake-client.exe', 'release.json',
            'windows/installer-common.ps1', 'windows/install-server.ps1',
            'windows/install-client.ps1', 'windows/uninstall.ps1'
        )) {
        if (-not $seen.Contains($required)) { throw "Package checksum manifest is missing $required." }
    }
    foreach ($file in (Get-LinkLakePackageInventory $PackageRoot)) {
        $relative = $file.FullName.Substring($PackageRoot.Length).TrimStart([char]92, [char]47).Replace([char]92, [char]47)
        if ($relative -ne 'checksums.sha256' -and -not $seen.Contains($relative)) {
            throw "Package contains an entry that is not covered by checksums.sha256: $relative"
        }
    }
}

function Read-LinkLakeBinaryIdentity {
    param([Parameter(Mandatory)][string]$BinaryPath)
    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        throw "LinkLake binary was not found: $BinaryPath"
    }
    $output = @(& $BinaryPath --version-json 2>&1)
    if ($LASTEXITCODE -ne 0 -or $output.Count -ne 1) {
        throw "LinkLake binary did not return one successful version identity: $BinaryPath"
    }
    try { $identity = $output[0] | ConvertFrom-Json }
    catch { throw "LinkLake binary returned invalid version JSON: $BinaryPath" }
    $fields = @($identity.PSObject.Properties.Name)
    foreach ($required in @('product', 'version', 'target')) {
        if ($fields -notcontains $required) { throw "LinkLake binary identity is missing $required." }
    }
    if (-not (Test-LinkLakeSemVer $identity.version)) { throw 'LinkLake binary identity has an invalid version.' }
    return $identity
}

function Assert-LinkLakePackageBinary {
    param(
        [Parameter(Mandatory)][string]$BinaryPath,
        [Parameter(Mandatory)][string]$ExpectedProduct,
        [Parameter(Mandatory)]$ReleaseIdentity
    )
    $identity = Read-LinkLakeBinaryIdentity $BinaryPath
    if ($identity.product -ne $ExpectedProduct -or
        $identity.version -ne $ReleaseIdentity.version -or
        $identity.target -ne $ReleaseIdentity.target -or
        $identity.PSObject.Properties.Name -notcontains 'commit' -or
        $identity.commit -ne $ReleaseIdentity.commit) {
        throw "Binary identity does not match release.json: $BinaryPath"
    }
    return $identity
}

function Assert-LinkLakeNotDowngrade {
    param([Parameter(Mandatory)][string]$DestinationBinary, [Parameter(Mandatory)][string]$NewVersion)
    if (-not (Test-Path -LiteralPath $DestinationBinary -PathType Leaf)) { return }
    $installed = Read-LinkLakeBinaryIdentity $DestinationBinary
    if ((Compare-LinkLakeSemVer $NewVersion $installed.version) -lt 0) {
        throw "Refusing to replace LinkLake $($installed.version) with older version $NewVersion."
    }
}

function New-LinkLakeDirectoryAcl {
    param([switch]$WritableByService)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $localService = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl.SetOwner($administrators)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system, 'FullControl', $inheritance, $propagation, $allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($administrators, 'FullControl', $inheritance, $propagation, $allow))
    $serviceRights = if ($WritableByService) { 'Modify' } else { 'ReadAndExecute' }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($localService, $serviceRights, $inheritance, $propagation, $allow))
    return $acl
}

function Set-LinkLakeDirectoryAcl {
    param([Parameter(Mandatory)][string]$Path, [switch]$WritableByService)
    Set-Acl -LiteralPath $Path -AclObject (New-LinkLakeDirectoryAcl -WritableByService:$WritableByService)
}

function New-LinkLakeDirectoryTransactionPlan {
    param([Parameter(Mandatory)][string]$Path, [switch]$WritableByService)
    $exists = Test-Path -LiteralPath $Path
    if ($exists -and -not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Installer directory path is occupied by a file: $Path"
    }
    return [pscustomobject]@{
        Path = $Path
        WritableByService = [bool]$WritableByService
        Existed = $exists
        OriginalAclSddl = if ($exists) { (Get-Acl -LiteralPath $Path).Sddl } else { $null }
    }
}

function Install-LinkLakeDirectoryPlans {
    param([Parameter(Mandatory)][object[]]$Plans)
    foreach ($plan in $Plans) {
        New-Item -ItemType Directory -Force -Path $plan.Path | Out-Null
        Set-LinkLakeDirectoryAcl $plan.Path -WritableByService:$plan.WritableByService
    }
}

function Restore-LinkLakeDirectoryPlans {
    param([Parameter(Mandatory)][object[]]$Plans)
    for ($index = $Plans.Count - 1; $index -ge 0; $index--) {
        $plan = $Plans[$index]
        if (-not (Test-Path -LiteralPath $plan.Path -PathType Container)) { continue }
        if ($plan.Existed) {
            $acl = Get-Acl -LiteralPath $plan.Path
            $acl.SetSecurityDescriptorSddlForm($plan.OriginalAclSddl)
            Set-Acl -LiteralPath $plan.Path -AclObject $acl
        }
        elseif (-not (Get-ChildItem -Force -LiteralPath $plan.Path | Select-Object -First 1)) {
            Remove-Item -LiteralPath $plan.Path -Force
        }
        else {
            Write-Warning "Preserving non-empty directory created during the failed transaction: $($plan.Path)"
        }
    }
}

function Set-LinkLakeSecretFileAcl {
    param([Parameter(Mandatory)][string]$Path, [switch]$WritableByService, [switch]$Executable)
    $acl = [Security.AccessControl.FileSecurity]::new()
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $localService = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl.SetOwner($administrators)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system, 'FullControl', $allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($administrators, 'FullControl', $allow))
    $serviceRights = if ($WritableByService) { 'Modify' } elseif ($Executable) { 'ReadAndExecute' } else { 'Read' }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($localService, $serviceRights, $allow))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Enter-LinkLakeInstallerLock {
    param([int]$TimeoutSeconds = 30)

    $lockDirectory = Resolve-LinkLakeSafePath (Join-Path $env:ProgramData 'LinkLake') 'installer lock directory' -RequireLocalDrive
    New-Item -ItemType Directory -Force -Path $lockDirectory | Out-Null
    Set-LinkLakeDirectoryAcl $lockDirectory
    $lockPath = Join-Path $lockDirectory '.installer.lock'
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ($true) {
        try {
            $stream = [IO.File]::Open(
                $lockPath,
                [IO.FileMode]::OpenOrCreate,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
            try {
                Set-LinkLakeSecretFileAcl $lockPath
                return $stream
            }
            catch {
                $stream.Dispose()
                throw
            }
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) {
                throw 'Another LinkLake installer or uninstaller is still running.'
            }
            Start-Sleep -Milliseconds 250
        }
    }
}

function Exit-LinkLakeInstallerLock {
    param([IO.FileStream]$Lock)
    if ($null -eq $Lock) { return }
    $path = $Lock.Name
    $Lock.Dispose()
    try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop } catch {}
}

function Remove-LinkLakeArtifactBestEffort {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try { Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction Stop }
    catch { Write-Warning "Could not remove committed installer artifact ${Path}: $($_.Exception.Message)" }
}

function Remove-LinkLakeArtifactReportingResidual {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[string]]$ResidualPaths
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try { Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction Stop }
    catch {
        if (Test-Path -LiteralPath $Path) { $ResidualPaths.Add($Path) }
        Write-Warning "Could not remove committed installer artifact ${Path}: $($_.Exception.Message)"
    }
}

function Get-LinkLakeRegistryValueSnapshot {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
    }
    $key = Get-Item -LiteralPath $Path
    if ($key.GetValueNames() -notcontains $Name) {
        return [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
    }
    return [pscustomobject]@{
        Exists = $true
        Kind = $key.GetValueKind($Name).ToString()
        Value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    }
}

function Restore-LinkLakeRegistryValueSnapshot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Snapshot
    )
    if (-not $Snapshot.Exists) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        return
    }
    $propertyType = switch ($Snapshot.Kind) {
        'String' { 'String' }
        'ExpandString' { 'ExpandString' }
        'Binary' { 'Binary' }
        'DWord' { 'DWord' }
        'MultiString' { 'MultiString' }
        'QWord' { 'QWord' }
        default { throw "Cannot restore unsupported registry value kind $($Snapshot.Kind)." }
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $propertyType -Value $Snapshot.Value -Force | Out-Null
}

function Restore-LinkLakeRegistrySecurityDescriptor {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Sddl
    )
    if ($Path -notmatch '^HK(?:LM|CU):\\(?:[^*?\[\]]+\\)*[^*?\[\]]+$') {
        throw "Registry ACL path is not a safe absolute registry path: $Path"
    }
    try { $null = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl) }
    catch { throw "Registry key $Path has an invalid security descriptor snapshot." }
    # Windows PowerShell 5.1's registry provider does not resolve Get-Acl/Set-Acl -LiteralPath.
    $acl = Get-Acl -Path $Path
    $acl.SetSecurityDescriptorSddlForm($Sddl)
    Set-Acl -Path $Path -AclObject $acl
}

function Get-LinkLakeRegistrySecurityDescriptor {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^HK(?:LM|CU):\\(?:[^*?\[\]]+\\)*[^*?\[\]]+$') {
        throw "Registry ACL path is not a safe absolute registry path: $Path"
    }
    $sddl = (Get-Acl -Path $Path).Sddl
    try { $null = [Security.AccessControl.RawSecurityDescriptor]::new($sddl) }
    catch { throw "Registry key $Path returned an invalid security descriptor." }
    return $sddl
}

function Get-LinkLakeServiceEnvironment {
    param([Parameter(Mandatory)][string]$ServiceName)
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $snapshot = Get-LinkLakeRegistryValueSnapshot $path 'Environment'
    if (-not $snapshot.Exists) { return @() }
    return @([string[]]$snapshot.Value)
}

function ConvertFrom-LinkLakeEnvironment {
    param([string[]]$Entries)
    $result = [ordered]@{}
    foreach ($entry in @($Entries)) {
        Assert-LinkLakeSafeValue $entry 'service environment entry' 16384
        $separator = $entry.IndexOf('=')
        if ($separator -le 0) { throw 'Service environment contains a malformed entry.' }
        $key = $entry.Substring(0, $separator)
        $value = $entry.Substring($separator + 1)
        if ($key -cnotmatch '^[A-Z][A-Z0-9_]{0,127}$') {
            throw "Service environment contains an invalid variable name: $key"
        }
        if ($result.Contains($key)) { throw "Service environment repeats variable $key." }
        Assert-LinkLakeSafeValue $value "environment value $key"
        $result[$key] = $value
    }
    return $result
}

function ConvertTo-LinkLakeEnvironment {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)
    $entries = foreach ($key in ($Values.Keys | Sort-Object)) {
        if ([string]$key -cnotmatch '^[A-Z][A-Z0-9_]{0,127}$') {
            throw "Service environment contains an invalid variable name: $key"
        }
        Assert-LinkLakeSafeValue ([string]$Values[$key]) "environment value $key"
        "$key=$($Values[$key])"
    }
    return @($entries)
}

function Set-LinkLakeServiceEnvironment {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Entries
    )
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $acl = [Security.AccessControl.RegistrySecurity]::new()
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $acl.SetOwner($administrators)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($system, 'FullControl', $allow))
    $acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($administrators, 'FullControl', $allow))
    Set-Acl -Path $path -AclObject $acl
    New-ItemProperty -Path $path -Name Environment -PropertyType MultiString -Value ([string[]]@($Entries)) -Force | Out-Null
}

function Invoke-LinkLakeSc {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
    & $sc @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe failed with exit code $LASTEXITCODE." }
}

function Get-LinkLakeServiceSecurityDescriptor {
    param([Parameter(Mandatory)][string]$ServiceName)
    $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
    $output = @(& $sc sdshow $ServiceName 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Could not snapshot the service security descriptor for $ServiceName." }
    $sddl = @($output | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^(?:O:|G:|D:)' }) | Select-Object -Last 1
    if (-not $sddl -or $sddl.Length -gt 16384) { throw "Service $ServiceName returned an invalid security descriptor." }
    try { $null = [Security.AccessControl.RawSecurityDescriptor]::new($sddl) }
    catch { throw "Service $ServiceName returned an invalid security descriptor." }
    return $sddl
}

function Initialize-LinkLakeServiceNative {
    if ('LinkLakeServiceNative' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public sealed class LinkLakeFailureActionSnapshot
{
    public uint ResetPeriod;
    public string RebootMessage;
    public string Command;
    public int[] ActionTypes;
    public uint[] ActionDelays;
    public bool FailureActionsOnNonCrashFailures;
    public bool DelayedAutoStart;
}

public sealed class LinkLakeRequiredPrivilegesSnapshot
{
    public bool IsConfigured;
    public string[] Privileges;
}

public static class LinkLakeServiceNative
{
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_CHANGE_CONFIG = 0x0002;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const uint SERVICE_CONFIG_FAILURE_ACTIONS = 2;
    private const uint SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3;
    private const uint SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4;
    private const uint SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 6;

    [StructLayout(LayoutKind.Sequential)]
    private struct SC_ACTION
    {
        public int Type;
        public uint Delay;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SERVICE_FAILURE_ACTIONS
    {
        public uint ResetPeriod;
        public IntPtr RebootMessage;
        public IntPtr Command;
        public uint ActionCount;
        public IntPtr Actions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_FAILURE_ACTIONS_FLAG
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool Enabled;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_DELAYED_AUTO_START_INFO
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool Enabled;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_REQUIRED_PRIVILEGES_INFO
    {
        public IntPtr RequiredPrivileges;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig2(
        IntPtr service,
        uint infoLevel,
        IntPtr buffer,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2(IntPtr service, uint infoLevel, IntPtr info);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int argumentCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    private static IntPtr OpenServiceChecked(string serviceName, uint access, out IntPtr manager)
    {
        manager = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr service = OpenService(manager, serviceName, access);
        if (service == IntPtr.Zero)
        {
            int error = Marshal.GetLastWin32Error();
            CloseServiceHandle(manager);
            manager = IntPtr.Zero;
            throw new Win32Exception(error);
        }
        return service;
    }

    private static IntPtr QueryConfig(IntPtr service, uint level)
    {
        uint bytesNeeded;
        QueryServiceConfig2(service, level, IntPtr.Zero, 0, out bytesNeeded);
        int error = Marshal.GetLastWin32Error();
        if (bytesNeeded == 0 || error != ERROR_INSUFFICIENT_BUFFER)
            throw new Win32Exception(error);
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)bytesNeeded));
        if (!QueryServiceConfig2(service, level, buffer, bytesNeeded, out bytesNeeded))
        {
            error = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(buffer);
            throw new Win32Exception(error);
        }
        return buffer;
    }

    public static LinkLakeFailureActionSnapshot Capture(string serviceName)
    {
        IntPtr manager;
        IntPtr service = OpenServiceChecked(serviceName, SERVICE_QUERY_CONFIG, out manager);
        IntPtr failureBuffer = IntPtr.Zero;
        IntPtr flagBuffer = IntPtr.Zero;
        IntPtr delayedBuffer = IntPtr.Zero;
        try
        {
            failureBuffer = QueryConfig(service, SERVICE_CONFIG_FAILURE_ACTIONS);
            SERVICE_FAILURE_ACTIONS failure = (SERVICE_FAILURE_ACTIONS)Marshal.PtrToStructure(
                failureBuffer, typeof(SERVICE_FAILURE_ACTIONS));
            if (failure.ActionCount > 64) throw new InvalidOperationException("service has too many failure actions");
            int actionCount = checked((int)failure.ActionCount);
            int[] types = new int[actionCount];
            uint[] delays = new uint[actionCount];
            int actionSize = Marshal.SizeOf(typeof(SC_ACTION));
            for (int index = 0; index < actionCount; index++)
            {
                IntPtr actionPointer = IntPtr.Add(failure.Actions, checked(index * actionSize));
                SC_ACTION action = (SC_ACTION)Marshal.PtrToStructure(actionPointer, typeof(SC_ACTION));
                types[index] = action.Type;
                delays[index] = action.Delay;
            }

            flagBuffer = QueryConfig(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG);
            SERVICE_FAILURE_ACTIONS_FLAG flag = (SERVICE_FAILURE_ACTIONS_FLAG)Marshal.PtrToStructure(
                flagBuffer, typeof(SERVICE_FAILURE_ACTIONS_FLAG));
            delayedBuffer = QueryConfig(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO);
            SERVICE_DELAYED_AUTO_START_INFO delayed = (SERVICE_DELAYED_AUTO_START_INFO)Marshal.PtrToStructure(
                delayedBuffer, typeof(SERVICE_DELAYED_AUTO_START_INFO));

            LinkLakeFailureActionSnapshot snapshot = new LinkLakeFailureActionSnapshot();
            snapshot.ResetPeriod = failure.ResetPeriod;
            snapshot.RebootMessage = failure.RebootMessage == IntPtr.Zero ? null : Marshal.PtrToStringUni(failure.RebootMessage);
            snapshot.Command = failure.Command == IntPtr.Zero ? null : Marshal.PtrToStringUni(failure.Command);
            snapshot.ActionTypes = types;
            snapshot.ActionDelays = delays;
            snapshot.FailureActionsOnNonCrashFailures = flag.Enabled;
            snapshot.DelayedAutoStart = delayed.Enabled;
            return snapshot;
        }
        finally
        {
            if (failureBuffer != IntPtr.Zero) Marshal.FreeHGlobal(failureBuffer);
            if (flagBuffer != IntPtr.Zero) Marshal.FreeHGlobal(flagBuffer);
            if (delayedBuffer != IntPtr.Zero) Marshal.FreeHGlobal(delayedBuffer);
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
    }

    public static LinkLakeRequiredPrivilegesSnapshot CaptureRequiredPrivileges(string serviceName)
    {
        IntPtr manager;
        IntPtr service = OpenServiceChecked(serviceName, SERVICE_QUERY_CONFIG, out manager);
        IntPtr buffer = IntPtr.Zero;
        try
        {
            buffer = QueryConfig(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO);
            SERVICE_REQUIRED_PRIVILEGES_INFO info = (SERVICE_REQUIRED_PRIVILEGES_INFO)Marshal.PtrToStructure(
                buffer, typeof(SERVICE_REQUIRED_PRIVILEGES_INFO));
            LinkLakeRequiredPrivilegesSnapshot snapshot = new LinkLakeRequiredPrivilegesSnapshot();
            snapshot.IsConfigured = info.RequiredPrivileges != IntPtr.Zero;
            if (!snapshot.IsConfigured)
            {
                snapshot.Privileges = new string[0];
                return snapshot;
            }
            System.Collections.Generic.List<string> privileges = new System.Collections.Generic.List<string>();
            IntPtr cursor = info.RequiredPrivileges;
            while (true)
            {
                string privilege = Marshal.PtrToStringUni(cursor);
                if (String.IsNullOrEmpty(privilege)) break;
                privileges.Add(privilege);
                cursor = IntPtr.Add(cursor, checked((privilege.Length + 1) * 2));
            }
            snapshot.Privileges = privileges.ToArray();
            return snapshot;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
    }

    private static void ChangeConfigChecked(IntPtr service, uint level, IntPtr value)
    {
        if (!ChangeServiceConfig2(service, level, value))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public static string[] SplitCommandLine(string commandLine)
    {
        if (String.IsNullOrWhiteSpace(commandLine)) throw new ArgumentException("command line is blank", "commandLine");
        int count;
        IntPtr arguments = CommandLineToArgvW(commandLine, out count);
        if (arguments == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            string[] values = new string[count];
            for (int index = 0; index < count; index++)
            {
                IntPtr value = Marshal.ReadIntPtr(arguments, index * IntPtr.Size);
                values[index] = Marshal.PtrToStringUni(value);
            }
            return values;
        }
        finally { LocalFree(arguments); }
    }

    public static void Restore(string serviceName, LinkLakeFailureActionSnapshot snapshot)
    {
        if (snapshot == null) throw new ArgumentNullException("snapshot");
        if (snapshot.ActionTypes == null || snapshot.ActionDelays == null ||
            snapshot.ActionTypes.Length != snapshot.ActionDelays.Length || snapshot.ActionTypes.Length > 64)
            throw new ArgumentException("invalid failure action snapshot", "snapshot");

        IntPtr manager;
        IntPtr service = OpenServiceChecked(serviceName, SERVICE_CHANGE_CONFIG, out manager);
        IntPtr actions = IntPtr.Zero;
        IntPtr rebootMessage = IntPtr.Zero;
        IntPtr command = IntPtr.Zero;
        IntPtr failurePointer = IntPtr.Zero;
        IntPtr flagPointer = IntPtr.Zero;
        IntPtr delayedPointer = IntPtr.Zero;
        try
        {
            int actionSize = Marshal.SizeOf(typeof(SC_ACTION));
            if (snapshot.ActionTypes.Length > 0)
            {
                actions = Marshal.AllocHGlobal(checked(actionSize * snapshot.ActionTypes.Length));
                for (int index = 0; index < snapshot.ActionTypes.Length; index++)
                {
                    SC_ACTION action = new SC_ACTION();
                    action.Type = snapshot.ActionTypes[index];
                    action.Delay = snapshot.ActionDelays[index];
                    Marshal.StructureToPtr(action, IntPtr.Add(actions, checked(index * actionSize)), false);
                }
            }
            rebootMessage = Marshal.StringToHGlobalUni(snapshot.RebootMessage ?? String.Empty);
            command = Marshal.StringToHGlobalUni(snapshot.Command ?? String.Empty);
            SERVICE_FAILURE_ACTIONS failure = new SERVICE_FAILURE_ACTIONS();
            failure.ResetPeriod = snapshot.ResetPeriod;
            failure.RebootMessage = rebootMessage;
            failure.Command = command;
            failure.ActionCount = checked((uint)snapshot.ActionTypes.Length);
            failure.Actions = actions;
            failurePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SERVICE_FAILURE_ACTIONS)));
            Marshal.StructureToPtr(failure, failurePointer, false);
            ChangeConfigChecked(service, SERVICE_CONFIG_FAILURE_ACTIONS, failurePointer);

            SERVICE_FAILURE_ACTIONS_FLAG flag = new SERVICE_FAILURE_ACTIONS_FLAG();
            flag.Enabled = snapshot.FailureActionsOnNonCrashFailures;
            flagPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SERVICE_FAILURE_ACTIONS_FLAG)));
            Marshal.StructureToPtr(flag, flagPointer, false);
            ChangeConfigChecked(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, flagPointer);

            SERVICE_DELAYED_AUTO_START_INFO delayed = new SERVICE_DELAYED_AUTO_START_INFO();
            delayed.Enabled = snapshot.DelayedAutoStart;
            delayedPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SERVICE_DELAYED_AUTO_START_INFO)));
            Marshal.StructureToPtr(delayed, delayedPointer, false);
            ChangeConfigChecked(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, delayedPointer);
        }
        finally
        {
            if (actions != IntPtr.Zero) Marshal.FreeHGlobal(actions);
            if (rebootMessage != IntPtr.Zero) Marshal.FreeHGlobal(rebootMessage);
            if (command != IntPtr.Zero) Marshal.FreeHGlobal(command);
            if (failurePointer != IntPtr.Zero) Marshal.FreeHGlobal(failurePointer);
            if (flagPointer != IntPtr.Zero) Marshal.FreeHGlobal(flagPointer);
            if (delayedPointer != IntPtr.Zero) Marshal.FreeHGlobal(delayedPointer);
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
    }

    public static void RestoreRequiredPrivileges(string serviceName, LinkLakeRequiredPrivilegesSnapshot snapshot)
    {
        if (snapshot == null) throw new ArgumentNullException("snapshot");
        if (snapshot.Privileges == null || snapshot.Privileges.Length > 64)
            throw new ArgumentException("invalid required privilege snapshot", "snapshot");

        IntPtr manager;
        IntPtr service = OpenServiceChecked(serviceName, SERVICE_CHANGE_CONFIG, out manager);
        IntPtr privileges = IntPtr.Zero;
        IntPtr infoPointer = IntPtr.Zero;
        try
        {
            SERVICE_REQUIRED_PRIVILEGES_INFO info = new SERVICE_REQUIRED_PRIVILEGES_INFO();
            if (snapshot.IsConfigured)
            {
                string multiString = snapshot.Privileges.Length == 0
                    ? "\0"
                    : String.Join("\0", snapshot.Privileges) + "\0";
                privileges = Marshal.StringToHGlobalUni(multiString);
                info.RequiredPrivileges = privileges;
            }
            else
            {
                info.RequiredPrivileges = IntPtr.Zero;
            }
            infoPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SERVICE_REQUIRED_PRIVILEGES_INFO)));
            Marshal.StructureToPtr(info, infoPointer, false);
            ChangeConfigChecked(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, infoPointer);
        }
        finally
        {
            if (privileges != IntPtr.Zero) Marshal.FreeHGlobal(privileges);
            if (infoPointer != IntPtr.Zero) Marshal.FreeHGlobal(infoPointer);
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
    }
}
'@
}

function Get-LinkLakeServiceSnapshot {
    param([Parameter(Mandatory)][string]$ServiceName)
    $escapedServiceName = $ServiceName.Replace("'", "''")
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escapedServiceName'" -ErrorAction SilentlyContinue
    if (-not $service) {
        return [pscustomobject]@{
            Exists = $false
            State = 'Stopped'
            WasRunning = $false
            WasActive = $false
            PathName = $null
            StartMode = $null
            StartName = $null
            ServiceType = $null
            ErrorControl = $null
            DesktopInteract = $false
            DisplayName = $null
            Description = $null
            Environment = @()
            EnvironmentValue = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
            DelayedAutoStart = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
            FailureActions = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
            FailureActionsFlag = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
            ServiceDependencies = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
            GroupDependencies = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
            ServiceSidType = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
            RequiredPrivileges = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
            NativeRequiredPrivileges = $null
            PreshutdownTimeout = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
            LaunchProtected = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
            HasTriggers = $false
            NativeConfig = $null
            ServiceSddl = $null
            RegistrySddl = $null
        }
    }
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $environmentValue = Get-LinkLakeRegistryValueSnapshot $registryPath 'Environment'
    $requiredPrivilegesValue = Get-LinkLakeRegistryValueSnapshot $registryPath 'RequiredPrivileges'
    Initialize-LinkLakeServiceNative
    $nativeConfig = [LinkLakeServiceNative]::Capture($ServiceName)
    $nativeRequiredPrivileges = [LinkLakeServiceNative]::CaptureRequiredPrivileges($ServiceName)
    $nativeRequiredPrivileges.IsConfigured = [bool]$requiredPrivilegesValue.Exists
    $nativeRequiredPrivileges.Privileges = if ($requiredPrivilegesValue.Exists) {
        @([string[]]$requiredPrivilegesValue.Value | Where-Object { $_ })
    }
    else { @() }
    $runtimeState = switch ([string]$service.State) {
        'Start Pending' { 'Running' }
        'Continue Pending' { 'Running' }
        'Pause Pending' { 'Paused' }
        'Stop Pending' { 'Stopped' }
        default { [string]$service.State }
    }
    return [pscustomobject]@{
        Exists = $true
        State = $runtimeState
        WasRunning = $runtimeState -eq 'Running'
        WasActive = $runtimeState -ne 'Stopped'
        PathName = $service.PathName
        StartMode = $service.StartMode
        StartName = $service.StartName
        ServiceType = $service.ServiceType
        ErrorControl = $service.ErrorControl
        DesktopInteract = [bool]$service.DesktopInteract
        DisplayName = $service.DisplayName
        Description = $service.Description
        Environment = if ($environmentValue.Exists) { @([string[]]$environmentValue.Value) } else { @() }
        EnvironmentValue = $environmentValue
        DelayedAutoStart = Get-LinkLakeRegistryValueSnapshot $registryPath 'DelayedAutoStart'
        FailureActions = Get-LinkLakeRegistryValueSnapshot $registryPath 'FailureActions'
        FailureActionsFlag = Get-LinkLakeRegistryValueSnapshot $registryPath 'FailureActionsOnNonCrashFailures'
        ServiceDependencies = Get-LinkLakeRegistryValueSnapshot $registryPath 'DependOnService'
        GroupDependencies = Get-LinkLakeRegistryValueSnapshot $registryPath 'DependOnGroup'
        ServiceSidType = Get-LinkLakeRegistryValueSnapshot $registryPath 'ServiceSidType'
        RequiredPrivileges = $requiredPrivilegesValue
        NativeRequiredPrivileges = $nativeRequiredPrivileges
        PreshutdownTimeout = Get-LinkLakeRegistryValueSnapshot $registryPath 'PreshutdownTimeout'
        LaunchProtected = Get-LinkLakeRegistryValueSnapshot $registryPath 'LaunchProtected'
        HasTriggers = Test-Path -LiteralPath (Join-Path $registryPath 'TriggerInfo')
        NativeConfig = $nativeConfig
        ServiceSddl = Get-LinkLakeServiceSecurityDescriptor $ServiceName
        RegistrySddl = Get-LinkLakeRegistrySecurityDescriptor $registryPath
    }
}

function Stop-LinkLakeServiceChecked {
    param([Parameter(Mandatory)][string]$ServiceName, [int]$TimeoutSeconds = 30)
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) { return }
    try {
        if ($service.Status -eq 'Stopped') { return }
        if ($service.Status -ne 'StopPending') {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        }
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds($TimeoutSeconds))
    }
    finally { $service.Dispose() }
}

function Wait-LinkLakeServiceDeleted {
    param([Parameter(Mandatory)][string]$ServiceName, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) { return }
        $service.Dispose()
        Start-Sleep -Milliseconds 250
    }
    throw "Service $ServiceName is still pending deletion."
}

function Test-LinkLakeServiceExists {
    param([Parameter(Mandatory)][string]$ServiceName)
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) { return $false }
    $service.Dispose()
    return $true
}

function Start-LinkLakeServiceChecked {
    param([Parameter(Mandatory)][string]$ServiceName, [int]$TimeoutSeconds = 30, [int]$StableSeconds = 3)
    $initial = Get-Service -Name $ServiceName -ErrorAction Stop
    try {
        if ($initial.Status -ne 'Running' -and $initial.Status -ne 'StartPending') {
            Start-Service -Name $ServiceName -ErrorAction Stop
        }
    }
    finally { $initial.Dispose() }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $stableSince = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        try {
            if ($service.Status -eq 'Running') {
                if ($null -eq $stableSince) { $stableSince = [DateTime]::UtcNow }
                if (([DateTime]::UtcNow - $stableSince).TotalSeconds -ge $StableSeconds) { return }
            }
            else { $stableSince = $null }
        }
        finally { $service.Dispose() }
        Start-Sleep -Milliseconds 250
    }
    throw "Service $ServiceName did not remain running for $StableSeconds seconds."
}

function Wait-LinkLakeServiceStatus {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][ServiceProcess.ServiceControllerStatus]$Status,
        [int]$TimeoutSeconds = 30
    )
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    try { $service.WaitForStatus($Status, [TimeSpan]::FromSeconds($TimeoutSeconds)) }
    finally { $service.Dispose() }
}

function Restore-LinkLakeServiceRuntimeState {
    param([Parameter(Mandatory)][string]$ServiceName, [Parameter(Mandatory)]$Snapshot)
    switch ($Snapshot.State) {
        'Running' { Start-LinkLakeServiceChecked $ServiceName }
        'Paused' {
            Start-LinkLakeServiceChecked $ServiceName
            Suspend-Service -Name $ServiceName -ErrorAction Stop
            Wait-LinkLakeServiceStatus $ServiceName ([ServiceProcess.ServiceControllerStatus]::Paused)
        }
    }
}

function ConvertTo-LinkLakeServiceAccount {
    param([Parameter(Mandatory)][string]$StartName)
    $account = switch -Regex ($StartName) {
        '^(LocalSystem|NT AUTHORITY\\SYSTEM)$' { 'LocalSystem'; break }
        '^NT AUTHORITY\\LocalService$' { 'NT AUTHORITY\LocalService'; break }
        '^NT AUTHORITY\\NetworkService$' { 'NT AUTHORITY\NetworkService'; break }
        default { throw "Cannot automatically restore custom service account $StartName." }
    }
    return $account
}

function ConvertTo-LinkLakeServiceStartMode {
    param([Parameter(Mandatory)][string]$StartMode)
    $mode = switch ($StartMode) {
        'Auto' { 'auto' }
        'Disabled' { 'disabled' }
        'Manual' { 'demand' }
        default { throw "Cannot automatically restore service start mode $StartMode." }
    }
    return $mode
}

function ConvertTo-LinkLakeServiceType {
    param([Parameter(Mandatory)][string]$ServiceType)
    $type = switch ($ServiceType) {
        'Own Process' { 'own' }
        'Share Process' { 'share' }
        default { throw "Cannot automatically restore service type $ServiceType." }
    }
    return $type
}

function ConvertTo-LinkLakeServiceErrorControl {
    param([Parameter(Mandatory)][string]$ErrorControl)
    $mode = switch ($ErrorControl) {
        'Ignore' { 'ignore' }
        'Normal' { 'normal' }
        'Severe' { 'severe' }
        'Critical' { 'critical' }
        default { throw "Cannot automatically restore service error-control mode $ErrorControl." }
    }
    return $mode
}

function Assert-LinkLakeServiceSnapshotSupported {
    param([Parameter(Mandatory)]$Snapshot)
    if (-not $Snapshot.Exists) { return }
    $null = ConvertTo-LinkLakeServiceAccount $Snapshot.StartName
    $null = ConvertTo-LinkLakeServiceStartMode $Snapshot.StartMode
    $null = ConvertTo-LinkLakeServiceErrorControl $Snapshot.ErrorControl
    if ($Snapshot.ServiceType -ne 'Own Process' -or $Snapshot.DesktopInteract) {
        throw 'Transactional lifecycle changes require a non-interactive own-process LinkLake service.'
    }
    foreach ($dependency in @([string[]]$Snapshot.ServiceDependencies.Value) + @([string[]]$Snapshot.GroupDependencies.Value)) {
        if (-not $dependency) { continue }
        Assert-LinkLakeSafeValue $dependency 'service dependency' 256
        if ($dependency.Contains('/')) { throw 'Service dependencies must not contain slash delimiters.' }
    }
    $requiredPrivileges = if ($Snapshot.NativeRequiredPrivileges) {
        @([string[]]$Snapshot.NativeRequiredPrivileges.Privileges)
    }
    else { @([string[]]$Snapshot.RequiredPrivileges.Value) }
    foreach ($privilege in $requiredPrivileges) {
        if ($privilege -and $privilege -cnotmatch '^Se[A-Za-z0-9]+Privilege$') {
            throw "Service contains an invalid required privilege name: $privilege"
        }
    }
    if ($Snapshot.PreshutdownTimeout.Exists -or
        ($Snapshot.LaunchProtected.Exists -and [int]$Snapshot.LaunchProtected.Value -ne 0) -or
        $Snapshot.HasTriggers) {
        throw 'Transactional lifecycle changes refuse custom preshutdown, protected-service, or trigger settings.'
    }
}

function Assert-LinkLakeServiceOwnsBinary {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$ExpectedBinary,
        [Parameter(Mandatory)][string]$ServiceName
    )
    if (-not $Snapshot.Exists) { return }
    $arguments = Get-LinkLakeServiceCommandArguments $Snapshot
    if ($arguments.Count -lt 1) { throw "Service $ServiceName has an empty executable path." }
    $actualBinary = Resolve-LinkLakeSafePath ([string]$arguments[0]) "$ServiceName executable" -RequireLocalDrive
    if (-not $actualBinary.Equals($ExpectedBinary, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Service $ServiceName does not reference the requested LinkLake binary."
    }
}

function Get-LinkLakeServiceCommandArguments {
    param([Parameter(Mandatory)]$Snapshot)
    if (-not $Snapshot.Exists) { return @() }
    Initialize-LinkLakeServiceNative
    return [string[]][LinkLakeServiceNative]::SplitCommandLine([string]$Snapshot.PathName)
}

function Restore-LinkLakeServiceDependencies {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)]$ServiceDependencies,
        [Parameter(Mandatory)]$GroupDependencies
    )
    $dependencies = [Collections.Generic.List[string]]::new()
    if ($ServiceDependencies.Exists) {
        foreach ($dependency in @([string[]]$ServiceDependencies.Value)) {
            if ($dependency) { $dependencies.Add($dependency) }
        }
    }
    if ($GroupDependencies.Exists) {
        foreach ($group in @([string[]]$GroupDependencies.Value)) {
            if ($group) { $dependencies.Add("+$group") }
        }
    }
    $value = if ($dependencies.Count -eq 0) { '/' } else { $dependencies -join '/' }
    Invoke-LinkLakeSc @('config', $ServiceName, 'depend=', $value)
}

function Restore-LinkLakeAdvancedServiceConfiguration {
    param([Parameter(Mandatory)][string]$ServiceName, [Parameter(Mandatory)]$Snapshot)
    $sidType = if (-not $Snapshot.ServiceSidType.Exists -or [int]$Snapshot.ServiceSidType.Value -eq 0) {
        'none'
    }
    elseif ([int]$Snapshot.ServiceSidType.Value -eq 1) { 'unrestricted' }
    elseif ([int]$Snapshot.ServiceSidType.Value -eq 3) { 'restricted' }
    else { throw "Cannot restore service SID type $($Snapshot.ServiceSidType.Value)." }
    Invoke-LinkLakeSc @('sidtype', $ServiceName, $sidType)

    if ($Snapshot.NativeRequiredPrivileges) {
        Initialize-LinkLakeServiceNative
        [LinkLakeServiceNative]::RestoreRequiredPrivileges($ServiceName, $Snapshot.NativeRequiredPrivileges)
    }
    else {
        $privileges = if ($Snapshot.RequiredPrivileges.Exists) {
            @([string[]]$Snapshot.RequiredPrivileges.Value | Where-Object { $_ })
        }
        else { @() }
        $privilegeValue = if ($privileges.Count -eq 0) { '/' } else { $privileges -join '/' }
        Invoke-LinkLakeSc @('privs', $ServiceName, $privilegeValue)
    }

}

function Restore-LinkLakeServiceSnapshot {
    param([Parameter(Mandatory)][string]$ServiceName, [Parameter(Mandatory)]$Snapshot)
    if (-not $Snapshot.Exists) {
        if (Test-LinkLakeServiceExists $ServiceName) {
            try { Stop-LinkLakeServiceChecked $ServiceName 10 } catch {}
            Invoke-LinkLakeSc @('delete', $ServiceName)
            Wait-LinkLakeServiceDeleted $ServiceName
        }
        return
    }
    $account = ConvertTo-LinkLakeServiceAccount $Snapshot.StartName
    $start = ConvertTo-LinkLakeServiceStartMode $Snapshot.StartMode
    $type = ConvertTo-LinkLakeServiceType $Snapshot.ServiceType
    $errorControl = ConvertTo-LinkLakeServiceErrorControl $Snapshot.ErrorControl
    if (-not (Test-LinkLakeServiceExists $ServiceName)) {
        Invoke-LinkLakeSc @(
            'create', $ServiceName, 'binPath=', $Snapshot.PathName, 'start=', $start,
            'type=', $type, 'error=', $errorControl, 'obj=', $account, 'password=', '',
            'DisplayName=', $Snapshot.DisplayName
        )
    }
    Invoke-LinkLakeSc @(
        'config', $ServiceName, 'binPath=', $Snapshot.PathName, 'start=', $start,
        'type=', $type, 'error=', $errorControl, 'obj=', $account, 'password=', ''
    )
    Restore-LinkLakeServiceDependencies $ServiceName $Snapshot.ServiceDependencies $Snapshot.GroupDependencies
    Invoke-LinkLakeSc @('description', $ServiceName, $(if ($null -eq $Snapshot.Description) { '' } else { [string]$Snapshot.Description }))
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    Restore-LinkLakeRegistryValueSnapshot $registryPath 'Environment' $Snapshot.EnvironmentValue
    Restore-LinkLakeAdvancedServiceConfiguration $ServiceName $Snapshot
    if ($Snapshot.NativeConfig) {
        Initialize-LinkLakeServiceNative
        [LinkLakeServiceNative]::Restore($ServiceName, $Snapshot.NativeConfig)
    }
    foreach ($registryValue in @(
            @('DelayedAutoStart', $Snapshot.DelayedAutoStart),
            @('FailureActions', $Snapshot.FailureActions),
            @('FailureActionsOnNonCrashFailures', $Snapshot.FailureActionsFlag),
            @('DependOnService', $Snapshot.ServiceDependencies),
            @('DependOnGroup', $Snapshot.GroupDependencies),
            @('ServiceSidType', $Snapshot.ServiceSidType),
            @('RequiredPrivileges', $Snapshot.RequiredPrivileges)
        )) {
        Restore-LinkLakeRegistryValueSnapshot $registryPath $registryValue[0] $registryValue[1]
    }
    if ($Snapshot.RegistrySddl) {
        Restore-LinkLakeRegistrySecurityDescriptor $registryPath $Snapshot.RegistrySddl
    }
    if ($Snapshot.ServiceSddl) {
        Invoke-LinkLakeSc @('sdset', $ServiceName, $Snapshot.ServiceSddl)
    }
}

function Invoke-LinkLakeTransactionalChange {
    param(
        [Parameter(Mandatory)][scriptblock]$Stop,
        [Parameter(Mandatory)][scriptblock]$Apply,
        [Parameter(Mandatory)][scriptblock]$Validate,
        [Parameter(Mandatory)][scriptblock]$Start,
        [Parameter(Mandatory)][scriptblock]$Rollback,
        [Parameter(Mandatory)][scriptblock]$Recover,
        [bool]$WasRunning,
        [bool]$ShouldStart
    )
    $stopStarted = $false
    $applyStarted = $false
    try {
        if ($WasRunning) {
            $stopStarted = $true
            & $Stop
        }
        $applyStarted = $true
        & $Apply
        & $Validate
        if ($ShouldStart) { & $Start }
    }
    catch {
        $primary = $_.Exception.Message
        $recoveryErrors = [Collections.Generic.List[string]]::new()
        if ($applyStarted) {
            try { & $Rollback } catch { $recoveryErrors.Add("rollback: $($_.Exception.Message)") }
        }
        if ($WasRunning -and $stopStarted) {
            try { & $Recover } catch { $recoveryErrors.Add("service recovery: $($_.Exception.Message)") }
        }
        if ($recoveryErrors.Count -gt 0) {
            throw "$primary Recovery also failed: $($recoveryErrors -join '; ')"
        }
        if ($applyStarted) { throw "$primary The previous installation was restored." }
        throw $primary
    }
}

function Invoke-LinkLakeTransactionalUninstall {
    param(
        [Parameter(Mandatory)][scriptblock]$Stop,
        [Parameter(Mandatory)][scriptblock]$Stage,
        [Parameter(Mandatory)][scriptblock]$Remove,
        [Parameter(Mandatory)][scriptblock]$Commit,
        [Parameter(Mandatory)][scriptblock]$Rollback,
        [Parameter(Mandatory)][scriptblock]$Recover
    )
    $stopStarted = $false
    $stageStarted = $false
    try {
        $stopStarted = $true
        & $Stop
        $stageStarted = $true
        & $Stage
        & $Remove
    }
    catch {
        $primary = $_.Exception.Message
        $recoveryErrors = [Collections.Generic.List[string]]::new()
        if ($stageStarted) {
            try { & $Rollback } catch { $recoveryErrors.Add("rollback: $($_.Exception.Message)") }
        }
        if ($stopStarted) {
            try { & $Recover } catch { $recoveryErrors.Add("service recovery: $($_.Exception.Message)") }
        }
        if ($recoveryErrors.Count -gt 0) {
            throw "$primary Uninstall recovery also failed: $($recoveryErrors -join '; ')"
        }
        throw "$primary The previous installation and requested data were restored."
    }
    & $Commit
}
