$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$chartRoot = Join-Path $projectRoot 'deploy\helm\linklake'

$required = @(
    'Chart.yaml', 'values.yaml', 'values.schema.json', 'README.md',
    'templates\deployment.yaml', 'templates\service-management.yaml',
    'templates\service-data.yaml', 'templates\pvc.yaml',
    'templates\poddisruptionbudget.yaml', 'templates\networkpolicy.yaml'
)
foreach ($relative in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $chartRoot $relative))) {
        throw "Helm chart file is missing: $relative"
    }
}

$deployment = Get-Content -LiteralPath (Join-Path $chartRoot 'templates\deployment.yaml') -Raw
$values = Get-Content -LiteralPath (Join-Path $chartRoot 'values.yaml') -Raw
foreach ($contract in @(
    'type: Recreate', 'replicas: 1', 'path: /startupz', 'path: /readyz',
    'path: /livez', 'scheme: HTTPS', 'automountServiceAccountToken: false',
    'auth.existingSecret is required',
    'tls.managementSecret is required', 'tls.controlSecret is required'
)) {
    if (-not $deployment.Contains($contract)) {
        throw "Helm deployment contract is missing: $contract"
    }
}
if (-not $values.Contains('readOnlyRootFilesystem: true') -or
    -not $values.Contains('allowPrivilegeEscalation: false')) {
    throw 'The default container security context is incomplete.'
}
if ($deployment -match '(?i)kind:\s*Secret' -or $deployment -match '(?i)(password|token):\s*["''][^{}]') {
    throw 'The Helm chart must not render inline credentials.'
}

$schema = Get-Content -LiteralPath (Join-Path $chartRoot 'values.schema.json') -Raw | ConvertFrom-Json
if ($schema.properties.replicaCount.const -ne 1) {
    throw 'The Helm schema must enforce the single SQLite writer replica.'
}

$helm = Get-Command helm -ErrorAction SilentlyContinue
if ($helm) {
    $requiredSettings = @(
        '--set', 'auth.existingSecret=linklake-auth',
        '--set', 'tls.managementSecret=linklake-management-tls',
        '--set', 'tls.controlSecret=linklake-control-tls'
    )

    & $helm.Source lint $chartRoot @requiredSettings
    if ($LASTEXITCODE -ne 0) { throw 'helm lint failed.' }

    $rendered = (& $helm.Source template linklake $chartRoot @requiredSettings `
        --set 'services.data.publicTcpPorts[0]=25565' `
        --set 'services.data.publicUdpPorts[0]=19132') -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'helm template failed.' }
    foreach ($contract in @('name: tcp-25565', 'name: udp-19132')) {
        if (-not $rendered.Contains($contract)) {
            throw "Rendered Helm output is missing a dynamic service port: $contract"
        }
    }

    $defaultPolicy = (& $helm.Source template linklake $chartRoot @requiredSettings `
        --set networkPolicy.enabled=true `
        --show-only templates/networkpolicy.yaml) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'helm template for the default NetworkPolicy failed.' }
    if ($defaultPolicy -match '(?m)^\s*- port:\s*32100\s*$') {
        throw 'An empty networkPolicy.managementFrom must not expose the management port.'
    }

    $restrictedPolicy = (& $helm.Source template linklake $chartRoot @requiredSettings `
        --set networkPolicy.enabled=true `
        --set 'networkPolicy.managementFrom[0].podSelector.matchLabels.app=linklake-operator' `
        --show-only templates/networkpolicy.yaml) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'helm template for the restricted NetworkPolicy failed.' }
    foreach ($contract in @('app: linklake-operator', 'port: 32100')) {
        if (-not $restrictedPolicy.Contains($contract)) {
            throw "Restricted management NetworkPolicy is missing: $contract"
        }
    }
}

Write-Host 'Helm chart contract passed: single writer, external secrets, TLS probes, persistence, services, PDB, and NetworkPolicy.'
