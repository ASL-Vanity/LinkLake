$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$chartRoot = Join-Path $projectRoot 'deploy\helm\linklake'

$required = @(
    'Chart.yaml', 'values.yaml', 'values.schema.json', 'README.md',
    'templates\deployment.yaml', 'templates\service-management.yaml',
    'templates\service-data.yaml', 'templates\service-headless.yaml', 'templates\pvc.yaml',
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
    'type: Recreate', 'type: RollingUpdate', 'persistentVolumeClaimRetentionPolicy:',
    'LINKLAKE_STORAGE_BACKEND', 'LINKLAKE_POSTGRES_URL', 'LINKLAKE_HA_INSTANCE_ID',
    'path: /startupz', 'path: /readyz',
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
if ($schema.properties.replicaCount.minimum -ne 1 -or
    -not ($schema.properties.storage.properties.backend.enum -contains 'postgres')) {
    throw 'The Helm schema must describe SQLite and explicitly acknowledged PostgreSQL modes.'
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
    foreach ($contract in @('kind: Deployment', 'replicas: 1', 'type: Recreate', 'helm.sh/resource-policy: keep')) {
        if (-not $rendered.Contains($contract)) {
            throw "Default SQLite rendering is missing: $contract"
        }
    }

    $haSettings = @(
        '--set', 'auth.existingSecret=linklake-auth',
        '--set', 'tls.managementSecret=linklake-management-tls',
        '--set', 'tls.controlSecret=linklake-control-tls',
        '--set', 'storage.backend=postgres',
        '--set', 'storage.postgres.existingSecret=linklake-postgres',
        '--set', 'storage.postgres.replicatedStateAcknowledged=true',
        '--set', 'ha.enabled=true',
        '--set', 'replicaCount=3'
    )
    $haRendered = (& $helm.Source template linklake $chartRoot @haSettings) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'helm template for PostgreSQL HA mode failed.' }
    foreach ($contract in @(
        'kind: StatefulSet', 'replicas: 3', 'podManagementPolicy: Parallel',
        'type: RollingUpdate', 'persistentVolumeClaimRetentionPolicy:',
        'whenDeleted: Retain', 'whenScaled: Retain', 'volumeClaimTemplates:',
        'name: LINKLAKE_STORAGE_BACKEND', 'value: "postgres"',
        'name: LINKLAKE_POSTGRES_URL', 'name: LINKLAKE_HA_REPLICATED_STATE',
        'name: LINKLAKE_HA_INSTANCE_ID', 'fieldPath: metadata.name',
        'clusterIP: None', 'publishNotReadyAddresses: true'
    )) {
        if (-not $haRendered.Contains($contract)) {
            throw "PostgreSQL HA rendering is missing: $contract"
        }
    }

    & $helm.Source template linklake $chartRoot @requiredSettings --set replicaCount=2 *> $null
    if ($LASTEXITCODE -eq 0) {
        throw 'SQLite rendering must reject replicaCount greater than one.'
    }
    & $helm.Source template linklake $chartRoot @requiredSettings `
        --set storage.backend=postgres `
        --set storage.postgres.existingSecret=linklake-postgres *> $null
    if ($LASTEXITCODE -eq 0) {
        throw 'PostgreSQL rendering must require replicatedStateAcknowledged=true.'
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

Write-Host 'Helm chart contract passed: SQLite single-writer defaults, acknowledged PostgreSQL HA, rolling workload, PVC retention, external secrets, probes, services, PDB, and NetworkPolicy.'
