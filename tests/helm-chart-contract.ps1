param(
    [string]$HelmPath = '',
    [switch]$SkipRender
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
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
    throw 'The Helm schema must describe SQLite and shared PostgreSQL modes.'
}

foreach ($contract in @(
    'certificateMaterial.existingSecret', 'LINKLAKE_CERTIFICATE_KEY_FILE',
    'prepare-certificate-material', 'umask 077',
    'test "$(wc -c < /certificate-material/key.pending)" -eq 32',
    'chmod 0600 /certificate-material/key.pending',
    'mv /certificate-material/key.pending /certificate-material/key',
    'medium: Memory', 'defaultMode: 0440'
)) {
    if (-not $deployment.Contains($contract)) {
        throw "Helm certificate material contract is missing: $contract"
    }
}
if ($schema.properties.certificateMaterial.properties.key.minLength -ne 1) {
    throw 'The certificate material Secret key must not be empty.'
}

if ($SkipRender) {
    Write-Warning 'Helm rendering was explicitly skipped; only static chart contracts were checked.'
    [ordered]@{ ok = $true; static_contracts = $true; helm_rendered = $false } | ConvertTo-Json -Compress
    return
}
if ([string]::IsNullOrWhiteSpace($HelmPath)) {
    $helm = Get-Command helm -ErrorAction SilentlyContinue
    if ($helm) { $HelmPath = $helm.Source }
}
if ([string]::IsNullOrWhiteSpace($HelmPath) -or -not (Test-Path -LiteralPath $HelmPath -PathType Leaf)) {
    throw 'Helm CLI is required for rendering. Pass -HelmPath, or explicitly use -SkipRender for static checks only.'
}

$script:rejectedConfigurations = 0
function Assert-HelmRejected {
    param([string[]]$Settings, [string]$ExpectedError)
    $output = (& $HelmPath template linklake $chartRoot @Settings 2>&1) -join "`n"
    if ($LASTEXITCODE -eq 0) {
        throw "Helm accepted a configuration that should fail: $ExpectedError"
    }
    if ($output -notmatch $ExpectedError) {
        throw "Helm rejected a configuration for an unexpected reason: $output"
    }
    $script:rejectedConfigurations += 1
}

if (-not $SkipRender) {
    $requiredSettings = @(
        '--set', 'auth.existingSecret=linklake-auth',
        '--set', 'tls.managementSecret=linklake-management-tls',
        '--set', 'tls.controlSecret=linklake-control-tls'
    )

    & $HelmPath lint $chartRoot @requiredSettings
    if ($LASTEXITCODE -ne 0) { throw 'helm lint failed.' }

    $rendered = (& $HelmPath template linklake $chartRoot @requiredSettings `
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
        '--set', 'ha.enabled=true',
        '--set', 'replicaCount=3'
    )
    $haRendered = (& $HelmPath template linklake $chartRoot @haSettings) -join "`n"
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

    if ($haRendered -match '(?m)^kind: PersistentVolumeClaim\s*$' -or
        $haRendered -match '(?m)^\s+claimName:') {
        throw 'HA rendering must allocate per-Pod claims instead of sharing standalone claims.'
    }

    $postgresSettings = $requiredSettings + @(
        '--set', 'storage.backend=postgres',
        '--set', 'storage.postgres.existingSecret=linklake-postgres'
    )
    $postgresRendered = (& $HelmPath template linklake $chartRoot @postgresSettings) -join "`n"
    if ($LASTEXITCODE -ne 0 -or -not $postgresRendered.Contains('kind: Deployment')) {
        throw 'Single-instance PostgreSQL must render without the deprecated replication acknowledgement.'
    }
    $withoutLogs = (& $HelmPath template linklake $chartRoot @haSettings --set persistence.logs.enabled=false) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $withoutLogs -notmatch '(?ms)- name: logs\s+emptyDir: \{\}') {
        throw 'HA must support ephemeral log storage while retaining per-Pod data claims.'
    }
    if ($rendered.Contains('prepare-certificate-material') -or $rendered.Contains('LINKLAKE_CERTIFICATE_KEY_FILE')) {
        throw 'An unconfigured certificate material Secret must not render an unusable init container or key path.'
    }

    $certificateSettings = $haSettings + @(
        '--set', 'certificateMaterial.existingSecret=linklake-certificate-material',
        '--set', 'certificateMaterial.key=material.key'
    )
    $certificateRendered = (& $HelmPath template linklake $chartRoot @certificateSettings --show-only templates/deployment.yaml) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Helm certificate material rendering failed.' }
    foreach ($contract in @(
        'name: prepare-certificate-material', 'runAsNonRoot: true', 'runAsUser: 10001', 'fsGroup: 10001',
        'secretName: "linklake-certificate-material"', 'key: "material.key"',
        'defaultMode: 0440', 'medium: Memory', 'sizeLimit: 1Mi',
        'test "$(wc -c < /certificate-material/key.pending)" -eq 32',
        'chmod 0600 /certificate-material/key.pending',
        'mv /certificate-material/key.pending /certificate-material/key',
        'name: LINKLAKE_CERTIFICATE_KEY_FILE', 'value: /etc/linklake/certificate-material/key'
    )) {
        if (-not $certificateRendered.Contains($contract)) {
            throw "Rendered certificate material contract is missing: $contract"
        }
    }
    $mainContainer = [regex]::Match($certificateRendered, '(?ms)^      containers:\s.*?(?=^      volumes:)').Value
    if ($mainContainer -notmatch 'mountPath: /etc/linklake/certificate-material\s+readOnly: true' -or
        $mainContainer.Contains('certificate-material-source')) {
        throw 'The server must mount only the prepared certificate material directory, read-only.'
    }

    Assert-HelmRejected ($requiredSettings + @('--set', 'replicaCount=2')) 'replicaCount|ha.enabled'
    Assert-HelmRejected ($requiredSettings + @('--set', 'ha.enabled=true')) 'storage.backend|replicaCount|backend'
    Assert-HelmRejected ($requiredSettings + @('--set', 'storage.backend=postgres')) 'existingSecret'
    Assert-HelmRejected ($postgresSettings + @('--set', 'replicaCount=3')) 'ha.enabled|enabled'
    Assert-HelmRejected ($postgresSettings + @('--set', 'persistence.data.enabled=false')) 'durable per-instance accounting'
    Assert-HelmRejected ($haSettings + @('--set', 'persistence.data.enabled=false')) 'persistence.data|enabled'
    Assert-HelmRejected ($haSettings + @('--set', 'persistence.data.existingClaim=shared-data')) 'existingClaim'
    Assert-HelmRejected ($haSettings + @('--set', 'persistence.logs.existingClaim=shared-logs')) 'existingClaim'
    Assert-HelmRejected ($haSettings + @('--set', 'ha.heartbeatSeconds=15')) 'heartbeatSeconds'
    Assert-HelmRejected ($haSettings + @('--set', 'ha.leaderLeaseSeconds=31')) 'leaderLeaseSeconds'
    Assert-HelmRejected ($certificateSettings + @('--set', 'podSecurityContext.fsGroup=0')) 'fsGroup'
    Assert-HelmRejected ($certificateSettings + @('--set', 'podSecurityContext.fsGroup=null')) 'fsGroup'
    Assert-HelmRejected ($certificateSettings + @('--set', 'certificateMaterial.key=../key')) 'certificateMaterial.key'
    Assert-HelmRejected ($certificateSettings + @(
        '--set', 'server.extraEnv[0].name=LINKLAKE_CERTIFICATE_KEY_FILE',
        '--set', 'server.extraEnv[0].value=/tmp/untrusted-key'
    )) 'Do not override LINKLAKE_CERTIFICATE_KEY_FILE'

    $defaultPolicy = (& $HelmPath template linklake $chartRoot @requiredSettings `
        --set networkPolicy.enabled=true `
        --show-only templates/networkpolicy.yaml) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'helm template for the default NetworkPolicy failed.' }
    if ($defaultPolicy -match '(?m)^\s*- port:\s*32100\s*$') {
        throw 'An empty networkPolicy.managementFrom must not expose the management port.'
    }

    $restrictedPolicy = (& $HelmPath template linklake $chartRoot @requiredSettings `
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

[ordered]@{
    ok = $true
    helm_rendered = $true
    sqlite_single_writer = $true
    postgres_shared_state = $true
    ha_per_pod_pvcs = $true
    certificate_material_secret = $true
    rejected_configurations = $script:rejectedConfigurations
} | ConvertTo-Json -Compress
