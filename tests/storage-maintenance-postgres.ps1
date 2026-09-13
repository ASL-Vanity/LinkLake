param(
    [switch]$RunVerification,
    [string]$PostgresImage = 'postgres:16-alpine',
    [string]$PostgresBinDir,
    [string]$DisposablePostgresUrl,
    [string]$TestBinaryPath,
    [int]$TimeoutSeconds = 900
)
. (Join-Path $PSScriptRoot 'postgres-harness-common.ps1')
Invoke-LinkLakePostgresRustSuite @PSBoundParameters -Suite 'real_postgres_maintenance_cluster_contract' -EvidenceMarker 'real_pg_maintenance_contract_complete:' -ArtifactPrefix 'pg-maintenance' -Evidence @('source_lock','migration_rollback','migration_cancel','migration_replay','migration_manifest_guard','u64_and_credentials','real_pem_migration','multi_batch_rotation','corrupt_late_batch_rollback','reverse_rotation','fleet_eight_kinds','fleet_port_swap','fleet_replay','fleet_transaction_rollback','fleet_fencing')