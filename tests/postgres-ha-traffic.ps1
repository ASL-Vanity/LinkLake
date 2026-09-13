param(
    [switch]$RunVerification,
    [string]$PostgresImage = 'postgres:16-alpine',
    [string]$PostgresBinDir,
    [string]$DisposablePostgresUrl,
    [string]$TestBinaryPath,
    [int]$TimeoutSeconds = 900
)
. (Join-Path $PSScriptRoot 'postgres-harness-common.ps1')
Invoke-LinkLakePostgresRustSuite @PSBoundParameters -Suite 'real_postgres_traffic_cluster_contract' -EvidenceMarker 'real_pg_traffic_contract_complete:' -ArtifactPrefix 'pg-ha-traffic' -Evidence @('independent_pg_sessions','atomic_sliding_window','transaction_rollback','pending_quota','uuid_replay_conflict','u64_saturation','persistent_spool_reopen','worker_drain','leader_failover','expired_member_rejection','corrupt_json_fail_closed')