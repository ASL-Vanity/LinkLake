//! PostgreSQL 上的远程更新任务协调账本。

use super::*;
use crate::{
    ha_runtime::HaRuntime,
    storage::{CoordinationStorage, StorageBackend},
};
use std::sync::Arc;
use tokio_postgres::{Row, Transaction as PostgresTransaction};

const TARGET_LOCK_NAMESPACE: i32 = 0x4c4c_5554;
const IDEMPOTENCY_LOCK_NAMESPACE: i32 = 0x4c4c_5549;
const MAINTENANCE_LOCK_NAMESPACE: i32 = 0x4c4c_554d;

#[derive(Clone)]
pub(crate) struct PostgresUpdateTaskCatalog {
    storage: CoordinationStorage,
    database: Database,
    runtime: Arc<HaRuntime>,
}

struct StoredTask {
    task: RemoteUpdateTask,
    lease_token_sha256: Option<String>,
    request_fingerprint: String,
    terminal_replay: Option<TerminalReportReplay>,
}

enum TokenUpdate<'a> {
    Preserve,
    Set(&'a str),
    Clear,
    Terminal(&'a TerminalReportReplay),
}

impl PostgresUpdateTaskCatalog {
    pub(crate) fn open(
        storage: CoordinationStorage,
        database: &Database,
        runtime: Arc<HaRuntime>,
    ) -> Result<Self, UpdateTaskError> {
        if storage.backend() != StorageBackend::Postgres {
            return Err(UpdateTaskError::Storage(anyhow::anyhow!(
                "PostgreSQL remote update catalog requires PostgreSQL coordination storage"
            )));
        }
        Ok(Self {
            storage,
            database: database.clone(),
            runtime,
        })
    }

    async fn create_inner(
        &self,
        request: &CreateRemoteUpdateTaskRequest,
        requested_by: &str,
    ) -> anyhow::Result<RemoteUpdateTask> {
        request
            .validate()
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        validate_requested_by(requested_by).map_err(domain_error)?;
        if !self
            .client_exists(request.target_client_id)
            .map_err(domain_error)?
        {
            return Err(domain_error(UpdateTaskError::TargetNotFound));
        }

        let request = request.clone();
        let requested_by = requested_by.to_owned();
        let fingerprint = request_fingerprint(&request, &requested_by);
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_leader(&transaction).await?;
        lock_text(
            &transaction,
            IDEMPOTENCY_LOCK_NAMESPACE,
            &format!("{requested_by}\0{}", request.idempotency_key),
        )
        .await?;
        lock_target(&transaction, request.target_client_id).await?;
        let now = postgres_now(&transaction).await?;

        if let Some(existing) =
            task_by_idempotency(&transaction, &requested_by, &request.idempotency_key, true).await?
        {
            if existing.request_fingerprint != fingerprint {
                return Err(domain_error(UpdateTaskError::IdempotencyConflict));
            }
            reconcile_expired(&transaction, Some(existing.task.target_client_id), now).await?;
            let existing = task_by_id(&transaction, existing.task.task_id, true)
                .await?
                .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
            append_event(
                &transaction,
                &existing.task,
                RemoteUpdateEventKind::IdempotentReplay,
                now,
            )
            .await?;
            transaction.commit().await?;
            return Ok(existing.task);
        }

        reconcile_expired(&transaction, Some(request.target_client_id), now).await?;
        let active: bool = transaction
            .query_one(
                "SELECT EXISTS(
                    SELECT 1 FROM linklake_update_tasks
                    WHERE target_client_id = $1
                      AND state IN ('queued', 'claimed', 'running', 'cancel_requested')
                 )",
                &[&request.target_client_id.to_string()],
            )
            .await?
            .get(0);
        if active {
            return Err(domain_error(UpdateTaskError::TargetBusy));
        }
        let retained: i64 = transaction
            .query_one("SELECT COUNT(*) FROM linklake_update_tasks", &[])
            .await?
            .get(0);
        if retained >= MAX_RETAINED_TASKS {
            return Err(domain_error(UpdateTaskError::CapacityExceeded));
        }

        let task = RemoteUpdateTask {
            schema_version: REMOTE_UPDATE_CONTRACT_VERSION,
            task_id: Uuid::new_v4(),
            target_client_id: request.target_client_id,
            action: request.action,
            state: RemoteUpdateTaskState::Queued,
            stage: RemoteUpdateStage::Queued,
            recovery_state: RemoteUpdateRecoveryState::None,
            requested_by,
            idempotency_key: request.idempotency_key,
            attempt: 0,
            cancel_requested: false,
            lease_owner: None,
            lease_deadline_unix_seconds: None,
            restart: None,
            result: None,
            error_code: None,
            created_unix_seconds: now,
            updated_unix_seconds: now,
            completed_unix_seconds: None,
        };
        insert_task(&transaction, &task, &fingerprint).await?;
        append_event(&transaction, &task, RemoteUpdateEventKind::Created, now).await?;
        transaction.commit().await?;
        Ok(task)
    }

    async fn list_inner(
        &self,
        target_client_id: Option<Uuid>,
        requested_limit: usize,
    ) -> anyhow::Result<Vec<RemoteUpdateTask>> {
        if let Some(target_client_id) = target_client_id {
            validate_non_nil_uuid(target_client_id)
                .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        }
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_leader(&transaction).await?;
        match target_client_id {
            Some(target) => lock_target(&transaction, target).await?,
            None => lock_text(&transaction, MAINTENANCE_LOCK_NAMESPACE, "list").await?,
        }
        let now = postgres_now(&transaction).await?;
        reconcile_expired(&transaction, target_client_id, now).await?;
        let limit = i64::try_from(requested_limit.clamp(1, MAX_TASK_LIST_LIMIT))?;
        let rows = match target_client_id {
            Some(target) => {
                transaction
                    .query(
                        "SELECT snapshot_json FROM linklake_update_tasks
                         WHERE target_client_id = $1
                         ORDER BY created_unix_seconds DESC, task_id DESC LIMIT $2",
                        &[&target.to_string(), &limit],
                    )
                    .await?
            }
            None => {
                transaction
                    .query(
                        "SELECT snapshot_json FROM linklake_update_tasks
                         ORDER BY created_unix_seconds DESC, task_id DESC LIMIT $1",
                        &[&limit],
                    )
                    .await?
            }
        };
        let tasks = rows
            .iter()
            .map(task_snapshot)
            .collect::<anyhow::Result<_>>()?;
        transaction.commit().await?;
        Ok(tasks)
    }

    async fn detail_inner(&self, task_id: Uuid) -> anyhow::Result<RemoteUpdateTaskDetail> {
        validate_non_nil_uuid(task_id)
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_leader(&transaction).await?;
        let preliminary = task_by_id(&transaction, task_id, false)
            .await?
            .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
        lock_target(&transaction, preliminary.task.target_client_id).await?;
        let now = postgres_now(&transaction).await?;
        reconcile_expired(&transaction, Some(preliminary.task.target_client_id), now).await?;
        let task = task_by_id(&transaction, task_id, true)
            .await?
            .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?
            .task;
        let rows = transaction
            .query(
                "SELECT event_json FROM (
                    SELECT sequence, event_json FROM linklake_update_task_events
                    WHERE task_id = $1 ORDER BY sequence DESC LIMIT $2
                 ) AS recent ORDER BY sequence ASC",
                &[&task_id.to_string(), &MAX_EVENTS_PER_TASK],
            )
            .await?;
        let events = rows
            .iter()
            .map(event_snapshot)
            .collect::<anyhow::Result<_>>()?;
        let detail = RemoteUpdateTaskDetail { task, events };
        detail
            .validate(task_id)
            .map_err(|error| anyhow::anyhow!("invalid PostgreSQL update task detail: {error}"))?;
        transaction.commit().await?;
        Ok(detail)
    }

    async fn reconcile_after_restart_inner(&self) -> anyhow::Result<()> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_leader(&transaction).await?;
        lock_text(&transaction, MAINTENANCE_LOCK_NAMESPACE, "restart").await?;
        let now = postgres_now(&transaction).await?;
        let rows = transaction
            .query(
                "SELECT snapshot_json FROM linklake_update_tasks
                 WHERE state IN ('claimed', 'running', 'cancel_requested')
                 ORDER BY created_unix_seconds, task_id FOR UPDATE",
                &[],
            )
            .await?;
        for row in rows {
            let mut task = task_snapshot(&row)?;
            let lease_valid = task
                .lease_deadline_unix_seconds
                .is_some_and(|deadline| deadline > now)
                && task.lease_owner.is_some();
            if lease_valid {
                append_event(
                    &transaction,
                    &task,
                    RemoteUpdateEventKind::RestartReconciled,
                    now,
                )
                .await?;
            } else {
                let event = apply_lost_lease(&mut task, now);
                write_task(&transaction, &task, TokenUpdate::Clear).await?;
                append_event(&transaction, &task, event, now).await?;
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn sweep_inner(&self) -> anyhow::Result<()> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_leader(&transaction).await?;
        lock_text(&transaction, MAINTENANCE_LOCK_NAMESPACE, "sweep").await?;
        let now = postgres_now(&transaction).await?;
        reconcile_expired(&transaction, None, now).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn claim_inner(
        &self,
        target_client_id: Uuid,
        request: &RemoteUpdateClaimRequest,
    ) -> anyhow::Result<Option<RemoteUpdateClaim>> {
        validate_non_nil_uuid(target_client_id)
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        request
            .validate()
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_leader(&transaction).await?;
        lock_target(&transaction, target_client_id).await?;
        let now = postgres_now(&transaction).await?;
        reconcile_expired(&transaction, Some(target_client_id), now).await?;
        let row = transaction
            .query_opt(
                "SELECT snapshot_json, lease_token_sha256, request_fingerprint,
                        terminal_worker_instance_id, terminal_lease_token_sha256,
                        terminal_report_sha256
                 FROM linklake_update_tasks
                 WHERE target_client_id = $1 AND state = 'queued'
                 ORDER BY created_unix_seconds, task_id LIMIT 1 FOR UPDATE",
                &[&target_client_id.to_string()],
            )
            .await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(None);
        };
        let mut stored = stored_task(&row)?;
        if stored.task.attempt >= MAX_CLAIM_ATTEMPTS {
            stored.task.state = RemoteUpdateTaskState::Failed;
            stored.task.stage = RemoteUpdateStage::Failed;
            stored.task.recovery_state = RemoteUpdateRecoveryState::FailedClosed;
            stored.task.error_code = Some(RemoteUpdateErrorCode::FailedClosed);
            stored.task.updated_unix_seconds = now;
            stored.task.completed_unix_seconds = Some(now);
            clear_task_lease(&mut stored.task);
            write_task(&transaction, &stored.task, TokenUpdate::Clear).await?;
            append_event(
                &transaction,
                &stored.task,
                RemoteUpdateEventKind::Failed,
                now,
            )
            .await?;
            transaction.commit().await?;
            return Ok(None);
        }

        let lease_token = Uuid::new_v4();
        let lease_deadline = checked_deadline(now, request.requested_lease_seconds)?;
        stored.task.state = RemoteUpdateTaskState::Claimed;
        stored.task.stage = RemoteUpdateStage::Claimed;
        stored.task.recovery_state = RemoteUpdateRecoveryState::None;
        stored.task.restart = None;
        stored.task.attempt = stored
            .task
            .attempt
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("remote update task attempt counter overflowed"))?;
        stored.task.lease_owner = Some(request.worker_instance_id);
        stored.task.lease_deadline_unix_seconds = Some(lease_deadline);
        stored.task.updated_unix_seconds = now;
        let lease_hash = lease_token_sha256(lease_token);
        write_task(&transaction, &stored.task, TokenUpdate::Set(&lease_hash)).await?;
        append_event(
            &transaction,
            &stored.task,
            RemoteUpdateEventKind::Claimed,
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(Some(RemoteUpdateClaim {
            task: stored.task,
            lease_token,
            lease_deadline_unix_seconds: lease_deadline,
        }))
    }

    async fn renew_inner(
        &self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &RemoteUpdateLeaseRenewRequest,
    ) -> anyhow::Result<RemoteUpdateLeaseRenewResponse> {
        validate_non_nil_uuid(target_client_id)
            .and_then(|_| validate_non_nil_uuid(task_id))
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_leader(&transaction).await?;
        lock_target(&transaction, target_client_id).await?;
        let now = postgres_now(&transaction).await?;
        let mut stored = task_by_id(&transaction, task_id, true)
            .await?
            .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
        if stored.task.target_client_id != target_client_id {
            return Err(domain_error(UpdateTaskError::TaskNotFound));
        }
        request
            .validate(stored.task.action)
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        authorize_lease_token(
            &stored.task,
            stored.lease_token_sha256.as_deref(),
            &request.worker_instance_id,
            request.lease_token,
            now,
        )?;
        if !valid_renew_transition(stored.task.stage, request.stage, stored.task.action) {
            return Err(domain_error(UpdateTaskError::InvalidTransition));
        }
        let requested_deadline = checked_deadline(now, request.requested_lease_seconds)?;
        let deadline = if stored.task.stage == RemoteUpdateStage::AwaitingRestart
            || request.stage == RemoteUpdateStage::AwaitingRestart
        {
            let binding = stored
                .task
                .restart
                .as_ref()
                .ok_or_else(|| domain_error(UpdateTaskError::InvalidTransition))?;
            requested_deadline.min(binding.resume_deadline_unix_seconds)
        } else {
            requested_deadline
        };
        if deadline <= now {
            return Err(domain_error(UpdateTaskError::LeaseExpired));
        }
        stored.task.stage = request.stage;
        stored.task.state = if stored.task.cancel_requested {
            RemoteUpdateTaskState::CancelRequested
        } else if request.stage == RemoteUpdateStage::Claimed {
            RemoteUpdateTaskState::Claimed
        } else {
            RemoteUpdateTaskState::Running
        };
        stored.task.lease_deadline_unix_seconds = Some(deadline);
        stored.task.updated_unix_seconds = now;
        write_task(&transaction, &stored.task, TokenUpdate::Preserve).await?;
        append_event(
            &transaction,
            &stored.task,
            RemoteUpdateEventKind::LeaseRenewed,
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(RemoteUpdateLeaseRenewResponse {
            task_id,
            lease_deadline_unix_seconds: deadline,
            cancel_requested: stored.task.cancel_requested,
        })
    }

    async fn reconcile_inner(
        &self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &RemoteUpdateReconcileRequest,
    ) -> anyhow::Result<RemoteUpdateReconcileResponse> {
        validate_non_nil_uuid(target_client_id)
            .and_then(|_| validate_non_nil_uuid(task_id))
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        request
            .validate()
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;

        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_leader(&transaction).await?;
        lock_target(&transaction, target_client_id).await?;
        let now = postgres_now(&transaction).await?;
        let stored = task_by_id(&transaction, task_id, true)
            .await?
            .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
        if stored.task.target_client_id != target_client_id || stored.task.action != request.action
        {
            return Err(domain_error(UpdateTaskError::TaskNotFound));
        }

        reconcile_expired(&transaction, Some(target_client_id), now).await?;
        let stored = task_by_id(&transaction, task_id, true)
            .await?
            .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
        let state = if stored.task.state.is_terminal() {
            let replay = stored
                .terminal_replay
                .as_ref()
                .ok_or_else(|| domain_error(UpdateTaskError::LeaseConflict))?;
            validate_terminal_reconcile(&stored.task, replay, request)?;
            RemoteUpdateReconcileState::Terminal
        } else {
            authorize_lease_token(
                &stored.task,
                stored.lease_token_sha256.as_deref(),
                &request.worker_instance_id,
                request.lease_token,
                now,
            )?;
            validate_active_reconcile(&stored.task, request)?;
            RemoteUpdateReconcileState::Active
        };
        let response = RemoteUpdateReconcileResponse {
            state,
            task: stored.task,
        };
        transaction.commit().await?;
        Ok(response)
    }

    async fn report_inner(
        &self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &RemoteUpdateReportRequest,
    ) -> anyhow::Result<RemoteUpdateTask> {
        validate_non_nil_uuid(target_client_id)
            .and_then(|_| validate_non_nil_uuid(task_id))
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_leader(&transaction).await?;
        lock_target(&transaction, target_client_id).await?;
        let now = postgres_now(&transaction).await?;
        let mut stored = task_by_id(&transaction, task_id, true)
            .await?
            .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
        if stored.task.target_client_id != target_client_id {
            return Err(domain_error(UpdateTaskError::TaskNotFound));
        }
        request
            .validate(stored.task.action)
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        if stored.task.state.is_terminal() {
            validate_terminal_report_replay(
                stored
                    .terminal_replay
                    .as_ref()
                    .ok_or_else(|| domain_error(UpdateTaskError::InvalidTransition))?,
                request,
            )?;
            append_event(
                &transaction,
                &stored.task,
                RemoteUpdateEventKind::IdempotentReplay,
                now,
            )
            .await?;
            transaction.commit().await?;
            return Ok(stored.task);
        }
        validate_worker_report_transition(
            &request.report,
            stored.task.action,
            stored.task.stage,
            stored.task.cancel_requested,
        )?;
        authorize_lease_token(
            &stored.task,
            stored.lease_token_sha256.as_deref(),
            &request.worker_instance_id,
            request.lease_token,
            now,
        )?;
        let event = apply_worker_report(&mut stored.task, &request.report, now)?;
        let terminal_replay = stored
            .task
            .state
            .is_terminal()
            .then(|| TerminalReportReplay::from_request(request))
            .transpose()?;
        let token = if let Some(replay) = terminal_replay.as_ref() {
            TokenUpdate::Terminal(replay)
        } else if stored.task.lease_owner.is_some() {
            TokenUpdate::Preserve
        } else {
            TokenUpdate::Clear
        };
        write_task(&transaction, &stored.task, token).await?;
        append_event(&transaction, &stored.task, event, now).await?;
        transaction.commit().await?;
        Ok(stored.task)
    }

    async fn cancel_inner(
        &self,
        task_id: Uuid,
        request: &CancelRemoteUpdateTaskRequest,
    ) -> anyhow::Result<RemoteUpdateTask> {
        validate_non_nil_uuid(task_id)
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        request
            .validate()
            .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_leader(&transaction).await?;
        let preliminary = task_by_id(&transaction, task_id, false)
            .await?
            .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
        lock_target(&transaction, preliminary.task.target_client_id).await?;
        let now = postgres_now(&transaction).await?;
        reconcile_expired(&transaction, Some(preliminary.task.target_client_id), now).await?;
        let mut stored = task_by_id(&transaction, task_id, true)
            .await?
            .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
        if stored.task.state.is_terminal() || stored.task.cancel_requested {
            transaction.commit().await?;
            return Ok(stored.task);
        }
        stored.task.cancel_requested = true;
        stored.task.updated_unix_seconds = now;
        let event = if stored.task.state == RemoteUpdateTaskState::Queued {
            stored.task.state = RemoteUpdateTaskState::Cancelled;
            stored.task.stage = RemoteUpdateStage::Cancelled;
            stored.task.recovery_state = RemoteUpdateRecoveryState::None;
            stored.task.error_code = Some(RemoteUpdateErrorCode::Cancelled);
            stored.task.completed_unix_seconds = Some(now);
            clear_task_lease(&mut stored.task);
            RemoteUpdateEventKind::Cancelled
        } else {
            stored.task.state = RemoteUpdateTaskState::CancelRequested;
            RemoteUpdateEventKind::CancelRequested
        };
        let token = if stored.task.lease_owner.is_some() {
            TokenUpdate::Preserve
        } else {
            TokenUpdate::Clear
        };
        write_task(&transaction, &stored.task, token).await?;
        append_event(&transaction, &stored.task, event, now).await?;
        transaction.commit().await?;
        Ok(stored.task)
    }

    fn client_exists(&self, target_client_id: Uuid) -> Result<bool, UpdateTaskError> {
        self.database
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM clients WHERE client_id = ?1)",
                        [target_client_id.to_string()],
                        |row| row.get(0),
                    )
                    .map_err(Into::into)
            })
            .map_err(UpdateTaskError::Storage)
    }

    async fn assert_leader(&self, transaction: &PostgresTransaction<'_>) -> anyhow::Result<()> {
        let fencing_token = self
            .runtime
            .fencing_token()
            .map_err(|_| domain_error(UpdateTaskError::NotLeader))?;
        match self
            .runtime
            .coordinator()
            .assert_postgres_transaction_fence(transaction, fencing_token)
            .await
        {
            Ok(()) => Ok(()),
            Err(_) if !self.runtime.is_leader() => Err(domain_error(UpdateTaskError::NotLeader)),
            Err(error) => Err(error),
        }
    }
}

impl UpdateTaskCoordinationStorage for PostgresUpdateTaskCatalog {
    fn is_maintenance_leader(&self) -> bool {
        self.runtime.is_leader()
    }

    fn create<'a>(
        &'a self,
        request: &'a CreateRemoteUpdateTaskRequest,
        requested_by: &'a str,
        _now: u64,
    ) -> UpdateTaskFuture<'a, RemoteUpdateTask> {
        Box::pin(async move { map_database_result(self.create_inner(request, requested_by).await) })
    }

    fn list<'a>(
        &'a self,
        target_client_id: Option<Uuid>,
        requested_limit: usize,
        _now: u64,
    ) -> UpdateTaskFuture<'a, Vec<RemoteUpdateTask>> {
        Box::pin(async move {
            map_database_result(self.list_inner(target_client_id, requested_limit).await)
        })
    }

    fn detail(&self, task_id: Uuid, _now: u64) -> UpdateTaskFuture<'_, RemoteUpdateTaskDetail> {
        Box::pin(async move { map_database_result(self.detail_inner(task_id).await) })
    }

    fn reconcile_after_restart(&self, _now: u64) -> UpdateTaskFuture<'_, ()> {
        Box::pin(async move { map_database_result(self.reconcile_after_restart_inner().await) })
    }

    fn sweep(&self, _now: u64) -> UpdateTaskFuture<'_, ()> {
        Box::pin(async move { map_database_result(self.sweep_inner().await) })
    }

    fn claim<'a>(
        &'a self,
        target_client_id: Uuid,
        request: &'a RemoteUpdateClaimRequest,
        _now: u64,
    ) -> UpdateTaskFuture<'a, Option<RemoteUpdateClaim>> {
        Box::pin(
            async move { map_database_result(self.claim_inner(target_client_id, request).await) },
        )
    }

    fn renew<'a>(
        &'a self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &'a RemoteUpdateLeaseRenewRequest,
        _now: u64,
    ) -> UpdateTaskFuture<'a, RemoteUpdateLeaseRenewResponse> {
        Box::pin(async move {
            map_database_result(self.renew_inner(target_client_id, task_id, request).await)
        })
    }

    fn reconcile<'a>(
        &'a self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &'a RemoteUpdateReconcileRequest,
        _now: u64,
    ) -> UpdateTaskFuture<'a, RemoteUpdateReconcileResponse> {
        Box::pin(async move {
            map_database_result(
                self.reconcile_inner(target_client_id, task_id, request)
                    .await,
            )
        })
    }

    fn report<'a>(
        &'a self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &'a RemoteUpdateReportRequest,
        _now: u64,
    ) -> UpdateTaskFuture<'a, RemoteUpdateTask> {
        Box::pin(async move {
            map_database_result(self.report_inner(target_client_id, task_id, request).await)
        })
    }

    fn cancel<'a>(
        &'a self,
        task_id: Uuid,
        request: &'a CancelRemoteUpdateTaskRequest,
        _now: u64,
    ) -> UpdateTaskFuture<'a, RemoteUpdateTask> {
        Box::pin(async move { map_database_result(self.cancel_inner(task_id, request).await) })
    }
}

async fn lock_target(
    transaction: &PostgresTransaction<'_>,
    target_client_id: Uuid,
) -> anyhow::Result<()> {
    lock_text(
        transaction,
        TARGET_LOCK_NAMESPACE,
        &target_client_id.to_string(),
    )
    .await
}

async fn lock_text(
    transaction: &PostgresTransaction<'_>,
    namespace: i32,
    value: &str,
) -> anyhow::Result<()> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock($1, hashtext($2))",
            &[&namespace, &value],
        )
        .await?;
    Ok(())
}

async fn postgres_now(transaction: &PostgresTransaction<'_>) -> anyhow::Result<u64> {
    let value: i64 = transaction
        .query_one(
            "SELECT CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS BIGINT)",
            &[],
        )
        .await?
        .get(0);
    u64::try_from(value).map_err(Into::into)
}

async fn task_by_id(
    transaction: &PostgresTransaction<'_>,
    task_id: Uuid,
    for_update: bool,
) -> anyhow::Result<Option<StoredTask>> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    transaction
        .query_opt(
            &format!(
                "SELECT snapshot_json, lease_token_sha256, request_fingerprint,
                        terminal_worker_instance_id, terminal_lease_token_sha256,
                        terminal_report_sha256
                 FROM linklake_update_tasks WHERE task_id = $1{suffix}"
            ),
            &[&task_id.to_string()],
        )
        .await?
        .as_ref()
        .map(stored_task)
        .transpose()
}

async fn task_by_idempotency(
    transaction: &PostgresTransaction<'_>,
    requested_by: &str,
    idempotency_key: &str,
    for_update: bool,
) -> anyhow::Result<Option<StoredTask>> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    transaction
        .query_opt(
            &format!(
                "SELECT snapshot_json, lease_token_sha256, request_fingerprint,
                        terminal_worker_instance_id, terminal_lease_token_sha256,
                        terminal_report_sha256
                 FROM linklake_update_tasks
                 WHERE requested_by = $1 AND idempotency_key = $2{suffix}"
            ),
            &[&requested_by, &idempotency_key],
        )
        .await?
        .as_ref()
        .map(stored_task)
        .transpose()
}

fn stored_task(row: &Row) -> anyhow::Result<StoredTask> {
    let terminal_worker: Option<String> = row.get(3);
    let terminal_lease_token_sha256: Option<String> = row.get(4);
    let terminal_report_sha256: Option<String> = row.get(5);
    let terminal_replay = match (
        terminal_worker,
        terminal_lease_token_sha256,
        terminal_report_sha256,
    ) {
        (None, None, None) => None,
        (Some(worker), Some(lease_token_sha256), Some(report_sha256)) => {
            let worker_instance_id = Uuid::parse_str(&worker)?;
            anyhow::ensure!(
                !worker_instance_id.is_nil(),
                "PostgreSQL terminal replay worker identity is nil"
            );
            Some(TerminalReportReplay {
                worker_instance_id,
                lease_token_sha256,
                report_sha256,
            })
        }
        _ => anyhow::bail!("PostgreSQL terminal replay proof is incomplete"),
    };
    Ok(StoredTask {
        task: task_snapshot(row)?,
        lease_token_sha256: row.get(1),
        request_fingerprint: row.get(2),
        terminal_replay,
    })
}

fn task_snapshot(row: &Row) -> anyhow::Result<RemoteUpdateTask> {
    let snapshot: String = row.get(0);
    let task: RemoteUpdateTask = serde_json::from_str(&snapshot)?;
    validate_loaded_task(&task).map_err(anyhow::Error::msg)?;
    Ok(task)
}

fn event_snapshot(row: &Row) -> anyhow::Result<RemoteUpdateTaskEvent> {
    let snapshot: String = row.get(0);
    let event: RemoteUpdateTaskEvent = serde_json::from_str(&snapshot)?;
    event
        .validate(event.task_id)
        .map_err(|error| anyhow::anyhow!("invalid PostgreSQL update task event: {error}"))?;
    Ok(event)
}

async fn insert_task(
    transaction: &PostgresTransaction<'_>,
    task: &RemoteUpdateTask,
    fingerprint: &str,
) -> anyhow::Result<()> {
    task.validate()?;
    let snapshot = serde_json::to_string(task)?;
    let state = enum_text(task.state)?;
    let created = now_i64(task.created_unix_seconds)?;
    let affected = transaction
        .execute(
            "INSERT INTO linklake_update_tasks(
                task_id, target_client_id, requested_by, idempotency_key,
                request_fingerprint, state, created_unix_seconds,
                lease_deadline_unix_seconds, lease_token_sha256, snapshot_json
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, $8)",
            &[
                &task.task_id.to_string(),
                &task.target_client_id.to_string(),
                &task.requested_by,
                &task.idempotency_key,
                &fingerprint,
                &state,
                &created,
                &snapshot,
            ],
        )
        .await?;
    anyhow::ensure!(
        affected == 1,
        "PostgreSQL update task insert changed no row"
    );
    Ok(())
}

async fn write_task(
    transaction: &PostgresTransaction<'_>,
    task: &RemoteUpdateTask,
    token: TokenUpdate<'_>,
) -> anyhow::Result<()> {
    task.validate()?;
    let snapshot = serde_json::to_string(task)?;
    let state = enum_text(task.state)?;
    let deadline = task.lease_deadline_unix_seconds.map(now_i64).transpose()?;
    let task_id = task.task_id.to_string();
    let affected = match token {
        TokenUpdate::Preserve => {
            transaction
                .execute(
                    "UPDATE linklake_update_tasks
                     SET state = $2, lease_deadline_unix_seconds = $3, snapshot_json = $4
                     WHERE task_id = $1",
                    &[&task_id, &state, &deadline, &snapshot],
                )
                .await?
        }
        TokenUpdate::Set(token) => {
            transaction
                .execute(
                    "UPDATE linklake_update_tasks
                     SET state = $2, lease_deadline_unix_seconds = $3,
                         lease_token_sha256 = $4, snapshot_json = $5
                     WHERE task_id = $1",
                    &[&task_id, &state, &deadline, &token, &snapshot],
                )
                .await?
        }
        TokenUpdate::Clear => {
            transaction
                .execute(
                    "UPDATE linklake_update_tasks
                     SET state = $2, lease_deadline_unix_seconds = $3,
                         lease_token_sha256 = NULL, snapshot_json = $4
                     WHERE task_id = $1",
                    &[&task_id, &state, &deadline, &snapshot],
                )
                .await?
        }
        TokenUpdate::Terminal(replay) => {
            transaction
                .execute(
                    "UPDATE linklake_update_tasks
                     SET state = $2, lease_deadline_unix_seconds = $3,
                         lease_token_sha256 = NULL,
                         terminal_worker_instance_id = $4,
                         terminal_lease_token_sha256 = $5,
                         terminal_report_sha256 = $6,
                         snapshot_json = $7
                     WHERE task_id = $1",
                    &[
                        &task_id,
                        &state,
                        &deadline,
                        &replay.worker_instance_id.to_string(),
                        &replay.lease_token_sha256,
                        &replay.report_sha256,
                        &snapshot,
                    ],
                )
                .await?
        }
    };
    anyhow::ensure!(
        affected == 1,
        "PostgreSQL update task transition changed no row"
    );
    Ok(())
}

async fn append_event(
    transaction: &PostgresTransaction<'_>,
    task: &RemoteUpdateTask,
    kind: RemoteUpdateEventKind,
    now: u64,
) -> anyhow::Result<()> {
    let kind_text = enum_text(kind)?;
    let sampled_limit = match kind {
        RemoteUpdateEventKind::LeaseRenewed => Some(MAX_LEASE_EVENTS_PER_TASK),
        RemoteUpdateEventKind::IdempotentReplay => Some(MAX_REPLAY_EVENTS_PER_TASK),
        RemoteUpdateEventKind::RestartReconciled => Some(MAX_RESTART_EVENTS_PER_TASK),
        _ => None,
    };
    if let Some(limit) = sampled_limit {
        let recorded: i64 = transaction
            .query_one(
                "SELECT COUNT(*) FROM linklake_update_task_events
                 WHERE task_id = $1 AND kind = $2",
                &[&task.task_id.to_string(), &kind_text],
            )
            .await?
            .get(0);
        if recorded >= limit {
            return Ok(());
        }
    }
    let total: i64 = transaction
        .query_one(
            "SELECT COUNT(*) FROM linklake_update_task_events WHERE task_id = $1",
            &[&task.task_id.to_string()],
        )
        .await?
        .get(0);
    if total >= MAX_EVENTS_PER_TASK {
        return Err(domain_error(UpdateTaskError::CapacityExceeded));
    }
    let sequence: i64 = transaction
        .query_one(
            "SELECT COALESCE(MAX(sequence), 0) + 1
             FROM linklake_update_task_events WHERE task_id = $1",
            &[&task.task_id.to_string()],
        )
        .await?
        .get(0);
    let event = RemoteUpdateTaskEvent {
        schema_version: REMOTE_UPDATE_CONTRACT_VERSION,
        event_id: Uuid::new_v4(),
        task_id: task.task_id,
        sequence: u64::try_from(sequence)?,
        kind,
        state: task.state,
        stage: task.stage,
        recovery_state: task.recovery_state,
        error_code: task.error_code,
        created_unix_seconds: now,
    };
    event.validate(task.task_id)?;
    let event_json = serde_json::to_string(&event)?;
    let affected = transaction
        .execute(
            "INSERT INTO linklake_update_task_events(
                event_id, task_id, sequence, kind, created_unix_seconds, event_json
             ) VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &event.event_id.to_string(),
                &task.task_id.to_string(),
                &sequence,
                &kind_text,
                &now_i64(now)?,
                &event_json,
            ],
        )
        .await?;
    anyhow::ensure!(
        affected == 1,
        "PostgreSQL update task event insert changed no row"
    );
    Ok(())
}

async fn reconcile_expired(
    transaction: &PostgresTransaction<'_>,
    target_client_id: Option<Uuid>,
    now: u64,
) -> anyhow::Result<()> {
    let now = now_i64(now)?;
    let rows = match target_client_id {
        Some(target) => {
            transaction
                .query(
                    "SELECT snapshot_json FROM linklake_update_tasks
                     WHERE target_client_id = $1
                       AND state IN ('claimed', 'running', 'cancel_requested')
                       AND (lease_deadline_unix_seconds IS NULL
                            OR lease_deadline_unix_seconds <= $2)
                     ORDER BY lease_deadline_unix_seconds, task_id FOR UPDATE",
                    &[&target.to_string(), &now],
                )
                .await?
        }
        None => {
            transaction
                .query(
                    "SELECT snapshot_json FROM linklake_update_tasks
                     WHERE state IN ('claimed', 'running', 'cancel_requested')
                       AND (lease_deadline_unix_seconds IS NULL
                            OR lease_deadline_unix_seconds <= $1)
                     ORDER BY lease_deadline_unix_seconds, task_id FOR UPDATE",
                    &[&now],
                )
                .await?
        }
    };
    let now = u64::try_from(now)?;
    for row in rows {
        let mut task = task_snapshot(&row)?;
        let event = apply_lost_lease(&mut task, now);
        write_task(transaction, &task, TokenUpdate::Clear).await?;
        append_event(transaction, &task, event, now).await?;
    }
    Ok(())
}
