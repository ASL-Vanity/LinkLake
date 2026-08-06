//! TCP/UDP 公网监听端口的跨实例所有权租约。

use crate::{ha_coordination::HaCoordinator, storage::CoordinationStorage};
use rusqlite::{params, OptionalExtension, Transaction as SqliteTransaction};
use serde::Serialize;
use std::{fmt, str::FromStr, time::Duration};
use tokio_postgres::Transaction as PostgresTransaction;
use uuid::Uuid;

const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS public_port_ownership (
    protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
    public_port INTEGER NOT NULL CHECK(public_port BETWEEN 1 AND 65535),
    lease_id TEXT NOT NULL,
    owner_instance_id TEXT NOT NULL,
    owner_incarnation_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    policy_id TEXT NOT NULL,
    acquired_unix_seconds INTEGER NOT NULL,
    renewed_unix_seconds INTEGER NOT NULL,
    lease_until_unix_seconds INTEGER NOT NULL,
    PRIMARY KEY(protocol, public_port)
);
CREATE INDEX IF NOT EXISTS public_port_ownership_owner
    ON public_port_ownership(owner_instance_id, lease_until_unix_seconds);
"#;

const POSTGRES_PORT_LOCK_NAMESPACE: i64 = 0x4c4c_5054_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PublicPortProtocol {
    Tcp,
    Udp,
}

impl PublicPortProtocol {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    fn lock_discriminator(self) -> i64 {
        match self {
            Self::Tcp => 0,
            Self::Udp => 1,
        }
    }
}

impl fmt::Display for PublicPortProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PublicPortProtocol {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => anyhow::bail!("unsupported public port protocol"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PublicPortLease {
    pub(crate) protocol: PublicPortProtocol,
    pub(crate) public_port: u16,
    pub(crate) lease_id: Uuid,
    pub(crate) owner_instance_id: String,
    pub(crate) owner_incarnation_id: String,
    pub(crate) fencing_token: u64,
    pub(crate) policy_id: Uuid,
    pub(crate) acquired_unix_seconds: u64,
    pub(crate) renewed_unix_seconds: u64,
    pub(crate) lease_until_unix_seconds: u64,
}

#[derive(Clone)]
pub(crate) struct PublicPortOwnership {
    coordinator: HaCoordinator,
    lease_seconds: u64,
}

impl PublicPortOwnership {
    pub(crate) fn open(coordinator: HaCoordinator, lease: Duration) -> anyhow::Result<Self> {
        let lease_seconds = lease_seconds(lease)?;
        if let CoordinationStorage::Sqlite(database) = coordinator.storage() {
            database.with_transaction(ensure_sqlite_schema)?;
        }
        Ok(Self {
            coordinator,
            lease_seconds,
        })
    }

    pub(crate) async fn acquire(
        &self,
        protocol: PublicPortProtocol,
        public_port: u16,
        policy_id: Uuid,
        fencing_token: u64,
    ) -> anyhow::Result<Option<PublicPortLease>> {
        validate_port_and_fence(public_port, fencing_token)?;
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                let now = sqlite_now(transaction)?;
                self.coordinator
                    .assert_sqlite_transaction_fence(transaction, fencing_token)?;
                let current = read_sqlite_lease(transaction, protocol, public_port)?;
                let mode = claim_mode(
                    current.as_ref(),
                    self.coordinator.instance_id(),
                    self.coordinator.incarnation_id(),
                    fencing_token,
                    now,
                )?;
                match mode {
                    ClaimMode::Conflict => Ok(None),
                    ClaimMode::Fresh => {
                        let lease_id = Uuid::new_v4();
                        let lease_until = now.saturating_add(self.lease_seconds);
                        let changed = transaction.execute(
                            "INSERT INTO public_port_ownership(
                                 protocol, public_port, lease_id, owner_instance_id,
                                 owner_incarnation_id, fencing_token, policy_id,
                                 acquired_unix_seconds, renewed_unix_seconds,
                                 lease_until_unix_seconds
                             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)
                             ON CONFLICT(protocol, public_port) DO UPDATE SET
                                 lease_id = excluded.lease_id,
                                 owner_instance_id = excluded.owner_instance_id,
                                 owner_incarnation_id = excluded.owner_incarnation_id,
                                 fencing_token = excluded.fencing_token,
                                 policy_id = excluded.policy_id,
                                 acquired_unix_seconds = excluded.acquired_unix_seconds,
                                 renewed_unix_seconds = excluded.renewed_unix_seconds,
                                 lease_until_unix_seconds = excluded.lease_until_unix_seconds",
                            params![
                                protocol.as_str(),
                                i64::from(public_port),
                                lease_id.to_string(),
                                self.coordinator.instance_id(),
                                self.coordinator.incarnation_id(),
                                as_i64(fencing_token)?,
                                policy_id.to_string(),
                                as_i64(now)?,
                                as_i64(lease_until)?,
                            ],
                        )?;
                        anyhow::ensure!(changed == 1, "public port acquisition changed no row");
                        read_sqlite_lease(transaction, protocol, public_port)?
                            .ok_or_else(|| {
                                anyhow::anyhow!("public port lease disappeared after acquisition")
                            })
                            .map(Some)
                    }
                }
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.coordinator.storage().postgres_client().await?;
                let transaction = client.transaction().await?;
                self.coordinator
                    .assert_postgres_transaction_fence(&transaction, fencing_token)
                    .await?;
                lock_postgres_port(&transaction, protocol, public_port).await?;
                let now = postgres_now(&transaction).await?;
                let current =
                    read_postgres_lease_for_update(&transaction, protocol, public_port).await?;
                let mode = claim_mode(
                    current.as_ref(),
                    self.coordinator.instance_id(),
                    self.coordinator.incarnation_id(),
                    fencing_token,
                    now,
                )?;
                let lease = match mode {
                    ClaimMode::Conflict => None,
                    ClaimMode::Fresh => {
                        let lease_id = Uuid::new_v4();
                        Some(
                            replace_postgres_lease(
                                &transaction,
                                protocol,
                                public_port,
                                lease_id,
                                self.coordinator.instance_id(),
                                self.coordinator.incarnation_id(),
                                fencing_token,
                                policy_id,
                                now,
                                now.saturating_add(self.lease_seconds),
                            )
                            .await?,
                        )
                    }
                };
                transaction.commit().await?;
                Ok(lease)
            }
        }
    }

    pub(crate) async fn renew(
        &self,
        protocol: PublicPortProtocol,
        public_port: u16,
        policy_id: Uuid,
        lease_id: Uuid,
        fencing_token: u64,
    ) -> anyhow::Result<Option<PublicPortLease>> {
        validate_port_and_fence(public_port, fencing_token)?;
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                self.coordinator
                    .assert_sqlite_transaction_fence(transaction, fencing_token)?;
                let now = sqlite_now(transaction)?;
                let lease_until = now.saturating_add(self.lease_seconds);
                let changed = transaction.execute(
                    "UPDATE public_port_ownership
                     SET renewed_unix_seconds = ?8, lease_until_unix_seconds = ?9
                     WHERE protocol = ?1 AND public_port = ?2 AND lease_id = ?3
                       AND owner_instance_id = ?4 AND owner_incarnation_id = ?5
                       AND fencing_token = ?6 AND policy_id = ?7
                       AND lease_until_unix_seconds > ?8",
                    params![
                        protocol.as_str(),
                        i64::from(public_port),
                        lease_id.to_string(),
                        self.coordinator.instance_id(),
                        self.coordinator.incarnation_id(),
                        as_i64(fencing_token)?,
                        policy_id.to_string(),
                        as_i64(now)?,
                        as_i64(lease_until)?,
                    ],
                )?;
                anyhow::ensure!(changed <= 1, "multiple public port leases were renewed");
                if changed == 0 {
                    return Ok(None);
                }
                read_sqlite_lease(transaction, protocol, public_port)?
                    .map(Some)
                    .ok_or_else(|| anyhow::anyhow!("public port lease disappeared after renewal"))
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.coordinator.storage().postgres_client().await?;
                let transaction = client.transaction().await?;
                self.coordinator
                    .assert_postgres_transaction_fence(&transaction, fencing_token)
                    .await?;
                lock_postgres_port(&transaction, protocol, public_port).await?;
                let now = postgres_now(&transaction).await?;
                let lease = renew_postgres_lease(
                    &transaction,
                    protocol,
                    public_port,
                    lease_id,
                    self.coordinator.instance_id(),
                    self.coordinator.incarnation_id(),
                    fencing_token,
                    policy_id,
                    now,
                    now.saturating_add(self.lease_seconds),
                )
                .await?;
                transaction.commit().await?;
                Ok(lease)
            }
        }
    }

    pub(crate) async fn release(
        &self,
        protocol: PublicPortProtocol,
        public_port: u16,
        policy_id: Uuid,
        lease_id: Uuid,
        fencing_token: u64,
    ) -> anyhow::Result<bool> {
        validate_port_and_fence(public_port, fencing_token)?;
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                self.coordinator
                    .assert_sqlite_transaction_fence(transaction, fencing_token)?;
                Ok(transaction.execute(
                    "DELETE FROM public_port_ownership
                     WHERE protocol = ?1 AND public_port = ?2 AND lease_id = ?3
                       AND owner_instance_id = ?4 AND owner_incarnation_id = ?5
                       AND fencing_token = ?6 AND policy_id = ?7",
                    params![
                        protocol.as_str(),
                        i64::from(public_port),
                        lease_id.to_string(),
                        self.coordinator.instance_id(),
                        self.coordinator.incarnation_id(),
                        as_i64(fencing_token)?,
                        policy_id.to_string(),
                    ],
                )? == 1)
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.coordinator.storage().postgres_client().await?;
                let transaction = client.transaction().await?;
                self.coordinator
                    .assert_postgres_transaction_fence(&transaction, fencing_token)
                    .await?;
                lock_postgres_port(&transaction, protocol, public_port).await?;
                let changed = transaction
                    .execute(
                        "DELETE FROM linklake_public_port_ownership
                         WHERE protocol = $1 AND public_port = $2 AND lease_id = $3
                           AND owner_instance_id = $4 AND owner_incarnation_id = $5
                           AND fencing_token = $6 AND policy_id = $7",
                        &[
                            &protocol.as_str(),
                            &i32::from(public_port),
                            &lease_id.to_string(),
                            &self.coordinator.instance_id(),
                            &self.coordinator.incarnation_id(),
                            &as_i64(fencing_token)?,
                            &policy_id.to_string(),
                        ],
                    )
                    .await?;
                transaction.commit().await?;
                Ok(changed == 1)
            }
        }
    }

    pub(crate) async fn active(&self) -> anyhow::Result<Vec<PublicPortLease>> {
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                let mut statement = connection.prepare(
                    "SELECT ownership.protocol, ownership.public_port, ownership.lease_id,
                            ownership.owner_instance_id, ownership.owner_incarnation_id,
                            ownership.fencing_token, ownership.policy_id,
                            ownership.acquired_unix_seconds, ownership.renewed_unix_seconds,
                            ownership.lease_until_unix_seconds
                     FROM public_port_ownership AS ownership
                     JOIN ha_leader AS leader
                       ON leader.instance_id = ownership.owner_instance_id
                      AND leader.incarnation_id = ownership.owner_incarnation_id
                      AND leader.fencing_token = ownership.fencing_token
                     JOIN ha_members AS member
                       ON member.instance_id = ownership.owner_instance_id
                      AND member.incarnation_id = ownership.owner_incarnation_id
                     WHERE ownership.lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)
                       AND leader.lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)
                       AND member.lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)
                     ORDER BY ownership.protocol, ownership.public_port",
                )?;
                let rows = statement.query_map([], sqlite_lease_row)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
            }),
            CoordinationStorage::Postgres(_) => {
                let client = self.coordinator.storage().postgres_client().await?;
                client
                    .query(
                        "SELECT ownership.protocol, ownership.public_port, ownership.lease_id,
                            ownership.owner_instance_id, ownership.owner_incarnation_id,
                            ownership.fencing_token, ownership.policy_id,
                            CAST(EXTRACT(EPOCH FROM ownership.acquired_at) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM ownership.renewed_at) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM ownership.lease_until) AS BIGINT)
                         FROM linklake_public_port_ownership AS ownership
                         JOIN linklake_ha_leader AS leader
                           ON leader.instance_id = ownership.owner_instance_id
                          AND leader.incarnation_id = ownership.owner_incarnation_id
                          AND leader.fencing_token = ownership.fencing_token
                         JOIN linklake_ha_members AS member
                           ON member.instance_id = ownership.owner_instance_id
                          AND member.incarnation_id = ownership.owner_incarnation_id
                         WHERE ownership.lease_until > clock_timestamp()
                           AND leader.lease_until > clock_timestamp()
                           AND member.lease_until > clock_timestamp()
                         ORDER BY ownership.protocol, ownership.public_port",
                        &[],
                    )
                    .await?
                    .iter()
                    .map(postgres_lease)
                    .collect()
            }
        }
    }

    pub(crate) async fn prune_expired(&self) -> anyhow::Result<u64> {
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                Ok(connection.execute(
                    "DELETE FROM public_port_ownership
                     WHERE lease_until_unix_seconds <= CAST(unixepoch('now') AS INTEGER)",
                    [],
                )? as u64)
            }),
            CoordinationStorage::Postgres(_) => {
                let client = self.coordinator.storage().postgres_client().await?;
                Ok(client
                    .execute(
                        "DELETE FROM linklake_public_port_ownership
                         WHERE lease_until <= clock_timestamp()",
                        &[],
                    )
                    .await?)
            }
        }
    }
}

fn ensure_sqlite_schema(transaction: &SqliteTransaction<'_>) -> anyhow::Result<()> {
    transaction.execute_batch(SQLITE_SCHEMA)?;
    if sqlite_column_is_required(transaction, "public_port_ownership", "lease_id")? {
        return Ok(());
    }

    // 旧开发构建可能已经创建过不含租约身份的表。DDL 与数据复制必须处于同一事务，
    // 新身份会主动使重启前遗留的 worker 失效，避免它们误操作升级后的租约。
    anyhow::ensure!(
        !sqlite_table_exists(transaction, "public_port_ownership_lease_upgrade")?,
        "unfinished public port lease schema upgrade was detected"
    );
    transaction.execute_batch(
        "ALTER TABLE public_port_ownership
             RENAME TO public_port_ownership_lease_upgrade;
         DROP INDEX IF EXISTS public_port_ownership_owner;",
    )?;
    transaction.execute_batch(SQLITE_SCHEMA)?;
    transaction.execute(
        "INSERT INTO public_port_ownership(
             protocol, public_port, lease_id, owner_instance_id, owner_incarnation_id,
             fencing_token, policy_id, acquired_unix_seconds, renewed_unix_seconds,
             lease_until_unix_seconds
         )
         SELECT protocol, public_port, lower(hex(randomblob(16))), owner_instance_id,
                owner_incarnation_id, fencing_token, policy_id, acquired_unix_seconds,
                renewed_unix_seconds, lease_until_unix_seconds
         FROM public_port_ownership_lease_upgrade",
        [],
    )?;
    transaction.execute_batch("DROP TABLE public_port_ownership_lease_upgrade;")?;
    Ok(())
}

fn sqlite_column_is_required(
    transaction: &SqliteTransaction<'_>,
    table: &str,
    column: &str,
) -> anyhow::Result<bool> {
    let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == column {
            return Ok(row.get::<_, i64>(3)? == 1);
        }
    }
    Ok(false)
}

fn sqlite_table_exists(transaction: &SqliteTransaction<'_>, table: &str) -> anyhow::Result<bool> {
    Ok(transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
         )",
        [table],
        |row| row.get(0),
    )?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimMode {
    Conflict,
    Fresh,
}

fn claim_mode(
    current: Option<&PublicPortLease>,
    owner_instance_id: &str,
    owner_incarnation_id: &str,
    fencing_token: u64,
    now: u64,
) -> anyhow::Result<ClaimMode> {
    let Some(current) = current else {
        return Ok(ClaimMode::Fresh);
    };
    if current.fencing_token > fencing_token {
        anyhow::bail!("public port ownership contains a newer fencing token");
    }
    if current.fencing_token < fencing_token {
        return Ok(ClaimMode::Fresh);
    }
    anyhow::ensure!(
        current.owner_instance_id == owner_instance_id
            && current.owner_incarnation_id == owner_incarnation_id,
        "public port ownership reuses one fencing token across different process sessions"
    );
    if current.lease_until_unix_seconds <= now {
        return Ok(ClaimMode::Fresh);
    }
    Ok(ClaimMode::Conflict)
}

fn read_sqlite_lease(
    transaction: &SqliteTransaction<'_>,
    protocol: PublicPortProtocol,
    public_port: u16,
) -> anyhow::Result<Option<PublicPortLease>> {
    transaction
        .query_row(
            "SELECT protocol, public_port, lease_id, owner_instance_id, owner_incarnation_id,
                    fencing_token, policy_id,
                    acquired_unix_seconds, renewed_unix_seconds, lease_until_unix_seconds
             FROM public_port_ownership WHERE protocol = ?1 AND public_port = ?2",
            params![protocol.as_str(), i64::from(public_port)],
            sqlite_lease_row,
        )
        .optional()
        .map_err(Into::into)
}

fn sqlite_lease_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PublicPortLease> {
    let protocol = row.get::<_, String>(0)?.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let public_port = u16::try_from(row.get::<_, i64>(1)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    if public_port == 0 {
        return Err(rusqlite::Error::IntegralValueOutOfRange(1, 0));
    }
    let lease_id = Uuid::parse_str(&row.get::<_, String>(2)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let policy_id = Uuid::parse_str(&row.get::<_, String>(6)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(PublicPortLease {
        protocol,
        public_port,
        lease_id,
        owner_instance_id: row.get(3)?,
        owner_incarnation_id: row.get(4)?,
        fencing_token: positive(row.get(5)?, "public port fencing token").map_err(sqlite_error)?,
        policy_id,
        acquired_unix_seconds: nonnegative(row.get(7)?, "public port acquired time")
            .map_err(sqlite_error)?,
        renewed_unix_seconds: nonnegative(row.get(8)?, "public port renewed time")
            .map_err(sqlite_error)?,
        lease_until_unix_seconds: nonnegative(row.get(9)?, "public port lease time")
            .map_err(sqlite_error)?,
    })
}

async fn read_postgres_lease_for_update(
    transaction: &PostgresTransaction<'_>,
    protocol: PublicPortProtocol,
    public_port: u16,
) -> anyhow::Result<Option<PublicPortLease>> {
    transaction
        .query_opt(
            "SELECT protocol, public_port, lease_id, owner_instance_id, owner_incarnation_id,
                fencing_token, policy_id,
                CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT)
             FROM linklake_public_port_ownership
             WHERE protocol = $1 AND public_port = $2 FOR UPDATE",
            &[&protocol.as_str(), &i32::from(public_port)],
        )
        .await?
        .map(|row| postgres_lease(&row))
        .transpose()
}

async fn renew_postgres_lease(
    transaction: &PostgresTransaction<'_>,
    protocol: PublicPortProtocol,
    public_port: u16,
    lease_id: Uuid,
    owner_instance_id: &str,
    owner_incarnation_id: &str,
    fencing_token: u64,
    policy_id: Uuid,
    now: u64,
    lease_until: u64,
) -> anyhow::Result<Option<PublicPortLease>> {
    transaction
        .query_opt(
            "UPDATE linklake_public_port_ownership
             SET renewed_at = to_timestamp($8), lease_until = to_timestamp($9)
             WHERE protocol = $1 AND public_port = $2 AND lease_id = $3
               AND owner_instance_id = $4 AND owner_incarnation_id = $5
               AND fencing_token = $6 AND policy_id = $7
               AND lease_until > to_timestamp($8)
             RETURNING protocol, public_port, lease_id, owner_instance_id,
                 owner_incarnation_id, fencing_token, policy_id,
                 CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                 CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                 CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT)",
            &[
                &protocol.as_str(),
                &i32::from(public_port),
                &lease_id.to_string(),
                &owner_instance_id,
                &owner_incarnation_id,
                &as_i64(fencing_token)?,
                &policy_id.to_string(),
                &as_i64(now)?,
                &as_i64(lease_until)?,
            ],
        )
        .await?
        .map(|row| postgres_lease(&row))
        .transpose()
}

async fn replace_postgres_lease(
    transaction: &PostgresTransaction<'_>,
    protocol: PublicPortProtocol,
    public_port: u16,
    lease_id: Uuid,
    owner_instance_id: &str,
    owner_incarnation_id: &str,
    fencing_token: u64,
    policy_id: Uuid,
    now: u64,
    lease_until: u64,
) -> anyhow::Result<PublicPortLease> {
    let row = transaction
        .query_one(
            "INSERT INTO linklake_public_port_ownership(
                 protocol, public_port, lease_id, owner_instance_id, owner_incarnation_id,
                 fencing_token, policy_id,
                 acquired_at, renewed_at, lease_until
             ) VALUES ($1, $2, $3, $4, $5, $6, $7,
                 to_timestamp($8), to_timestamp($8), to_timestamp($9))
             ON CONFLICT(protocol, public_port) DO UPDATE SET
                 lease_id = EXCLUDED.lease_id,
                 owner_instance_id = EXCLUDED.owner_instance_id,
                 owner_incarnation_id = EXCLUDED.owner_incarnation_id,
                 fencing_token = EXCLUDED.fencing_token,
                 policy_id = EXCLUDED.policy_id,
                 acquired_at = EXCLUDED.acquired_at,
                 renewed_at = EXCLUDED.renewed_at,
                 lease_until = EXCLUDED.lease_until
             RETURNING protocol, public_port, lease_id, owner_instance_id,
                 owner_incarnation_id, fencing_token, policy_id,
                 CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                 CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                 CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT)",
            &[
                &protocol.as_str(),
                &i32::from(public_port),
                &lease_id.to_string(),
                &owner_instance_id,
                &owner_incarnation_id,
                &as_i64(fencing_token)?,
                &policy_id.to_string(),
                &as_i64(now)?,
                &as_i64(lease_until)?,
            ],
        )
        .await?;
    postgres_lease(&row)
}

fn postgres_lease(row: &tokio_postgres::Row) -> anyhow::Result<PublicPortLease> {
    let public_port = u16::try_from(row.get::<_, i32>(1))
        .map_err(|_| anyhow::anyhow!("public port is outside the supported range"))?;
    anyhow::ensure!(public_port > 0, "public port must be positive");
    Ok(PublicPortLease {
        protocol: row.get::<_, String>(0).parse()?,
        public_port,
        lease_id: Uuid::parse_str(&row.get::<_, String>(2))?,
        owner_instance_id: row.get(3),
        owner_incarnation_id: row.get(4),
        fencing_token: positive(row.get(5), "public port fencing token")?,
        policy_id: Uuid::parse_str(&row.get::<_, String>(6))?,
        acquired_unix_seconds: nonnegative(row.get(7), "public port acquired time")?,
        renewed_unix_seconds: nonnegative(row.get(8), "public port renewed time")?,
        lease_until_unix_seconds: nonnegative(row.get(9), "public port lease time")?,
    })
}

async fn lock_postgres_port(
    transaction: &PostgresTransaction<'_>,
    protocol: PublicPortProtocol,
    public_port: u16,
) -> anyhow::Result<()> {
    let lock_id = POSTGRES_PORT_LOCK_NAMESPACE
        .saturating_add(protocol.lock_discriminator() << 16)
        .saturating_add(i64::from(public_port));
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_id])
        .await?;
    Ok(())
}

fn sqlite_now(transaction: &SqliteTransaction<'_>) -> anyhow::Result<u64> {
    let value: i64 =
        transaction.query_row("SELECT CAST(unixepoch('now') AS INTEGER)", [], |row| {
            row.get(0)
        })?;
    nonnegative(value, "SQLite clock")
}

async fn postgres_now(transaction: &PostgresTransaction<'_>) -> anyhow::Result<u64> {
    let value: i64 = transaction
        .query_one(
            "SELECT CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS BIGINT)",
            &[],
        )
        .await?
        .get(0);
    nonnegative(value, "PostgreSQL clock")
}

fn validate_port_and_fence(public_port: u16, fencing_token: u64) -> anyhow::Result<()> {
    anyhow::ensure!(public_port > 0, "public port must be between 1 and 65535");
    anyhow::ensure!(fencing_token > 0, "fencing token must be positive");
    Ok(())
}

fn lease_seconds(duration: Duration) -> anyhow::Result<u64> {
    let seconds = duration.as_secs();
    anyhow::ensure!(
        seconds >= 2,
        "public port lease must be at least two seconds"
    );
    anyhow::ensure!(
        seconds <= 5 * 60,
        "public port lease must not exceed 300 seconds"
    );
    Ok(seconds)
}

fn as_i64(value: u64) -> anyhow::Result<i64> {
    i64::try_from(value).map_err(|_| anyhow::anyhow!("value exceeds database integer range"))
}

fn positive(value: i64, label: &str) -> anyhow::Result<u64> {
    anyhow::ensure!(value > 0, "{label} must be positive");
    Ok(value as u64)
}

fn nonnegative(value: i64, label: &str) -> anyhow::Result<u64> {
    anyhow::ensure!(value >= 0, "{label} must not be negative");
    Ok(value as u64)
}

fn sqlite_error(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Integer,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}
