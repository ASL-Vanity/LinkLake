//! 单机 SQLite 维护协议不能覆盖 PostgreSQL 集群；标记防止脱离服务环境的 helper 误判。
use std::{fs::OpenOptions, io::Write, path::Path};

pub(crate) const POSTGRES_STORAGE_MARKER: &str = "postgres-storage.marker";

pub(crate) fn mark_postgres_data_directory(data_dir: &Path) -> anyhow::Result<()> {
    let path = data_dir.join(POSTGRES_STORAGE_MARKER);
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(
                b"LinkLake PostgreSQL data directory; local SQLite is not a cluster backup.\n",
            )?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::ensure!(path.is_file(), "invalid PostgreSQL storage marker");
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(crate) fn ensure_sqlite_maintenance(data_dir: &Path) -> anyhow::Result<()> {
    let backend = std::env::var("LINKLAKE_STORAGE_BACKEND").unwrap_or_else(|_| "sqlite".into());
    let backend = backend.trim().to_ascii_lowercase();
    anyhow::ensure!(
        matches!(backend.as_str(), "" | "sqlite")
            && !data_dir.join(POSTGRES_STORAGE_MARKER).try_exists()?,
        "this maintenance command supports standalone SQLite only; PostgreSQL deployments require a cluster database backup and a schema-compatible cluster upgrade or recovery (see docs/postgres-upgrades.md)"
    );
    anyhow::ensure!(
        std::env::var_os("LINKLAKE_POSTGRES_URL").is_none(),
        "PostgreSQL connection configuration is present; refusing standalone SQLite maintenance"
    );
    Ok(())
}
