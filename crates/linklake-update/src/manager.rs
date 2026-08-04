use super::*;

const MANAGER_SCHEMA_VERSION: u32 = 2;
const MAX_MANAGER_EXTRACTED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MANAGER_ENTRIES: usize = 20_000;
const MANAGER_EXIT_TIMEOUT_SECONDS: u64 = 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerStagedUpdate {
    pub schema_version: u32,
    pub current_version: String,
    pub version: String,
    pub target: String,
    pub archive_name: String,
    pub archive_sha256: String,
    pub signature_key_id: String,
    pub staged_directory: PathBuf,
    pub staged_manifest: PathBuf,
    pub payload_sha256: String,
    pub downloaded_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ManagerSchedule {
    pub schema_version: u32,
    pub state: String,
    pub operation: String,
    pub from_version: String,
    pub to_version: String,
    pub status_file: PathBuf,
    pub helper_process_id: u32,
    pub requires_manager_exit: bool,
    pub manager_process_id: u32,
    pub manager_process_identity: String,
    pub exit_timeout_seconds: u64,
    pub exit_deadline_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerStatus {
    pub schema_version: u32,
    pub state: String,
    pub operation: Option<String>,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub message: String,
    pub error: Option<String>,
    pub backup: Option<PathBuf>,
    pub requires_manager_exit: bool,
    pub manager_process_id: Option<u32>,
    pub manager_process_identity: Option<String>,
    pub exit_deadline_unix_seconds: Option<u64>,
    pub updated_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ManagerOperation {
    Apply,
    Rollback,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ManagerPlan {
    schema_version: u32,
    operation: ManagerOperation,
    state_directory: PathBuf,
    target_directory: PathBuf,
    staged_directory: PathBuf,
    expected_target_tree_sha256: String,
    staged_tree_sha256: String,
    from_version: String,
    to_version: String,
    manager_process_id: u32,
    manager_process_identity: String,
    manager_exit_timeout_seconds: u64,
    created_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ManagerBackup {
    schema_version: u32,
    version: String,
    directory: PathBuf,
    tree_sha256: String,
    created_unix_seconds: u64,
}

pub async fn manager_download(
    repository: &str,
    requested_channel: UpdateChannel,
    current_version: &Version,
    state_directory: &Path,
    signature_policy: SignaturePolicy,
) -> anyhow::Result<ManagerStagedUpdate> {
    let releases = fetch_releases(repository).await?;
    let selected = select_release(
        UpdateProduct::Manager,
        &releases,
        requested_channel,
        current_version,
    )?;
    anyhow::ensure!(
        selected.version > *current_version,
        "Manager network updates must be newer than the installed version"
    );
    let state = prepare_state_directory(state_directory)?;
    let downloads = state.join("downloads").join(selected.version.to_string());
    fs::create_dir_all(&downloads)?;
    secure_directory(&downloads)?;
    let client = update_http_client()?;
    let (signed_bytes, signed_manifest) = fetch_and_verify_signed_manifest(
        repository,
        &selected,
        UpdateProduct::Manager,
        signature_policy,
    )
    .await?;
    let checksum_bytes =
        download_asset(&client, repository, selected.checksum, MAX_CHECKSUM_BYTES).await?;
    let package_bytes =
        download_asset(&client, repository, selected.package, MAX_ARCHIVE_BYTES).await?;
    let signed_asset = matching_signed_asset(
        &signed_manifest,
        UpdateProduct::Manager,
        &selected.version,
        platform_target()?,
        &selected.package.name,
    )?;
    let package_hash = verify_downloaded_package(
        &package_bytes,
        &checksum_bytes,
        &selected.package.name,
        &required_github_digest(selected.package)?,
        signed_asset,
    )?;
    let package_path = downloads.join(&selected.package.name);
    write_download_atomically(&package_path, &package_bytes)?;
    write_download_atomically(&downloads.join(&selected.checksum.name), &checksum_bytes)?;
    write_download_atomically(&downloads.join(SIGNED_MANIFEST_NAME), &signed_bytes)?;

    let staged = extract_manager_package(
        &state,
        &package_path,
        &package_bytes,
        current_version,
        &selected.version,
        package_hash,
        signed_manifest.key_id,
    )?;
    write_json_atomically(
        &state
            .join("staging")
            .join(&staged.version)
            .join("manager-staged.json"),
        &staged,
    )?;
    Ok(staged)
}

pub fn manager_apply(
    state_directory: &Path,
    install_directory: &Path,
    manager_process_id: u32,
    confirmed: bool,
) -> anyhow::Result<ManagerSchedule> {
    anyhow::ensure!(confirmed, "pass --yes to confirm Manager installation");
    let state = prepare_state_directory(state_directory)?;
    let staged = latest_manager_staged(&state)?;
    anyhow::ensure!(
        directory_tree_sha256(&staged.staged_directory)? == staged.payload_sha256,
        "staged Manager payload changed after download"
    );
    schedule_manager(
        &state,
        install_directory,
        &staged.staged_directory,
        &staged.current_version,
        &staged.version,
        manager_process_id,
        ManagerOperation::Apply,
    )
}

pub fn manager_rollback(
    state_directory: &Path,
    install_directory: &Path,
    manager_process_id: u32,
    confirmed: bool,
) -> anyhow::Result<ManagerSchedule> {
    anyhow::ensure!(confirmed, "pass --yes to confirm Manager rollback");
    let state = prepare_state_directory(state_directory)?;
    let backup: ManagerBackup =
        read_json_limited(&state.join("manager-backup.json"), MAX_MANIFEST_BYTES)?;
    anyhow::ensure!(
        backup.schema_version == MANAGER_SCHEMA_VERSION,
        "invalid Manager backup"
    );
    anyhow::ensure!(
        backup.directory.is_dir(),
        "Manager rollback directory is missing"
    );
    anyhow::ensure!(
        directory_tree_sha256(&backup.directory)? == backup.tree_sha256,
        "Manager rollback payload changed"
    );
    let current = read_manager_release(&absolute_path(install_directory)?)?;
    schedule_manager(
        &state,
        install_directory,
        &backup.directory,
        &current.version,
        &backup.version,
        manager_process_id,
        ManagerOperation::Rollback,
    )
}

pub fn manager_status(state_directory: &Path) -> anyhow::Result<ManagerStatus> {
    let path = absolute_path(state_directory)?.join("manager-status.json");
    if path.is_file() {
        return read_json_limited(&path, MAX_MANIFEST_BYTES);
    }
    Ok(ManagerStatus {
        schema_version: MANAGER_SCHEMA_VERSION,
        state: "idle".to_owned(),
        operation: None,
        from_version: None,
        to_version: None,
        message: "no Manager update operation has been scheduled".to_owned(),
        error: None,
        backup: None,
        requires_manager_exit: false,
        manager_process_id: None,
        manager_process_identity: None,
        exit_deadline_unix_seconds: None,
        updated_unix_seconds: unix_seconds(),
    })
}

pub fn run_manager_helper(plan_path: &Path, expected_sha256: &str) -> anyhow::Result<()> {
    let bytes = fs::read(plan_path)?;
    anyhow::ensure!(
        sha256_bytes(&bytes) == normalize_sha256(expected_sha256)?,
        "Manager helper plan digest mismatch"
    );
    let mut plan: ManagerPlan = serde_json::from_slice(&bytes)?;
    if let Err(error) = validate_manager_plan(plan_path, &mut plan) {
        write_manager_validation_failure(plan_path, &plan, &error);
        return Err(error);
    }
    let result = wait_for_manager_exit(&plan).and_then(|()| execute_manager_plan(&plan));
    if let Err(error) = &result {
        write_manager_failure_if_pending(&plan, error);
    }
    result
}

fn write_manager_validation_failure(plan_path: &Path, plan: &ManagerPlan, error: &anyhow::Error) {
    let Ok(state) = fs::canonicalize(&plan.state_directory) else {
        return;
    };
    if ensure_within(plan_path, &state).is_err() {
        return;
    }
    let mut trusted_plan = plan.clone();
    trusted_plan.state_directory = state;
    let _ = write_manager_status(
        &trusted_plan.state_directory,
        "failed",
        trusted_plan.operation,
        &trusted_plan,
        Some(error.to_string()),
        None,
    );
}

fn write_manager_failure_if_pending(plan: &ManagerPlan, error: &anyhow::Error) {
    let status = manager_status(&plan.state_directory).ok();
    if status
        .as_ref()
        .is_some_and(|value| matches!(value.state.as_str(), "failed" | "rolled_back" | "succeeded"))
    {
        return;
    }
    let _ = write_manager_status(
        &plan.state_directory,
        "failed",
        plan.operation,
        plan,
        Some(error.to_string()),
        None,
    );
}

fn extract_manager_package(
    state: &Path,
    package: &Path,
    package_bytes: &[u8],
    current_version: &Version,
    version: &Version,
    archive_sha256: String,
    signature_key_id: String,
) -> anyhow::Result<ManagerStagedUpdate> {
    let staging_root = state.join("staging");
    fs::create_dir_all(&staging_root)?;
    let temporary = staging_root.join(format!(
        ".manager-{}.partial-{}",
        version,
        Uuid::new_v4().simple()
    ));
    let payload = temporary.join("payload");
    fs::create_dir_all(&payload)?;
    if package.extension() == Some(OsStr::new("zip")) {
        extract_manager_zip(package_bytes, &payload)?;
    } else {
        extract_manager_tar(package_bytes, &payload)?;
    }
    let release = read_manager_release(&payload)?;
    anyhow::ensure!(
        release.version == version.to_string(),
        "Manager release version mismatch"
    );
    anyhow::ensure!(
        release.target == platform_target()?,
        "Manager release target mismatch"
    );
    validate_manager_payload(&payload)?;
    let final_directory = staging_root.join(version.to_string()).join("manager");
    if let Some(parent) = final_directory.parent() {
        fs::create_dir_all(parent)?;
    }
    if final_directory.exists() {
        fs::remove_dir_all(&final_directory)?;
    }
    fs::rename(&payload, &final_directory)?;
    let _ = fs::remove_dir_all(&temporary);
    let payload_sha256 = directory_tree_sha256(&final_directory)?;
    Ok(ManagerStagedUpdate {
        schema_version: MANAGER_SCHEMA_VERSION,
        current_version: current_version.to_string(),
        version: version.to_string(),
        target: platform_target()?.to_owned(),
        archive_name: package
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        archive_sha256,
        signature_key_id,
        staged_manifest: final_directory.join("release.json"),
        staged_directory: final_directory,
        payload_sha256,
        downloaded_unix_seconds: unix_seconds(),
    })
}

fn extract_manager_zip(package_bytes: &[u8], destination: &Path) -> anyhow::Result<()> {
    let mut archive = ZipArchive::new(Cursor::new(package_bytes))?;
    anyhow::ensure!(
        archive.len() <= MAX_MANAGER_ENTRIES,
        "Manager archive has too many entries"
    );
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            anyhow::bail!("Manager ZIP contains a symbolic link");
        }
        let path = entry
            .enclosed_name()
            .ok_or_else(|| anyhow::anyhow!("Manager ZIP contains an unsafe path"))?;
        let Some(relative) = manager_relative_path(&path)? else {
            continue;
        };
        let output = destination.join(relative);
        if entry.is_dir() {
            fs::create_dir_all(&output)?;
            continue;
        }
        total = total.saturating_add(entry.size());
        anyhow::ensure!(
            total <= MAX_MANAGER_EXTRACTED_BYTES,
            "Manager archive is too large"
        );
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        copy_limited(&mut entry, &output, MAX_MANAGER_EXTRACTED_BYTES)?;
    }
    Ok(())
}

fn extract_manager_tar(package_bytes: &[u8], destination: &Path) -> anyhow::Result<()> {
    let mut archive = Archive::new(GzDecoder::new(Cursor::new(package_bytes)));
    let mut count = 0_usize;
    let mut total = 0_u64;
    for entry in archive.entries()? {
        count += 1;
        anyhow::ensure!(
            count <= MAX_MANAGER_ENTRIES,
            "Manager archive has too many entries"
        );
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        anyhow::ensure!(
            kind.is_file() || kind.is_dir(),
            "Manager TAR contains a special entry"
        );
        let path = entry.path()?.into_owned();
        let Some(relative) = manager_relative_path(&path)? else {
            continue;
        };
        let output = destination.join(relative);
        if kind.is_dir() {
            fs::create_dir_all(&output)?;
            continue;
        }
        let size = entry.header().size()?;
        total = total.saturating_add(size);
        anyhow::ensure!(
            total <= MAX_MANAGER_EXTRACTED_BYTES,
            "Manager archive is too large"
        );
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        copy_limited(&mut entry, &output, MAX_MANAGER_EXTRACTED_BYTES)?;
        #[cfg(unix)]
        if let Ok(mode) = entry.header().mode() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&output, fs::Permissions::from_mode(mode & 0o777))?;
        }
    }
    Ok(())
}

fn manager_relative_path(path: &Path) -> anyhow::Result<Option<PathBuf>> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_owned()),
            _ => anyhow::bail!("Manager archive contains an unsafe path"),
        }
    }
    if parts
        .first()
        .is_some_and(|value| value.to_string_lossy().starts_with("linklake-manager-"))
    {
        parts.remove(0);
    }
    if parts.is_empty() {
        return Ok(None);
    }
    let mut relative = PathBuf::new();
    for part in parts {
        relative.push(part);
    }
    Ok(Some(relative))
}

fn validate_manager_payload(root: &Path) -> anyhow::Result<()> {
    #[cfg(windows)]
    anyhow::ensure!(
        root.join("linklake_manager.exe").is_file(),
        "Manager executable is missing"
    );
    #[cfg(target_os = "linux")]
    anyhow::ensure!(
        root.join("linklake_manager").is_file(),
        "Manager executable is missing"
    );
    #[cfg(target_os = "macos")]
    {
        let found = fs::read_dir(root)?.filter_map(Result::ok).any(|entry| {
            entry.path().extension() == Some(OsStr::new("app"))
                && entry
                    .path()
                    .join("Contents/MacOS/linklake_manager")
                    .is_file()
        });
        anyhow::ensure!(found, "Manager application bundle is missing");
    }
    Ok(())
}

fn read_manager_release(root: &Path) -> anyhow::Result<ReleaseManifest> {
    let value: serde_json::Value =
        read_json_limited(&root.join("release.json"), MAX_MANIFEST_BYTES)?;
    anyhow::ensure!(
        value["product"].as_str() == Some("LinkLake Manager"),
        "invalid Manager product"
    );
    anyhow::ensure!(
        value["component"].as_str() == Some("manager"),
        "invalid Manager component"
    );
    let release = ReleaseManifest {
        product: value["product"].as_str().unwrap_or_default().to_owned(),
        version: value["version"].as_str().unwrap_or_default().to_owned(),
        target: value["target"].as_str().unwrap_or_default().to_owned(),
        built_unix_seconds: value["built_unix_seconds"].as_u64().unwrap_or_default(),
    };
    anyhow::ensure!(
        release.built_unix_seconds > 0,
        "invalid Manager build timestamp"
    );
    Ok(release)
}

fn latest_manager_staged(state: &Path) -> anyhow::Result<ManagerStagedUpdate> {
    let staging = state.join("staging");
    let mut values = fs::read_dir(staging)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path().join("manager-staged.json");
            read_json_limited::<ManagerStagedUpdate>(&path, MAX_MANIFEST_BYTES).ok()
        })
        .collect::<Vec<_>>();
    values.sort_by_key(|value| value.downloaded_unix_seconds);
    values
        .pop()
        .ok_or_else(|| anyhow::anyhow!("no staged Manager update exists"))
}

fn schedule_manager(
    state: &Path,
    install_directory: &Path,
    staged_directory: &Path,
    from_version: &str,
    to_version: &str,
    manager_process_id: u32,
    operation: ManagerOperation,
) -> anyhow::Result<ManagerSchedule> {
    anyhow::ensure!(
        manager_process_id > 0,
        "Manager process ID must be positive"
    );
    anyhow::ensure!(
        manager_process_id != std::process::id(),
        "Manager process ID must identify the calling Manager, not the updater"
    );
    let manager_process_identity = process_identity(manager_process_id)?;
    let target = fs::canonicalize(absolute_path(install_directory)?)?;
    anyhow::ensure!(target.is_dir(), "Manager install directory is invalid");
    validate_manager_payload(&target)?;
    let release = read_manager_release(&target)?;
    anyhow::ensure!(
        release.version == from_version,
        "Manager installed version changed"
    );
    let staged = fs::canonicalize(staged_directory)?;
    validate_manager_staged_location(operation, &staged, state, &target)?;
    validate_manager_payload(&staged)?;
    let staged_release = read_manager_release(&staged)?;
    anyhow::ensure!(
        staged_release.version == to_version,
        "staged Manager release version changed"
    );
    anyhow::ensure!(
        staged_release.target == platform_target()?,
        "staged Manager release target changed"
    );
    let exit_timeout_seconds = manager_exit_timeout_seconds();
    let expected_target_tree_sha256 = directory_tree_sha256(&target)?;
    let staged_tree_sha256 = directory_tree_sha256(&staged)?;
    let plan = ManagerPlan {
        schema_version: MANAGER_SCHEMA_VERSION,
        operation,
        state_directory: state.to_owned(),
        target_directory: target,
        staged_directory: staged,
        expected_target_tree_sha256,
        staged_tree_sha256,
        from_version: from_version.to_owned(),
        to_version: to_version.to_owned(),
        manager_process_id,
        manager_process_identity: manager_process_identity.clone(),
        manager_exit_timeout_seconds: exit_timeout_seconds,
        created_unix_seconds: unix_seconds(),
    };
    let plans = state.join("manager-plans");
    let helpers = state.join("helpers");
    fs::create_dir_all(&plans)?;
    fs::create_dir_all(&helpers)?;
    secure_directory(&plans)?;
    secure_directory(&helpers)?;
    let id = Uuid::new_v4().simple().to_string();
    let plan_path = plans.join(format!("{id}.json"));
    let bytes = serde_json::to_vec_pretty(&plan)?;
    write_bytes_atomically(&plan_path, &bytes)?;
    let helper = helpers.join(if cfg!(windows) {
        format!("linklake-manager-update-helper-{id}.exe")
    } else {
        format!("linklake-manager-update-helper-{id}")
    });
    fs::copy(std::env::current_exe()?, &helper)?;
    set_executable_permissions(&helper)?;
    anyhow::ensure!(
        sha256_file(&helper)? == sha256_file(&std::env::current_exe()?)?,
        "Manager helper copy is incomplete"
    );
    write_manager_status(state, "scheduled", operation, &plan, None, None)?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(state.join("manager-helper.log"))?;
    let error_log = log.try_clone()?;
    let mut command = Command::new(&helper);
    command
        .arg("__manager-update-helper")
        .arg("--plan")
        .arg(&plan_path)
        .arg("--plan-sha256")
        .arg(sha256_bytes(&bytes))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(error_log));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000 | 0x0000_0008 | 0x0000_0200);
    }
    #[cfg(windows)]
    let inheritance_guard = disable_standard_handle_inheritance()?;
    let child_result = command.spawn();
    #[cfg(windows)]
    drop(inheritance_guard);
    let child = match child_result {
        Ok(child) => child,
        Err(error) => {
            write_manager_status(
                state,
                "failed",
                operation,
                &plan,
                Some(error.to_string()),
                None,
            )?;
            return Err(error.into());
        }
    };
    Ok(ManagerSchedule {
        schema_version: MANAGER_SCHEMA_VERSION,
        state: "scheduled".to_owned(),
        operation: manager_operation_name(operation).to_owned(),
        from_version: plan.from_version,
        to_version: plan.to_version,
        status_file: state.join("manager-status.json"),
        helper_process_id: child.id(),
        requires_manager_exit: true,
        manager_process_id,
        manager_process_identity,
        exit_timeout_seconds,
        exit_deadline_unix_seconds: plan
            .created_unix_seconds
            .saturating_add(exit_timeout_seconds),
    })
}

fn validate_manager_plan(path: &Path, plan: &mut ManagerPlan) -> anyhow::Result<()> {
    anyhow::ensure!(
        plan.schema_version == MANAGER_SCHEMA_VERSION,
        "invalid Manager plan schema"
    );
    plan.state_directory = fs::canonicalize(&plan.state_directory)?;
    ensure_within(path, &plan.state_directory)?;
    plan.staged_directory = fs::canonicalize(&plan.staged_directory)?;
    plan.target_directory = fs::canonicalize(&plan.target_directory)?;
    validate_manager_staged_location(
        plan.operation,
        &plan.staged_directory,
        &plan.state_directory,
        &plan.target_directory,
    )?;
    anyhow::ensure!(
        plan.manager_process_id > 0 && plan.manager_process_id != std::process::id(),
        "invalid Manager exit handshake process ID"
    );
    anyhow::ensure!(
        (1..=300).contains(&plan.manager_exit_timeout_seconds),
        "invalid Manager exit handshake timeout"
    );
    anyhow::ensure!(
        directory_tree_sha256(&plan.target_directory)? == plan.expected_target_tree_sha256,
        "installed Manager changed after scheduling"
    );
    anyhow::ensure!(
        directory_tree_sha256(&plan.staged_directory)? == plan.staged_tree_sha256,
        "staged Manager payload changed after scheduling"
    );
    Ok(())
}

fn validate_manager_staged_location(
    operation: ManagerOperation,
    staged: &Path,
    state: &Path,
    target: &Path,
) -> anyhow::Result<()> {
    match operation {
        ManagerOperation::Apply => ensure_within(staged, state),
        ManagerOperation::Rollback => {
            anyhow::ensure!(
                staged.parent() == target.parent(),
                "Manager rollback backup must share the installation parent directory"
            );
            anyhow::ensure!(
                staged
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with(".linklake-manager.backup-")),
                "Manager rollback backup name is invalid"
            );
            Ok(())
        }
    }
}

fn wait_for_manager_exit(plan: &ManagerPlan) -> anyhow::Result<()> {
    write_manager_status(
        &plan.state_directory,
        "waiting_for_exit",
        plan.operation,
        plan,
        None,
        None,
    )?;
    if !wait_for_process_exit(
        plan.manager_process_id,
        &plan.manager_process_identity,
        Duration::from_secs(plan.manager_exit_timeout_seconds),
    )? {
        let error = format!(
            "Manager process {} did not exit within {} seconds",
            plan.manager_process_id, plan.manager_exit_timeout_seconds
        );
        write_manager_status(
            &plan.state_directory,
            "failed",
            plan.operation,
            plan,
            Some(error.clone()),
            None,
        )?;
        anyhow::bail!(error);
    }
    Ok(())
}

fn execute_manager_plan(plan: &ManagerPlan) -> anyhow::Result<()> {
    anyhow::ensure!(
        directory_tree_sha256(&plan.target_directory)? == plan.expected_target_tree_sha256,
        "installed Manager changed while waiting for exit"
    );
    anyhow::ensure!(
        directory_tree_sha256(&plan.staged_directory)? == plan.staged_tree_sha256,
        "staged Manager payload changed while waiting for exit"
    );
    write_manager_status(
        &plan.state_directory,
        "installing",
        plan.operation,
        plan,
        None,
        None,
    )?;
    let parent = plan
        .target_directory
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Manager install directory has no parent"))?;
    let id = Uuid::new_v4().simple().to_string();
    let incoming = parent.join(format!(".linklake-manager.incoming-{id}"));
    let backup = parent.join(format!(".linklake-manager.backup-{id}"));
    copy_directory(&plan.staged_directory, &incoming)?;
    anyhow::ensure!(
        directory_tree_sha256(&incoming)? == plan.staged_tree_sha256,
        "Manager incoming copy digest mismatch"
    );
    let deadline = std::time::Instant::now() + HELPER_RETRY_TIMEOUT;
    loop {
        match fs::rename(&plan.target_directory, &backup) {
            Ok(()) => break,
            Err(error) if std::time::Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(500));
            }
            Err(error) => {
                let _ = fs::remove_dir_all(&incoming);
                write_manager_status(
                    &plan.state_directory,
                    "failed",
                    plan.operation,
                    plan,
                    Some(error.to_string()),
                    None,
                )?;
                return Err(error.into());
            }
        }
    }
    if let Err(error) = fs::rename(&incoming, &plan.target_directory) {
        let restore = restore_manager_directory(plan, &backup, None);
        let (state, final_error) = match restore {
            Ok(()) => ("rolled_back", error.to_string()),
            Err(restore_error) => (
                "failed",
                format!("{error}; automatic restore failed: {restore_error}"),
            ),
        };
        write_manager_status(
            &plan.state_directory,
            state,
            plan.operation,
            plan,
            Some(final_error.clone()),
            backup.exists().then_some(backup.clone()),
        )?;
        anyhow::bail!(final_error);
    }
    let validation = read_manager_release(&plan.target_directory).and_then(|release| {
        anyhow::ensure!(
            release.version == plan.to_version,
            "installed Manager version mismatch"
        );
        validate_manager_payload(&plan.target_directory)?;
        anyhow::ensure!(
            directory_tree_sha256(&plan.target_directory)? == plan.staged_tree_sha256,
            "installed Manager payload digest mismatch"
        );
        #[cfg(debug_assertions)]
        anyhow::ensure!(
            std::env::var_os("LINKLAKE_MANAGER_UPDATE_TEST_FAIL_AFTER_SWITCH").is_none(),
            "test fixture simulated Manager post-switch validation failure"
        );
        Ok(())
    });
    if let Err(error) = validation {
        let failed = parent.join(format!(".linklake-manager.failed-{id}"));
        let restore = restore_manager_directory(plan, &backup, Some(&failed));
        let (state, final_error) = match restore {
            Ok(()) => ("rolled_back", error.to_string()),
            Err(restore_error) => (
                "failed",
                format!("{error}; automatic restore failed: {restore_error}"),
            ),
        };
        write_manager_status(
            &plan.state_directory,
            state,
            plan.operation,
            plan,
            Some(final_error.clone()),
            backup.exists().then_some(backup),
        )?;
        anyhow::bail!(final_error);
    }
    let backup_release = read_manager_release(&backup)?;
    let backup_tree_sha256 = directory_tree_sha256(&backup)?;
    anyhow::ensure!(
        backup_tree_sha256 == plan.expected_target_tree_sha256,
        "Manager backup payload digest mismatch"
    );
    let metadata = ManagerBackup {
        schema_version: MANAGER_SCHEMA_VERSION,
        version: backup_release.version,
        tree_sha256: backup_tree_sha256,
        directory: backup.clone(),
        created_unix_seconds: unix_seconds(),
    };
    write_json_atomically(&plan.state_directory.join("manager-backup.json"), &metadata)?;
    write_manager_status(
        &plan.state_directory,
        if plan.operation == ManagerOperation::Rollback {
            "rolled_back"
        } else {
            "succeeded"
        },
        plan.operation,
        plan,
        None,
        Some(backup),
    )
}

fn restore_manager_directory(
    plan: &ManagerPlan,
    backup: &Path,
    failed: Option<&Path>,
) -> anyhow::Result<()> {
    if plan.target_directory.exists() {
        let failed = failed.ok_or_else(|| {
            anyhow::anyhow!("cannot restore Manager while the failed target still exists")
        })?;
        fs::rename(&plan.target_directory, failed)?;
    }
    fs::rename(backup, &plan.target_directory)?;
    anyhow::ensure!(
        directory_tree_sha256(&plan.target_directory)? == plan.expected_target_tree_sha256,
        "restored Manager payload digest mismatch"
    );
    let release = read_manager_release(&plan.target_directory)?;
    anyhow::ensure!(
        release.version == plan.from_version,
        "restored Manager version mismatch"
    );
    if let Some(failed) = failed {
        let _ = fs::remove_dir_all(failed);
    }
    Ok(())
}

fn copy_directory(source: &Path, destination: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        !destination.exists(),
        "Manager incoming directory already exists"
    );
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_directory(&entry.path(), &target)?;
        } else if entry.file_type()?.is_file() {
            fs::copy(entry.path(), &target)?;
            #[cfg(unix)]
            fs::set_permissions(&target, entry.metadata()?.permissions())?;
        } else {
            anyhow::bail!("Manager staging directory contains a special file");
        }
    }
    Ok(())
}

fn manager_exit_timeout_seconds() -> u64 {
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os("LINKLAKE_MANAGER_UPDATE_TEST_EXIT_TIMEOUT_SECONDS") {
        if let Ok(value) = value.to_string_lossy().parse::<u64>() {
            if (1..=300).contains(&value) {
                return value;
            }
        }
    }
    MANAGER_EXIT_TIMEOUT_SECONDS
}

fn directory_tree_sha256(root: &Path) -> anyhow::Result<String> {
    let root = fs::canonicalize(root)?;
    anyhow::ensure!(root.is_dir(), "Manager payload root is not a directory");
    let mut files = Vec::new();
    collect_manager_files(&root, &root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut tree = Sha256::new();
    tree.update(b"linklake-manager-tree-v1\0");
    for (relative, path) in files {
        let metadata = fs::metadata(&path)?;
        tree.update((relative.len() as u64).to_be_bytes());
        tree.update(relative.as_bytes());
        tree.update(metadata.len().to_be_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tree.update(metadata.permissions().mode().to_be_bytes());
        }
        #[cfg(not(unix))]
        tree.update(0_u32.to_be_bytes());

        let mut file = File::open(path)?;
        let mut file_digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            file_digest.update(&buffer[..read]);
        }
        anyhow::ensure!(
            total == metadata.len(),
            "Manager payload changed while hashing"
        );
        tree.update(file_digest.finalize());
    }
    Ok(format!("{:x}", tree.finalize()))
}

fn collect_manager_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_manager_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root)?;
            let relative = relative
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Manager payload path is not valid UTF-8"))?
                .replace('\\', "/");
            files.push((relative, path));
        } else {
            anyhow::bail!("Manager payload contains a symbolic link or special file");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn process_identity(process_id: u32) -> anyhow::Result<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    anyhow::ensure!(!handle.is_null(), "Manager process is not running");
    let result = process_identity_from_handle(handle);
    unsafe {
        CloseHandle(handle);
    }
    result
}

#[cfg(windows)]
fn process_identity_from_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> anyhow::Result<String> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;

    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    anyhow::ensure!(
        unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } != 0,
        "could not read Manager process identity"
    );
    let value = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    Ok(format!("windows-filetime-{value:016x}"))
}

#[cfg(windows)]
fn wait_for_process_exit(
    process_id: u32,
    expected_identity: &str,
    timeout: Duration,
) -> anyhow::Result<bool> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    let handle = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            process_id,
        )
    };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(value) if value == ERROR_INVALID_PARAMETER as i32 => Ok(true),
            _ => Err(error.into()),
        };
    }
    if process_identity_from_handle(handle)? != expected_identity {
        unsafe {
            CloseHandle(handle);
        }
        return Ok(true);
    }
    let timeout_millis = timeout.as_millis().min(u32::MAX as u128) as u32;
    let wait = unsafe { WaitForSingleObject(handle, timeout_millis) };
    unsafe {
        CloseHandle(handle);
    }
    match wait {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(std::io::Error::last_os_error().into()),
    }
}

#[cfg(unix)]
fn process_identity(process_id: u32) -> anyhow::Result<String> {
    Ok(format!("unix-pid-{process_id}"))
}

#[cfg(unix)]
fn wait_for_process_exit(
    process_id: u32,
    _expected_identity: &str,
    timeout: Duration,
) -> anyhow::Result<bool> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let result = unsafe { libc::kill(process_id as libc::pid_t, 0) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ESRCH) => return Ok(true),
                Some(libc::EPERM) => {}
                _ => return Err(error.into()),
            }
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(Duration::from_millis(250));
    }
}

fn write_manager_status(
    state: &Path,
    status: &str,
    operation: ManagerOperation,
    plan: &ManagerPlan,
    error: Option<String>,
    backup: Option<PathBuf>,
) -> anyhow::Result<()> {
    write_json_atomically(
        &state.join("manager-status.json"),
        &ManagerStatus {
            schema_version: MANAGER_SCHEMA_VERSION,
            state: status.to_owned(),
            operation: Some(manager_operation_name(operation).to_owned()),
            from_version: Some(plan.from_version.clone()),
            to_version: Some(plan.to_version.clone()),
            message: match status {
                "scheduled" => "Manager update helper scheduled; exit Manager to unlock its files",
                "waiting_for_exit" => {
                    "Manager update helper is waiting for the Manager process to exit"
                }
                "installing" => "Manager package is being installed",
                "succeeded" => "Manager package installed and verified",
                "rolled_back" => "Manager rollback completed",
                _ => "Manager update failed",
            }
            .to_owned(),
            error,
            backup,
            requires_manager_exit: matches!(status, "scheduled" | "waiting_for_exit"),
            manager_process_id: Some(plan.manager_process_id),
            manager_process_identity: Some(plan.manager_process_identity.clone()),
            exit_deadline_unix_seconds: Some(
                plan.created_unix_seconds
                    .saturating_add(plan.manager_exit_timeout_seconds),
            ),
            updated_unix_seconds: unix_seconds(),
        },
    )
}

fn manager_operation_name(operation: ManagerOperation) -> &'static str {
    match operation {
        ManagerOperation::Apply => "apply",
        ManagerOperation::Rollback => "rollback",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_tree_digest_binds_paths_and_file_contents() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("data")).unwrap();
        fs::write(root.path().join("release.json"), b"release").unwrap();
        fs::write(root.path().join("data/runtime.dat"), b"runtime").unwrap();
        let original = directory_tree_sha256(root.path()).unwrap();

        fs::write(root.path().join("data/runtime.dat"), b"tampered").unwrap();
        assert_ne!(directory_tree_sha256(root.path()).unwrap(), original);

        fs::write(root.path().join("data/runtime.dat"), b"runtime").unwrap();
        fs::rename(
            root.path().join("data/runtime.dat"),
            root.path().join("data/renamed.dat"),
        )
        .unwrap();
        assert_ne!(directory_tree_sha256(root.path()).unwrap(), original);
    }

    #[test]
    fn current_process_does_not_satisfy_exit_handshake() {
        let identity = process_identity(std::process::id()).unwrap();
        assert!(
            !wait_for_process_exit(std::process::id(), &identity, Duration::from_millis(1),)
                .unwrap()
        );
    }

    #[test]
    fn exited_process_satisfies_exit_handshake() {
        let mut child = if cfg!(windows) {
            Command::new("cmd.exe")
                .args(["/c", "exit", "0"])
                .spawn()
                .unwrap()
        } else {
            Command::new("sh").args(["-c", "exit 0"]).spawn().unwrap()
        };
        let process_id = child.id();
        let identity = process_identity(process_id).unwrap();
        child.wait().unwrap();
        assert!(wait_for_process_exit(process_id, &identity, Duration::from_secs(1)).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn terminated_process_satisfies_exit_handshake() {
        let mut child = Command::new("cmd.exe")
            .args(["/d", "/c", "ping 127.0.0.1 -n 121 >nul"])
            .spawn()
            .unwrap();
        let process_id = child.id();
        let identity = process_identity(process_id).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(wait_for_process_exit(process_id, &identity, Duration::from_secs(1)).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn process_terminated_while_waiting_satisfies_exit_handshake() {
        let mut child = Command::new("cmd.exe")
            .args(["/d", "/c", "ping 127.0.0.1 -n 121 >nul"])
            .spawn()
            .unwrap();
        let process_id = child.id();
        let identity = process_identity(process_id).unwrap();
        let killer = std::thread::spawn(move || {
            sleep(Duration::from_millis(100));
            Command::new("taskkill.exe")
                .args(["/pid", &process_id.to_string(), "/f", "/t"])
                .status()
                .unwrap();
        });
        assert!(wait_for_process_exit(process_id, &identity, Duration::from_secs(5)).unwrap());
        killer.join().unwrap();
        child.wait().unwrap();
    }
}
