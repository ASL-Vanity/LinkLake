//! 只读磁盘证书/账户，导入前用目标集群材料密钥加密；不创建明文中间文件。
use super::*;
use std::{
    collections::{hash_map::DefaultHasher, BTreeSet},
    hash::{Hash, Hasher},
    io::Read,
};
use zeroize::Zeroizing;

use crate::{
    certificate_catalog::{normalize_certificate_identifier, postgres::private_key_context},
    certificate_manager::{CERTIFICATE_COMMIT_MARKER, CERTIFICATE_GENERATIONS_DIRECTORY},
    certificate_material::MAX_MATERIAL_BYTES,
};

pub(super) fn import(
    builder: &mut Builder,
    cipher: &CertificateMaterialCipher,
    config: &Value,
    tls: &[Value],
    states: &[Value],
    options: &MigrationSourceOptions,
) -> Result<()> {
    let http = builder
        .tables
        .get("http_route_policies")
        .cloned()
        .unwrap_or_default();
    let mut covered_directories = BTreeSet::new();
    let mut covered_identifiers = BTreeSet::new();
    for policy in tls {
        let route = text(policy, "route_id")?;
        let Some(http) = http.iter().find(|row| row["id"] == policy["route_id"]) else {
            return Err(MigrationError::InvalidSource);
        };
        let identifier = policy
            .get("certificate_identifier")
            .and_then(Value::as_str)
            .unwrap_or(text(http, "hostname")?);
        let normalized = normalize_certificate_identifier(identifier)
            .map_err(|_| MigrationError::InvalidSource)?;
        if normalized != identifier {
            return Err(MigrationError::InvalidSource);
        }
        let folder = identifier
            .strip_prefix("*.")
            .map(|suffix| format!("_wildcard_.{suffix}"))
            .unwrap_or_else(|| identifier.to_owned());
        covered_directories.insert(folder.clone());
        let directory = builder.source.directory.join("certificates").join(folder);
        let state = states
            .iter()
            .find(|row| row["route_id"] == policy["route_id"]);
        if !directory.exists() {
            if state.is_some_and(|row| {
                row["last_success"].as_i64().is_some()
                    || row["status"] == "active"
                    || row["status"] == "expired"
            }) {
                return Err(MigrationError::InvalidSource);
            }
            continue;
        }
        // PG 一份标识对应一份route材料；拒绝多个来源路由竞争同一持久材料。
        if !covered_identifiers.insert(identifier.to_owned()) {
            return Err(MigrationError::InvalidSource);
        }
        let (certificate, private_key) =
            read_certificate_pair(&builder.source.directory, &directory, identifier)?;
        let route_id = Uuid::parse_str(route).map_err(|_| MigrationError::InvalidSource)?;
        builder.digest.update(b"certificate-material\0");
        builder.digest.update(route.as_bytes());
        builder.digest.update(identifier.as_bytes());
        builder
            .digest
            .update(Sha256::digest(certificate.as_slice()));
        builder
            .digest
            .update(Sha256::digest(private_key.as_slice()));
        let encrypted = cipher
            .seal(
                &private_key_context(route_id, identifier, &certificate),
                &private_key,
            )
            .map_err(|_| MigrationError::InvalidKey)?;
        let generation = revision(
            "certificate-material",
            &json!({"route":route,"certificate_sha256":format!("{:x}",Sha256::digest(certificate.as_slice()))}),
        );
        let updated = state
            .and_then(|row| row["last_success"].as_i64())
            .unwrap_or(0);
        builder.add("linklake_certificate_materials",json!({"identifier":identifier,"route_id":route,"generation":generation,"certificate_pem":bytea(&certificate),"encrypted_private_key":bytea(&encrypted),"updated_unix_seconds":updated}));
    }
    let certificates = builder.source.directory.join("certificates");
    if certificates.exists() {
        for entry in std::fs::read_dir(&certificates).map_err(|_| MigrationError::InvalidSource)? {
            let entry = entry.map_err(|_| MigrationError::InvalidSource)?;
            if entry
                .file_type()
                .map_err(|_| MigrationError::InvalidSource)?
                .is_dir()
                && !covered_directories.contains(&entry.file_name().to_string_lossy().to_string())
            {
                return Err(MigrationError::UnsupportedSourceData);
            }
        }
    }

    let mut directories = BTreeSet::from([
        text(config, "directory_url")?.to_owned(),
        "https://acme-v02.api.letsencrypt.org/directory".to_owned(),
        "https://acme-staging-v02.api.letsencrypt.org/directory".to_owned(),
    ]);
    directories.extend(options.account_directories.iter().cloned());
    let mut recognized_files = BTreeSet::new();
    for directory in directories {
        let url = reqwest::Url::parse(&directory).map_err(|_| MigrationError::InvalidSource)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(MigrationError::InvalidSource);
        }
        let current_name = format!(
            "account-sha256-{:x}.json",
            Sha256::digest(directory.as_bytes())
        );
        let mut hasher = DefaultHasher::new();
        directory.hash(&mut hasher);
        let legacy_name = format!("account-{:016x}.json", hasher.finish());
        recognized_files.insert(current_name.clone());
        recognized_files.insert(legacy_name.clone());
        let current = builder.source.directory.join("acme").join(current_name);
        let legacy = builder.source.directory.join("acme").join(legacy_name);
        let file = if current.exists() {
            current
        } else if legacy.exists() {
            legacy
        } else {
            continue;
        };
        let credentials = read_material_file(&builder.source.directory, &file, MAX_MATERIAL_BYTES)?;
        let _validated_credentials =
            serde_json::from_slice::<instant_acme::AccountCredentials>(&credentials)
                .map_err(|_| MigrationError::InvalidSource)?;
        builder.digest.update(b"acme-account\0");
        builder.digest.update(directory.as_bytes());
        builder
            .digest
            .update(Sha256::digest(credentials.as_slice()));
        let encrypted = cipher
            .seal(&format!("acme-account:{directory}"), &credentials)
            .map_err(|_| MigrationError::InvalidKey)?;
        builder.add("linklake_acme_accounts",json!({"directory_url":directory,"encrypted_credentials":bytea(&encrypted),"updated_unix_seconds":config["updated_at"]}));
    }
    let acme = builder.source.directory.join("acme");
    if acme.exists() {
        for entry in std::fs::read_dir(acme).map_err(|_| MigrationError::InvalidSource)? {
            let entry = entry.map_err(|_| MigrationError::InvalidSource)?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("account-")
                && name.ends_with(".json")
                && !recognized_files.contains(&name)
            {
                return Err(MigrationError::UnsupportedSourceData);
            }
        }
    }
    Ok(())
}

fn read_material_file(root: &Path, path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let canonical = path
        .canonicalize()
        .map_err(|_| MigrationError::InvalidSource)?;
    if !canonical.starts_with(root) {
        return Err(MigrationError::InvalidSource);
    }
    let file = File::open(&canonical).map_err(|_| MigrationError::InvalidSource)?;
    let metadata = file.metadata().map_err(|_| MigrationError::InvalidSource)?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(MigrationError::InvalidSource);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| MigrationError::InvalidSource)?;
    if bytes.len() > maximum {
        return Err(MigrationError::InvalidSource);
    }
    Ok(bytes)
}

type CertificatePemPair = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

fn read_certificate_pair(
    root: &Path,
    directory: &Path,
    identifier: &str,
) -> Result<CertificatePemPair> {
    let mut candidates = Vec::new();
    let generations = directory.join(CERTIFICATE_GENERATIONS_DIRECTORY);
    if generations.exists() {
        for entry in std::fs::read_dir(generations).map_err(|_| MigrationError::InvalidSource)? {
            let entry = entry.map_err(|_| MigrationError::InvalidSource)?;
            if entry
                .file_type()
                .map_err(|_| MigrationError::InvalidSource)?
                .is_dir()
                && !entry.file_name().to_string_lossy().starts_with('.')
            {
                candidates.push(entry.path());
            }
        }
        candidates.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
    }
    candidates.retain(|path| {
        read_material_file(root, &path.join("committed"), 128)
            .is_ok_and(|bytes| bytes.as_slice() == CERTIFICATE_COMMIT_MARKER)
    });
    candidates.push(directory.to_owned());
    for candidate in candidates {
        let certificate =
            read_material_file(root, &candidate.join("fullchain.pem"), MAX_MATERIAL_BYTES);
        let private =
            read_material_file(root, &candidate.join("private-key.pem"), MAX_MATERIAL_BYTES);
        let (Ok(certificate), Ok(private)) = (certificate, private) else {
            continue;
        };
        // 按提交代顺序选取结构完整且标识匹配的材料；不依赖当前时钟，确保源指纹稳定。
        // 过期状态由启动后的正常证书维护处理，迁移不能假装从未签发。
        let Ok((chain, _)) =
            crate::certificate_manager::validate_certificate_key_pair(&certificate, &private)
        else {
            continue;
        };
        let Ok((_, parsed)) = x509_parser::parse_x509_certificate(chain[0].as_ref()) else {
            continue;
        };
        let matches=parsed.subject_alternative_name().ok().flatten().is_some_and(|extension|extension.value.general_names.iter().any(|name|matches!(name,x509_parser::extensions::GeneralName::DNSName(value) if value.trim_end_matches('.').eq_ignore_ascii_case(identifier))));
        if matches {
            return Ok((certificate, private));
        }
    }
    Err(MigrationError::InvalidSource)
}
