use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use linklake_update::{
    canonical_signed_manifest_bytes, DetachedSignature, SignaturePolicy, SignedAsset,
    SignedReleaseManifest, SIGNATURE_NAME, SIGNED_MANIFEST_NAME,
};
use semver::Version;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
#[command(name = "linklake-release-sign")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 仅输出指定 Ed25519 种子的公钥信息，绝不输出私钥。
    PublicKey {
        #[arg(long)]
        key_id: String,
        #[arg(long, default_value = "LINKLAKE_RELEASE_SIGNING_KEY_B64")]
        signing_key_env: String,
    },
    Generate {
        #[arg(long)]
        dist: PathBuf,
        #[arg(long)]
        version: Version,
        #[arg(long)]
        key_id: String,
        #[arg(long, default_value = "0.8.0-rc.1")]
        minimum_updater_version: Version,
        #[arg(long, default_value = "LINKLAKE_RELEASE_SIGNING_KEY_B64")]
        signing_key_env: String,
        #[arg(long)]
        allow_development_key: bool,
    },
    Verify {
        #[arg(long)]
        dist: PathBuf,
        #[arg(long)]
        allow_development_key: bool,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::PublicKey {
            key_id,
            signing_key_env,
        } => print_public_key(&key_id, &signing_key_env),
        Command::Generate {
            dist,
            version,
            key_id,
            minimum_updater_version,
            signing_key_env,
            allow_development_key,
        } => generate(
            &dist,
            &version,
            &key_id,
            &minimum_updater_version,
            &signing_key_env,
            allow_development_key,
        ),
        Command::Verify {
            dist,
            allow_development_key,
        } => verify(&dist, allow_development_key),
    }
}

fn signing_key_from_env(signing_key_env: &str) -> anyhow::Result<SigningKey> {
    let key_value = std::env::var(signing_key_env)
        .map_err(|_| anyhow::anyhow!("required signing secret {signing_key_env} is not set"))?;
    signing_key_from_base64(&key_value)
}

fn signing_key_from_base64(key_value: &str) -> anyhow::Result<SigningKey> {
    let seed: [u8; 32] = BASE64.decode(key_value.trim())?.try_into().map_err(|_| {
        anyhow::anyhow!("Ed25519 signing secret must be a base64-encoded 32-byte seed")
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

fn print_public_key(key_id: &str, signing_key_env: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!key_id.trim().is_empty(), "key ID must not be empty");
    let signing_key = signing_key_from_env(signing_key_env)?;
    println!(
        "{}",
        serde_json::json!({
            "key_id": key_id,
            "algorithm": "Ed25519",
            "public_key_base64": BASE64.encode(signing_key.verifying_key().to_bytes()),
        })
    );
    Ok(())
}

fn generate(
    dist: &Path,
    version: &Version,
    key_id: &str,
    minimum_updater_version: &Version,
    signing_key_env: &str,
    allow_development_key: bool,
) -> anyhow::Result<()> {
    let signing_key = signing_key_from_env(signing_key_env)?;
    validate_signing_key(key_id, &signing_key, version, allow_development_key)?;

    let assets = collect_assets(dist, version)?;
    anyhow::ensure!(
        !assets.is_empty(),
        "no updater-compatible release assets were found"
    );
    let manifest = SignedReleaseManifest {
        schema_version: 1,
        release_version: version.to_string(),
        key_id: key_id.to_owned(),
        minimum_updater_version: minimum_updater_version.to_string(),
        created_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        assets,
    };
    let manifest_bytes = canonical_signed_manifest_bytes(&manifest)?;
    let detached = DetachedSignature {
        schema_version: 1,
        key_id: key_id.to_owned(),
        algorithm: "Ed25519".to_owned(),
        signature_base64: BASE64.encode(signing_key.sign(&manifest_bytes).to_bytes()),
    };
    fs::write(dist.join(SIGNED_MANIFEST_NAME), &manifest_bytes)?;
    fs::write(
        dist.join(SIGNATURE_NAME),
        serde_json::to_vec_pretty(&detached)?,
    )?;
    verify(dist, allow_development_key)
}

fn verify(dist: &Path, allow_development_key: bool) -> anyhow::Result<()> {
    let manifest_bytes = fs::read(dist.join(SIGNED_MANIFEST_NAME))?;
    let signature_bytes = fs::read(dist.join(SIGNATURE_NAME))?;
    let policy = if allow_development_key {
        SignaturePolicy::Development
    } else {
        SignaturePolicy::Production
    };
    let manifest =
        linklake_update::verify_signed_manifest_bytes(&manifest_bytes, &signature_bytes, policy)?;
    for asset in &manifest.assets {
        let path = dist.join(&asset.name);
        anyhow::ensure!(path.is_file(), "signed asset is missing: {}", asset.name);
        let bytes = fs::read(path)?;
        anyhow::ensure!(
            bytes.len() as u64 == asset.size,
            "signed asset size mismatch"
        );
        anyhow::ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == asset.sha256,
            "signed asset digest mismatch: {}",
            asset.name
        );
    }
    println!(
        "verified {} signed assets with key {}",
        manifest.assets.len(),
        manifest.key_id
    );
    Ok(())
}

fn validate_signing_key(
    key_id: &str,
    signing_key: &SigningKey,
    version: &Version,
    allow_development_key: bool,
) -> anyhow::Result<()> {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../security/release-keys.json"))?;
    let keys = value["keys"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("trusted key registry is invalid"))?;
    let key = keys
        .iter()
        .find(|value| value["key_id"].as_str() == Some(key_id))
        .ok_or_else(|| anyhow::anyhow!("key ID is not present in security/release-keys.json"))?;
    let purpose = key["purpose"].as_str().unwrap_or_default();
    anyhow::ensure!(
        purpose == "production" || (allow_development_key && purpose == "development"),
        "formal signing requires a key marked purpose=production"
    );
    let registered = key["public_key_base64"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("trusted key has no public key"))?;
    anyhow::ensure!(
        BASE64.encode(signing_key.verifying_key().to_bytes()) == registered,
        "signing secret does not match the registered public key"
    );
    let not_before = Version::parse(key["not_before_version"].as_str().unwrap_or_default())?;
    anyhow::ensure!(
        version >= &not_before,
        "signing key is not active for this version"
    );
    if let Some(not_after) = key["not_after_version"].as_str() {
        anyhow::ensure!(
            version <= &Version::parse(not_after)?,
            "signing key has expired for this version"
        );
    }
    Ok(())
}

fn collect_assets(dist: &Path, version: &Version) -> anyhow::Result<Vec<SignedAsset>> {
    let mut assets = Vec::new();
    let prefix = format!("linklake-{version}-");
    let manager_prefix = format!("linklake-manager-{version}-");
    for entry in fs::read_dir(dist)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // 更新清单只描述客户端和服务端实际可安装的 ZIP/TAR 包；平台签名、
        // SBOM、容器证据和原生包由各自的验证链负责，不能被误解析为更新目标。
        if !(name.ends_with(".zip") || name.ends_with(".tar.gz")) {
            continue;
        }
        let (components, target) = if let Some(rest) = name.strip_prefix(&manager_prefix) {
            (vec!["manager"], archive_target(rest)?)
        } else if let Some(rest) = name.strip_prefix(&prefix) {
            (vec!["client", "server"], archive_target(rest)?)
        } else {
            continue;
        };
        let bytes = fs::read(entry.path())?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        for component in components {
            assets.push(SignedAsset {
                component: component.to_owned(),
                target: target.clone(),
                name: name.clone(),
                sha256: digest.clone(),
                size: bytes.len() as u64,
            });
        }
    }
    assets.sort_by(|left, right| {
        (&left.component, &left.target, &left.name).cmp(&(
            &right.component,
            &right.target,
            &right.name,
        ))
    });
    Ok(assets)
}

fn archive_target(value: &str) -> anyhow::Result<String> {
    let target = value
        .strip_suffix(".tar.gz")
        .or_else(|| value.strip_suffix(".zip"))
        .ok_or_else(|| anyhow::anyhow!("unsupported updater archive name: {value}"))?;
    anyhow::ensure!(!target.is_empty(), "release asset target is empty");
    Ok(target.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_public_key_without_exposing_seed() {
        let key = signing_key_from_base64("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=").unwrap();
        assert_eq!(
            BASE64.encode(key.verifying_key().to_bytes()),
            "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
        );
    }

    #[test]
    fn platform_signatures_and_supply_chain_evidence_are_not_update_assets() {
        let directory = tempfile::tempdir().unwrap();
        let version = Version::parse("1.0.0-rc.1").unwrap();
        for name in [
            "linklake-1.0.0-rc.1-windows-x86_64.zip",
            "linklake-manager-1.0.0-rc.1-windows-x86_64.zip",
            "linklake-1.0.0-rc.1-windows-x86_64.zip.asc",
            "linklake-1.0.0-rc.1-windows-x86_64.zip.spdx.json",
            "linklake_1.0.0-rc.1_amd64.deb",
            "linklake-1.0.0-0.rc.1.x86_64.rpm",
            "linklake-linux-release-public-key.asc",
            "container-image-1.0.0-rc.1.txt",
        ] {
            fs::write(directory.path().join(name), name).unwrap();
        }

        let assets = collect_assets(directory.path(), &version).unwrap();
        assert_eq!(assets.len(), 3);
        assert!(assets
            .iter()
            .all(|asset| { asset.name.ends_with(".zip") && !asset.name.ends_with(".zip.asc") }));
    }
}
