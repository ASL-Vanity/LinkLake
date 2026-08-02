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

fn generate(
    dist: &Path,
    version: &Version,
    key_id: &str,
    minimum_updater_version: &Version,
    signing_key_env: &str,
    allow_development_key: bool,
) -> anyhow::Result<()> {
    let key_value = std::env::var(signing_key_env)
        .map_err(|_| anyhow::anyhow!("required signing secret {signing_key_env} is not set"))?;
    let seed: [u8; 32] = BASE64.decode(key_value.trim())?.try_into().map_err(|_| {
        anyhow::anyhow!("Ed25519 signing secret must be a base64-encoded 32-byte seed")
    })?;
    let signing_key = SigningKey::from_bytes(&seed);
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
        if name.ends_with(".sha256") || name.ends_with(".deb") || name.ends_with(".rpm") {
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
