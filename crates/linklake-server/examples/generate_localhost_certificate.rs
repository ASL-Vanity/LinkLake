use rcgen::generate_simple_self_signed;
use std::{env, fs, path::PathBuf};

fn main() -> anyhow::Result<()> {
    let output = PathBuf::from(
        env::args_os()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("missing output directory"))?,
    );
    fs::create_dir_all(&output)?;
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()])?;
    fs::write(output.join("control-cert.pem"), certified.cert.pem())?;
    fs::write(
        output.join("control-key.pem"),
        certified.signing_key.serialize_pem(),
    )?;
    Ok(())
}
