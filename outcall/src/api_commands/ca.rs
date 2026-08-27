use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use outcall_api::{CaBundleResult, CaStatus};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use time::OffsetDateTime;

use super::response_data;
use crate::daemon_client::http_get;

pub(crate) fn cmd_ca_init(out_dir: Option<String>, force: bool) -> Result<()> {
    let requested_dir = out_dir.map(PathBuf::from).unwrap_or_else(default_ca_dir);
    let directory = prepare_ca_output_dir(&requested_dir, force)?;

    let mut parameters = CertificateParams::default();
    parameters.distinguished_name = DistinguishedName::new();
    parameters
        .distinguished_name
        .push(DnType::CommonName, "Outcall CA");
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    parameters.not_before = OffsetDateTime::now_utc();
    parameters.not_after = ten_year_expiry(parameters.not_before)?;
    parameters.subject_alt_names = vec![SanType::DnsName("outcall-ca".try_into()?)];

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .map_err(|error| anyhow::anyhow!("failed to generate RSA key pair: {error}"))?;
    let certificate = parameters
        .self_signed(&key_pair)
        .map_err(|error| anyhow::anyhow!("failed to sign CA certificate: {error}"))?;

    let cert_path = directory.join("ca.crt");
    let key_path = directory.join("ca.key");
    outcall::secure_fs::write_runtime_file(&key_path, key_pair.serialize_pem().as_bytes())?;
    outcall::secure_fs::write_runtime_file(&cert_path, certificate.pem().as_bytes())?;
    std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o644))
        .context("failed to set ca.crt permissions")?;

    println!(
        "CA material generated in {}\n  cert: {}\n  key:  {}\n  SHA-256: {}",
        directory.display(),
        cert_path.display(),
        key_path.display(),
        sha256_fingerprint(certificate.der().as_ref())
    );
    println!("TLS interception is not available in this release.");
    println!("outcalld rejects intercept rules until S011 is implemented.");
    Ok(())
}

pub(crate) fn cmd_ca_bundle(socket: &str) -> Result<()> {
    let bundle: CaBundleResult = response_data(&http_get(socket, "/api/v1/ca/bundle")?)?;
    print!("{}", bundle.pem_bundle);
    Ok(())
}

pub(crate) fn cmd_ca_status(socket: &str) -> Result<()> {
    let status: CaStatus = response_data(&http_get(socket, "/api/v1/ca/status")?)?;
    println!("CA loaded:    {}", if status.loaded { "yes" } else { "no" });
    if let Some(cert_path) = status.cert_path {
        println!("Cert:         {cert_path}");
    }
    if let Some(key_path) = status.key_path {
        println!("Key:          {key_path}");
    }
    if let Some(serial) = status.subject_serial {
        println!("Serial:       {serial}");
    }
    println!(
        "Interception: {}",
        if status.interception_enabled {
            "enabled"
        } else {
            "disabled (no CA)"
        }
    );
    Ok(())
}

fn default_ca_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".outcall/ca")
}

fn ten_year_expiry(not_before: OffsetDateTime) -> Result<OffsetDateTime> {
    let expiry_year = not_before
        .year()
        .checked_add(10)
        .context("CA expiry year overflowed")?;
    match not_before.replace_year(expiry_year) {
        Ok(expiry) => Ok(expiry),
        Err(_) => not_before
            .replace_day(28)
            .and_then(|adjusted| adjusted.replace_year(expiry_year))
            .context("failed to compute CA expiry"),
    }
}

fn sha256_fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let digest = Sha256::digest(der);
    let mut fingerprint = String::with_capacity(digest.len() * 3 - 1);
    for (index, byte) in digest.iter().enumerate() {
        if index > 0 {
            fingerprint.push(':');
        }
        fingerprint.push(HEX[(byte >> 4) as usize] as char);
        fingerprint.push(HEX[(byte & 0x0f) as usize] as char);
    }
    fingerprint
}

fn prepare_ca_output_dir(directory: &Path, force: bool) -> Result<PathBuf> {
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            anyhow::bail!("CA output {} must be a real directory", directory.display());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(directory).with_context(|| {
                format!("failed to create CA directory {}", directory.display())
            })?;
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect CA directory {}", directory.display())
            });
        }
    }

    let canonical = std::fs::canonicalize(directory).with_context(|| {
        format!(
            "failed to canonicalize CA directory {}",
            directory.display()
        )
    })?;
    outcall::secure_fs::secure_runtime_dir(&canonical)?;
    if !force {
        for name in ["ca.crt", "ca.key"] {
            let path = canonical.join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(_) => anyhow::bail!(
                    "{} already exists; pass --force only when intentionally rotating the CA",
                    path.display()
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to inspect {}", path.display()));
                }
            }
        }
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use rcgen::date_time_ymd;

    use super::*;

    #[test]
    fn sha256_fingerprint_is_colon_separated_uppercase() {
        assert_eq!(
            sha256_fingerprint(b"abc"),
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
        );
    }

    #[test]
    fn expiry_handles_leap_day() {
        let expiry = ten_year_expiry(date_time_ymd(2024, 2, 29)).unwrap();
        assert_eq!(expiry, date_time_ymd(2034, 2, 28));
    }

    #[test]
    fn ca_output_refuses_existing_material_without_force() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("ca.crt"), "existing").unwrap();
        let error = prepare_ca_output_dir(root.path(), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("pass --force"));
    }

    #[cfg(unix)]
    #[test]
    fn ca_output_rejects_symlinked_directory() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = root.path().join("link");
        symlink(&real, &link).unwrap();
        let error = prepare_ca_output_dir(&link, true).unwrap_err().to_string();
        assert!(error.contains("real directory"));
    }
}
