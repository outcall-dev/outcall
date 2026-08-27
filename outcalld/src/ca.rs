//! Read-only helpers for configured interception CA material.

use std::path::Path;

use anyhow::{Context, Result};

pub fn read_certificate_serial(cert_path: &Path) -> Result<String> {
    let pem_bytes = std::fs::read(cert_path)
        .with_context(|| format!("failed to read CA certificate {}", cert_path.display()))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_bytes)
        .map_err(|error| anyhow::anyhow!("failed to parse CA certificate PEM: {error}"))?;
    let certificate = pem
        .parse_x509()
        .map_err(|error| anyhow::anyhow!("failed to parse CA X.509 certificate: {error}"))?;
    Ok(certificate.tbs_certificate.raw_serial_as_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_ca_certificate_serial() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cert_path = temp.path().join("ca.crt");
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("certificate parameters");
        params.serial_number = Some(rcgen::SerialNumber::from(42_u64));
        let key = rcgen::KeyPair::generate().expect("key pair");
        let certificate = params.self_signed(&key).expect("self-signed certificate");
        std::fs::write(&cert_path, certificate.pem()).expect("write certificate");

        assert_eq!(
            read_certificate_serial(&cert_path).expect("certificate serial"),
            "2a"
        );
    }

    #[test]
    fn invalid_ca_certificate_has_no_serial() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cert_path = temp.path().join("ca.crt");
        std::fs::write(&cert_path, "not a certificate").expect("write malformed fixture");
        assert!(read_certificate_serial(&cert_path).is_err());
    }
}
