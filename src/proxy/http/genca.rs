use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};

/// Get self-signed certificate and key.
pub fn get_self_signed_cert() -> crate::Result<(Vec<u8>, Vec<u8>)> {
    let temp_dir = std::env::temp_dir().join(env!("CARGO_PKG_NAME"));
    if !temp_dir.exists() {
        tracing::info!("Creating temp cert directory: {}", temp_dir.display());
        std::fs::create_dir_all(&temp_dir)?;
    }

    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");
    if cert_path.exists() && key_path.exists() {
        let cert = std::fs::read_to_string(cert_path)?;
        let key = std::fs::read(key_path)?;
        tracing::info!("Using existing self-signed certificate: \n{}", cert);

        return Ok((cert.into_bytes(), key));
    }

    let (cert, key) = generate_self_signed()?;
    std::fs::write(cert_path, &cert)?;
    std::fs::write(key_path, &key)?;
    Ok((cert, key))
}

/// Generate self-signed certificate and key.
fn generate_self_signed() -> crate::Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::default();
    params.not_before = date_time_ymd(1975, 1, 1);
    params.not_after = date_time_ymd(4096, 1, 1);
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "vproxy");
    distinguished_name.push(DnType::OrganizationName, "vproxy");
    params.distinguished_name = distinguished_name;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into()?)];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert = cert.pem();
    tracing::info!("Generating self-signed certificate:\n{}", cert);

    Ok((cert.into_bytes(), key_pair.serialize_pem().into_bytes()))
}
