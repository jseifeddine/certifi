use anyhow::Result;
use rand::Rng;

pub fn generate_pfx_password() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

pub fn build_pfx(
    fullchain_pem: &str,
    privkey_pem: &str,
    password: &str,
    friendly_name: &str,
) -> Result<Vec<u8>> {
    use crate::services::acme::pem_to_der;

    // Parse certs from fullchain PEM
    const MARKER: &str = "-----BEGIN CERTIFICATE-----";
    let positions: Vec<usize> = fullchain_pem
        .match_indices(MARKER)
        .map(|(i, _)| i)
        .collect();

    if positions.is_empty() {
        anyhow::bail!("No certificates found in fullchain PEM");
    }

    // Boundaries for each cert
    let mut cert_pems: Vec<&str> = Vec::new();
    for (idx, &start) in positions.iter().enumerate() {
        let end = positions
            .get(idx + 1)
            .copied()
            .unwrap_or(fullchain_pem.len());
        cert_pems.push(&fullchain_pem[start..end]);
    }

    let leaf_der = pem_to_der(cert_pems[0]);
    let key_der = pem_to_der(privkey_pem);

    let ca_der: Option<Vec<u8>> = cert_pems.get(1).map(|p| pem_to_der(p));
    let ca_opt: Option<&[u8]> = ca_der.as_deref();

    let pfx = p12::PFX::new(&leaf_der, &key_der, ca_opt, password, friendly_name)
        .ok_or_else(|| anyhow::anyhow!("Failed to build PFX (invalid cert or key?)"))?;

    Ok(pfx.to_der())
}

pub fn parse_cert_expiry(cert_pem: &str) -> Option<String> {
    crate::services::acme::cert_expiry_from_pem(cert_pem)
}
