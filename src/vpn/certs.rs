//! TLS configuration for the OpenVPN control channel: CA-based server
//! verification (OpenVPN does not check hostnames), optional
//! remote-cert-tls server, and client certificate authentication.

use super::ovpn::OvpnConfig;
use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;

#[derive(Debug)]
struct OvpnVerifier {
    anchors: Vec<TrustAnchor<'static>>,
    require_server_eku: bool,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

const EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

impl ServerCertVerifier for OvpnVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], _n: &ServerName<'_>, _o: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let ee = webpki::EndEntityCert::try_from(end_entity).map_err(|e| rustls::Error::General(format!("bad server certificate: {e}")))?;
        let usage = if self.require_server_eku { webpki::KeyUsage::server_auth() } else { webpki::KeyUsage::required_if_present(EKU_SERVER_AUTH) };
        ee.verify_for_usage(self.algs.all, &self.anchors, intermediates, now, usage, None, None)
            .map_err(|e| rustls::Error::General(format!("VPN server certificate is not signed by the profile's CA ({e:?})")))?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.algs)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn pem_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut rd = pem.as_bytes();
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd).collect::<Result<_, _>>().context("parsing certificate PEM")?;
    Ok(certs)
}

pub fn tls_config(cfg: &OvpnConfig) -> Result<Arc<rustls::ClientConfig>> {
    let provider = crate::tls::provider();
    let ca = pem_certs(cfg.ca_pem.as_deref().unwrap_or(""))?;
    if ca.is_empty() {
        return Err(anyhow!("no certificates found in the profile's CA"));
    }
    let mut anchors = Vec::new();
    for c in &ca {
        let a = webpki::anchor_from_trusted_cert(c).map_err(|e| anyhow!("unusable CA certificate: {e:?}"))?;
        anchors.push(a.to_owned());
    }
    let verifier = Arc::new(OvpnVerifier { anchors, require_server_eku: cfg.remote_cert_tls_server, algs: provider.signature_verification_algorithms });
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let config = match (&cfg.cert_pem, &cfg.key_pem) {
        (Some(cert), Some(key)) => {
            let mut chain = pem_certs(cert)?;
            if let Some(extra) = &cfg.extra_certs_pem {
                chain.extend(pem_certs(extra)?);
            }
            if key.contains("ENCRYPTED") {
                return Err(anyhow!("the profile's private key is password-protected; export it without a passphrase"));
            }
            let mut rd = key.as_bytes();
            let k = rustls_pemfile::private_key(&mut rd).context("parsing private key")?.ok_or_else(|| anyhow!("no private key found in the profile"))?;
            builder.with_client_auth_cert(chain, k).context("client certificate/key")?
        }
        _ => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

// ---- tiny DER reader to get the subject CN for verify-x509-name -------------

fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if b.len() < 2 {
        return None;
    }
    let tag = b[0];
    let (len, hl) = if b[1] & 0x80 == 0 {
        (b[1] as usize, 2)
    } else {
        let n = (b[1] & 0x7f) as usize;
        if n == 0 || n > 4 || b.len() < 2 + n {
            return None;
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | b[2 + i] as usize;
        }
        (l, 2 + n)
    };
    if b.len() < hl + len {
        return None;
    }
    Some((tag, &b[hl..hl + len], &b[hl + len..]))
}

pub fn subject_cn(der: &[u8]) -> Option<String> {
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut rest = tbs;
    let (tag, _, r) = tlv(rest)?;
    if tag == 0xA0 {
        rest = r; // explicit version
    }
    let (_, _, r) = tlv(rest)?; // serial
    let (_, _, r) = tlv(r)?; // signature alg
    let (_, _, r) = tlv(r)?; // issuer
    let (_, _, r) = tlv(r)?; // validity
    let (_, subject, _) = tlv(r)?;
    let mut sets = subject;
    while let Some((_, set, next)) = tlv(sets) {
        let (_, atv, _) = tlv(set)?;
        let (_, oid, after) = tlv(atv)?;
        if oid == [0x55, 0x04, 0x03] {
            let (_, val, _) = tlv(after)?;
            return Some(String::from_utf8_lossy(val).into_owned());
        }
        sets = next;
    }
    None
}
