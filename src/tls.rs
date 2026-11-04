//! TLS for VNC sessions (VeNCrypt X509*): an automatically generated
//! self-signed server certificate, and fingerprint pinning (trust on first
//! use) on the viewer side. Nothing for the user to generate by hand.
//!
//! Also provides `split()`, which turns a TCP or TLS connection into
//! independent reader/writer halves usable from different threads.

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub struct ServerIdentity {
    pub cert: CertificateDer<'static>,
    pub key: Vec<u8>,
    pub fingerprint: String,
}

/// Load (or create on first run) the server's certificate.
pub fn load_or_create_identity(dir: &Path) -> Result<ServerIdentity> {
    let cert_path = dir.join("server-cert.der");
    let key_path = dir.join("server-key.der");
    let (cert, key) = match (std::fs::read(&cert_path), std::fs::read(&key_path)) {
        (Ok(c), Ok(k)) => (c, k),
        _ => {
            let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "portless".into());
            let ck = rcgen::generate_simple_self_signed(vec![host, "PortlessVNC".into()]).context("generate certificate")?;
            let c = ck.cert.der().to_vec();
            let k = ck.key_pair.serialize_der();
            std::fs::create_dir_all(dir)?;
            std::fs::write(&cert_path, &c)?;
            std::fs::write(&key_path, &k)?;
            (c, k)
        }
    };
    let fingerprint = crate::util::sha256_hex(&cert);
    Ok(ServerIdentity { cert: CertificateDer::from(cert), key, fingerprint })
}

pub fn server_config(id: &ServerIdentity) -> Result<Arc<rustls::ServerConfig>> {
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![id.cert.clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.clone())))?;
    Ok(Arc::new(cfg))
}

/// Accepts any certificate but remembers it, so the caller can compare its
/// fingerprint with the pinned one before sending any credentials.
#[derive(Debug)]
pub struct RecordingVerifier {
    pub seen: Mutex<Option<Vec<u8>>>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl RecordingVerifier {
    pub fn new() -> Arc<Self> {
        Arc::new(RecordingVerifier { seen: Mutex::new(None), algs: provider().signature_verification_algorithms })
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _i: &[CertificateDer<'_>], _n: &ServerName<'_>, _o: &[u8], _now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock() = Some(end_entity.to_vec());
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

pub fn viewer_config(v: Arc<RecordingVerifier>) -> Result<Arc<rustls::ClientConfig>> {
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(v)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

// ---- stream splitting ------------------------------------------------------

pub struct TlsShared {
    conn: Mutex<rustls::Connection>,
    /// TLS bytes read from the socket but not yet accepted by rustls
    pending: Mutex<Vec<u8>>,
    tcp: TcpStream,
}

pub enum Transport {
    Plain(TcpStream),
    Tls(Arc<TlsShared>),
}

impl Transport {
    /// Run a TLS handshake over `tcp` (blocking) and wrap it.
    pub fn handshake(mut conn: rustls::Connection, mut tcp: TcpStream) -> io::Result<Transport> {
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp)?;
        }
        while conn.wants_write() {
            conn.write_tls(&mut tcp)?;
        }
        Ok(Transport::Tls(Arc::new(TlsShared { conn: Mutex::new(conn), pending: Mutex::new(Vec::new()), tcp })))
    }

    pub fn tcp(&self) -> &TcpStream {
        match self {
            Transport::Plain(t) => t,
            Transport::Tls(s) => &s.tcp,
        }
    }

    pub fn split(&self) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        match self {
            Transport::Plain(t) => Ok((Box::new(t.try_clone()?), Box::new(t.try_clone()?))),
            Transport::Tls(s) => Ok((
                Box::new(TlsReader { s: s.clone(), tcp: s.tcp.try_clone()?, buf: vec![0u8; 32 * 1024] }),
                Box::new(TlsWriter { s: s.clone(), tcp: s.tcp.try_clone()? }),
            )),
        }
    }

    pub fn shutdown(&self) {
        let _ = self.tcp().shutdown(std::net::Shutdown::Both);
    }
}

struct TlsReader {
    s: Arc<TlsShared>,
    tcp: TcpStream,
    buf: Vec<u8>,
}

impl Read for TlsReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            {
                let mut c = self.s.conn.lock();
                match c.reader().read(out) {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
                // Feed buffered TLS bytes a little at a time: rustls refuses
                // more input while its (small) plaintext buffer is full.
                let mut pending = self.s.pending.lock();
                if !pending.is_empty() {
                    let mut rd = &pending[..];
                    let before = rd.len();
                    c.read_tls(&mut rd)?;
                    let used = before - rd.len();
                    pending.drain(..used);
                    drop(pending);
                    c.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    while c.wants_write() {
                        c.write_tls(&mut self.tcp)?;
                    }
                    continue;
                }
            }
            let n = self.tcp.read(&mut self.buf)?;
            if n == 0 {
                return Ok(0);
            }
            self.s.pending.lock().extend_from_slice(&self.buf[..n]);
        }
    }
}

struct TlsWriter {
    s: Arc<TlsShared>,
    tcp: TcpStream,
}

impl Write for TlsWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // rustls buffers at most ~64 KB of plaintext, so push large writes
        // through in pieces, flushing each one to the socket.
        let mut c = self.s.conn.lock();
        let mut off = 0;
        while off < data.len() {
            let n = c.writer().write(&data[off..])?;
            off += n;
            let flushed = c.wants_write();
            while c.wants_write() {
                c.write_tls(&mut self.tcp)?;
            }
            if n == 0 && !flushed {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "TLS connection closed"));
            }
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A plain-TCP stream wrapper that can run a TLS handshake mid-stream
/// (VeNCrypt starts in the clear, then upgrades).
pub fn tls_server(cfg: Arc<rustls::ServerConfig>, tcp: TcpStream) -> io::Result<Transport> {
    let conn = rustls::ServerConnection::new(cfg).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Transport::handshake(rustls::Connection::Server(conn), tcp)
}

pub fn tls_client(cfg: Arc<rustls::ClientConfig>, tcp: TcpStream) -> io::Result<Transport> {
    let name = ServerName::try_from("portless-vnc").unwrap().to_owned();
    let conn = rustls::ClientConnection::new(cfg, name).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Transport::handshake(rustls::Connection::Client(conn), tcp)
}

/// Read/Write over a not-yet-split transport (used during the RFB handshake).
pub struct HandshakeIo<'a>(pub &'a Transport);

impl Read for HandshakeIo<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self.0 {
            Transport::Plain(t) => (&*t).read(out),
            Transport::Tls(s) => {
                let mut r = TlsReader { s: s.clone(), tcp: s.tcp.try_clone()?, buf: vec![0u8; 16 * 1024] };
                r.read(out)
            }
        }
    }
}

impl Write for HandshakeIo<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self.0 {
            Transport::Plain(t) => (&*t).write(data),
            Transport::Tls(s) => TlsWriter { s: s.clone(), tcp: s.tcp.try_clone()? }.write(data),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
