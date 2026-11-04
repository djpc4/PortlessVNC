//! Parser for standard OpenVPN client configuration files (.ovpn).

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

#[derive(Clone, Debug)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    pub proto: Proto,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsWrap {
    None,
    /// tls-auth key (256 bytes) and key-direction
    Auth { key: Vec<u8>, direction: Option<u8> },
    /// tls-crypt key (256 bytes)
    Crypt { key: Vec<u8> },
    /// tls-crypt-v2 client key: Kc (256 bytes) + wrapped key WKc
    CryptV2 { key: Vec<u8>, wkc: Vec<u8> },
}

#[derive(Clone, Debug)]
pub enum Proxy {
    Http { host: String, port: u16, auth: Option<(String, String)> },
    Socks { host: String, port: u16 },
}

#[derive(Clone, Debug)]
pub struct OvpnConfig {
    pub remotes: Vec<Remote>,
    pub ca_pem: Option<String>,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub extra_certs_pem: Option<String>,
    pub tls_wrap: TlsWrap,
    pub auth_user_pass: bool,
    /// Credentials stored in the file given to auth-user-pass
    pub auth_file_creds: Option<(String, String)>,
    /// static-challenge "text" echo
    pub static_challenge: Option<(String, bool)>,
    pub cipher: Option<String>,
    pub data_ciphers: Vec<String>,
    pub auth_digest: String,
    pub remote_cert_tls_server: bool,
    pub verify_x509_name: Option<(String, String)>,
    pub reneg_sec: u64,
    pub ping: Option<u64>,
    pub ping_restart: Option<u64>,
    pub compress: Option<String>,
    pub proxy: Option<Proxy>,
    pub tls_version_min: Option<String>,
    pub warnings: Vec<String>,
}

fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    let mut has = false;
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                    }
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    has = true;
                } else if c.is_whitespace() {
                    if has || !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                        has = false;
                    }
                } else if (c == '#' || c == ';') && cur.is_empty() && !has {
                    break;
                } else {
                    cur.push(c);
                }
            }
        }
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Parse a "-----BEGIN OpenVPN Static key V1-----" hex block into 256 bytes.
pub fn parse_static_key(text: &str) -> Result<Vec<u8>> {
    let mut hexs = String::new();
    let mut inside = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("-----BEGIN") {
            inside = true;
            continue;
        }
        if l.starts_with("-----END") {
            break;
        }
        if inside && !l.starts_with('#') {
            hexs.push_str(l);
        }
    }
    let key = hex::decode(hexs.trim()).context("static key: bad hex")?;
    if key.len() != 256 {
        bail!("static key must be 2048 bits (got {} bytes)", key.len());
    }
    Ok(key)
}

fn parse_tls_crypt_v2(text: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    use base64::Engine;
    let mut b64 = String::new();
    let mut inside = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("-----BEGIN") {
            inside = true;
            continue;
        }
        if l.starts_with("-----END") {
            break;
        }
        if inside {
            b64.push_str(l);
        }
    }
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).context("tls-crypt-v2 key: bad base64")?;
    if raw.len() < 256 + 2 {
        bail!("tls-crypt-v2 client key too short");
    }
    Ok((raw[..256].to_vec(), raw[256..].to_vec()))
}

impl OvpnConfig {
    pub fn load(path: &Path) -> Result<OvpnConfig> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let base = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        Self::parse(&text, &base)
    }

    pub fn parse(text: &str, base: &Path) -> Result<OvpnConfig> {
        let mut c = OvpnConfig {
            remotes: Vec::new(),
            ca_pem: None,
            cert_pem: None,
            key_pem: None,
            extra_certs_pem: None,
            tls_wrap: TlsWrap::None,
            auth_user_pass: false,
            auth_file_creds: None,
            static_challenge: None,
            cipher: None,
            data_ciphers: Vec::new(),
            auth_digest: "SHA1".into(),
            remote_cert_tls_server: false,
            verify_x509_name: None,
            reneg_sec: 3600,
            ping: None,
            ping_restart: None,
            compress: None,
            proxy: None,
            tls_version_min: None,
            warnings: Vec::new(),
        };
        let mut default_proto = Proto::Udp;
        let mut default_port: u16 = 1194;
        let mut raw_remotes: Vec<(String, Option<u16>, Option<Proto>)> = Vec::new();
        let mut tls_auth: Option<(String, Option<u8>)> = None;
        let mut key_direction: Option<u8> = None;
        let mut tls_crypt: Option<String> = None;
        let mut tls_crypt_v2: Option<String> = None;
        let mut is_client = false;

        let read_file = |name: &str| -> Result<String> {
            let p = PathBuf::from(name);
            let p = if p.is_absolute() { p } else { base.join(p) };
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))
        };

        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            let l = line.trim();
            // inline blocks: <ca> ... </ca>
            if l.starts_with('<') && l.ends_with('>') && !l.starts_with("</") {
                let tag = &l[1..l.len() - 1];
                let mut body = String::new();
                let end = format!("</{tag}>");
                for bl in lines.by_ref() {
                    if bl.trim() == end {
                        break;
                    }
                    body.push_str(bl);
                    body.push('\n');
                }
                match tag {
                    "ca" => c.ca_pem = Some(body),
                    "cert" => c.cert_pem = Some(body),
                    "key" => c.key_pem = Some(body),
                    "extra-certs" => c.extra_certs_pem = Some(body),
                    "tls-auth" => tls_auth = Some((body, tls_auth.as_ref().and_then(|t| t.1))),
                    "tls-crypt" => tls_crypt = Some(body),
                    "tls-crypt-v2" => tls_crypt_v2 = Some(body),
                    "auth-user-pass" => {
                        let mut it = body.lines();
                        if let (Some(u), Some(p)) = (it.next(), it.next()) {
                            c.auth_file_creds = Some((u.trim().to_string(), p.trim().to_string()));
                        }
                        c.auth_user_pass = true;
                    }
                    "connection" => {
                        for cl in body.lines() {
                            let t = tokenize(cl);
                            if t.first().map(|s| s.as_str()) == Some("remote") && t.len() >= 2 {
                                raw_remotes.push((t[1].clone(), t.get(2).and_then(|p| p.parse().ok()), t.get(3).map(|p| parse_proto(p))));
                            }
                        }
                    }
                    "pkcs12" => bail!("PKCS#12 bundles are not supported; export the profile with inline <ca>/<cert>/<key> instead"),
                    "secret" => bail!("static-key (pre-shared secret) mode is not supported; use a TLS-based profile"),
                    other => c.warnings.push(format!("ignored inline block <{other}>")),
                }
                continue;
            }
            let t = tokenize(l);
            let Some(cmd) = t.first() else { continue };
            let cmd = cmd.trim_start_matches("--");
            let arg = |i: usize| t.get(i).cloned().unwrap_or_default();
            match cmd {
                "client" => is_client = true,
                "tls-client" | "pull" => is_client = true,
                "dev" => {
                    if arg(1).starts_with("tap") {
                        bail!("'dev tap' (layer 2) profiles are not supported; PortlessVNC needs a 'dev tun' profile");
                    }
                }
                "dev-type" => {
                    if arg(1) == "tap" {
                        bail!("'dev-type tap' profiles are not supported");
                    }
                }
                "proto" => default_proto = parse_proto(&arg(1)),
                "port" | "rport" => default_port = arg(1).parse().unwrap_or(1194),
                "remote" => {
                    if t.len() >= 2 {
                        raw_remotes.push((arg(1), t.get(2).and_then(|p| p.parse().ok()), t.get(3).map(|p| parse_proto(p))));
                    }
                }
                "ca" => {
                    if arg(1) != "[inline]" {
                        c.ca_pem = Some(read_file(&arg(1))?)
                    }
                }
                "cert" => {
                    if arg(1) != "[inline]" {
                        c.cert_pem = Some(read_file(&arg(1))?)
                    }
                }
                "key" => {
                    if arg(1) != "[inline]" {
                        c.key_pem = Some(read_file(&arg(1))?)
                    }
                }
                "extra-certs" => {
                    if arg(1) != "[inline]" {
                        c.extra_certs_pem = Some(read_file(&arg(1))?)
                    }
                }
                "tls-auth" => {
                    let dir = t.get(2).and_then(|d| d.parse().ok());
                    if arg(1) == "[inline]" || arg(1).is_empty() {
                        tls_auth = Some((tls_auth.map(|t| t.0).unwrap_or_default(), dir));
                    } else {
                        tls_auth = Some((read_file(&arg(1))?, dir));
                    }
                }
                "key-direction" => key_direction = arg(1).parse().ok(),
                "tls-crypt" => {
                    if arg(1) != "[inline]" && !arg(1).is_empty() {
                        tls_crypt = Some(read_file(&arg(1))?)
                    }
                }
                "tls-crypt-v2" => {
                    if arg(1) != "[inline]" && !arg(1).is_empty() {
                        tls_crypt_v2 = Some(read_file(&arg(1))?)
                    }
                }
                "auth-user-pass" => {
                    c.auth_user_pass = true;
                    let f = arg(1);
                    if !f.is_empty() && f != "[inline]" {
                        if let Ok(s) = read_file(&f) {
                            let mut it = s.lines();
                            if let (Some(u), Some(p)) = (it.next(), it.next()) {
                                c.auth_file_creds = Some((u.trim().to_string(), p.trim().to_string()));
                            }
                        }
                    }
                }
                "static-challenge" => c.static_challenge = Some((arg(1), arg(2) == "1")),
                "cipher" => c.cipher = Some(arg(1).to_uppercase()),
                "data-ciphers" | "ncp-ciphers" => c.data_ciphers = arg(1).split(':').map(|s| s.to_uppercase()).collect(),
                "data-ciphers-fallback" => c.cipher = Some(arg(1).to_uppercase()),
                "auth" => c.auth_digest = arg(1).to_uppercase(),
                "remote-cert-tls" => c.remote_cert_tls_server = arg(1) == "server",
                "ns-cert-type" => c.remote_cert_tls_server = arg(1) == "server",
                "verify-x509-name" => c.verify_x509_name = Some((arg(1), if t.len() > 2 { arg(2) } else { "subject".into() })),
                "reneg-sec" => c.reneg_sec = arg(1).parse().unwrap_or(3600),
                "keepalive" => {
                    c.ping = arg(1).parse().ok();
                    c.ping_restart = arg(2).parse().ok();
                }
                "ping" => c.ping = arg(1).parse().ok(),
                "ping-restart" => c.ping_restart = arg(1).parse().ok(),
                "comp-lzo" => c.compress = Some(format!("comp-lzo {}", arg(1))),
                "compress" => c.compress = Some(format!("compress {}", arg(1))),
                "http-proxy" => {
                    c.proxy = Some(Proxy::Http { host: arg(1), port: arg(2).parse().unwrap_or(8080), auth: None });
                    if t.len() > 3 && arg(3) != "auto" && arg(3) != "auto-nct" {
                        if let Ok(s) = read_file(&arg(3)) {
                            let mut it = s.lines();
                            if let (Some(u), Some(p), Some(Proxy::Http { auth, .. })) = (it.next(), it.next(), c.proxy.as_mut()) {
                                *auth = Some((u.trim().to_string(), p.trim().to_string()));
                            }
                        }
                    }
                }
                "socks-proxy" => c.proxy = Some(Proxy::Socks { host: arg(1), port: arg(2).parse().unwrap_or(1080) }),
                "tls-version-min" => c.tls_version_min = Some(arg(1)),
                "pkcs12" => bail!("PKCS#12 (.p12) files are not supported yet; export the profile with inline certificates (pfSense/OPNsense: \"Inline configuration\")"),
                "cryptoapicert" => bail!("cryptoapicert (Windows certificate store) is not supported"),
                "pkcs11-providers" | "pkcs11-id" => bail!("PKCS#11 smartcards are not supported"),
                "secret" => bail!("static-key (pre-shared secret) mode is not supported; use a TLS-based profile"),
                "askpass" => c.warnings.push("encrypted private keys are not supported".into()),
                // harmless / OS-level directives we deliberately ignore
                "nobind" | "persist-key" | "persist-tun" | "resolv-retry" | "verb" | "mute" | "float" | "lport" | "remote-random" | "setenv" | "block-outside-dns" | "route-method" | "route-delay" | "register-dns" | "redirect-gateway" | "route" | "route-nopull" | "dhcp-option" | "script-security" | "up" | "down" | "auth-nocache" | "tun-mtu" | "mssfix" | "fragment" | "sndbuf" | "rcvbuf" | "explicit-exit-notify" | "tls-cipher" | "tls-ciphersuites" | "push-peer-info" | "allow-compression" | "server-poll-timeout" | "connect-retry" | "connect-retry-max" | "hand-window" | "tls-timeout" | "auth-retry" | "remote-cert-ku" | "remote-cert-eku" | "pull-filter" | "windows-driver" | "ignore-unknown-option" | "tun-ipv6" | "user" | "group" | "mute-replay-warnings" | "replay-window" | "machine-readable-output" | "auth-token-user" | "management" | "management-query-passwords" | "management-hold" | "dev-node" | "ifconfig-nowarn" | "key-method" | "tls-exit" | "topology" => {}
                other => c.warnings.push(format!("ignored directive '{other}'")),
            }
        }
        let _ = is_client;
        for (host, port, proto) in raw_remotes {
            c.remotes.push(Remote { host, port: port.unwrap_or(default_port), proto: proto.unwrap_or(default_proto) });
        }
        if c.remotes.is_empty() {
            bail!("the profile has no 'remote' server");
        }
        if c.ca_pem.is_none() {
            bail!("the profile has no CA certificate (<ca> or 'ca' directive)");
        }
        if c.cert_pem.is_some() != c.key_pem.is_some() {
            bail!("the profile has a client certificate without a key (or vice versa)");
        }
        if c.cert_pem.is_none() && !c.auth_user_pass {
            bail!("the profile has neither a client certificate nor auth-user-pass");
        }
        c.tls_wrap = if let Some(v2) = tls_crypt_v2 {
            let (key, wkc) = parse_tls_crypt_v2(&v2)?;
            TlsWrap::CryptV2 { key, wkc }
        } else if let Some(tc) = tls_crypt {
            TlsWrap::Crypt { key: parse_static_key(&tc)? }
        } else if let Some((ta, dir)) = tls_auth {
            if ta.trim().is_empty() {
                return Err(anyhow!("tls-auth key is empty"));
            }
            TlsWrap::Auth { key: parse_static_key(&ta)?, direction: dir.or(key_direction) }
        } else {
            TlsWrap::None
        };
        Ok(c)
    }
}

fn parse_proto(p: &str) -> Proto {
    if p.to_ascii_lowercase().starts_with("tcp") { Proto::Tcp } else { Proto::Udp }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokenizer_quotes() {
        assert_eq!(tokenize(r#"static-challenge "Enter OTP" 1"#), vec!["static-challenge", "Enter OTP", "1"]);
        assert_eq!(tokenize("remote vpn.example.com 1194 udp # c"), vec!["remote", "vpn.example.com", "1194", "udp"]);
    }
}
