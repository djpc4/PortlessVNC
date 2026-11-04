//! Sans-I/O OpenVPN client protocol engine (OpenVPN 2.4+ compatible).
//!
//! Feed it received wire packets with `on_packet`, IP packets to tunnel with
//! `send_ip`, call `tick` periodically, and drain `out` (wire packets) and
//! `events`.

use super::crypto::{self, CipherKind, DataChannel, Digest, Wrap};
use super::ovpn::{OvpnConfig, TlsWrap};
use anyhow::{anyhow, bail, Result};
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const P_CONTROL_HARD_RESET_CLIENT_V1: u8 = 1;
pub const P_CONTROL_HARD_RESET_SERVER_V1: u8 = 2;
pub const P_CONTROL_SOFT_RESET_V1: u8 = 3;
pub const P_CONTROL_V1: u8 = 4;
pub const P_ACK_V1: u8 = 5;
pub const P_DATA_V1: u8 = 6;
pub const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
pub const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
pub const P_DATA_V2: u8 = 9;
pub const P_CONTROL_HARD_RESET_CLIENT_V3: u8 = 10;

const PING_MAGIC: [u8; 16] = [0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48];
const OCC_MAGIC: [u8; 16] = [0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c];
const OCC_EXIT: u8 = 6;
const CONTROL_CHUNK: usize = 1100;
const SEND_WINDOW: usize = 6;

#[derive(Clone, Debug, Default)]
pub struct PushInfo {
    pub ip: Option<Ipv4Addr>,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub routes: Vec<(Ipv4Addr, u8)>,
    pub ping: Option<u64>,
    pub ping_restart: Option<u64>,
    pub peer_id: Option<u32>,
    pub cipher: Option<String>,
    pub auth: Option<String>,
    pub ekm: bool,
    pub compress: Option<String>,
    pub mtu: u16,
    pub topology_subnet: bool,
    pub auth_token: Option<String>,
    pub redirect_gateway: bool,
}

#[derive(Debug)]
pub enum Event {
    Connected(PushInfo, String),
    Ip(Vec<u8>),
    AuthFailed(String),
    Challenge { state_id: String, user: String, text: String, echo: bool },
    Restart(String),
    Fatal(String),
    Info(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Comp {
    None,
    Stub,  // 0xFA "no compression" prefix byte (comp-lzo)
    Swap,  // 0xFB with first byte swapped to the end (compress / lz4 v1)
    V2,    // compression framing v2 (stub-v2 / lz4-v2)
}

struct Unacked {
    opcode: u8,
    payload: Vec<u8>,
    sent: Instant,
    tries: u32,
}

struct KeyState {
    id: u8,
    tls: rustls::ClientConnection,
    reset_opcode: u8,
    send_next: u32,
    unacked: BTreeMap<u32, Unacked>,
    send_queue: VecDeque<(u8, Vec<u8>)>,
    recv_next: u32,
    recv_buf: BTreeMap<u32, (u8, Vec<u8>)>,
    acks: Vec<u32>,
    tls_started: bool,
    km_sent: bool,
    plain: Vec<u8>,
    server_rand: Option<([u8; 32], [u8; 32])>,
    pre_master: [u8; 48],
    rand1: [u8; 32],
    rand2: [u8; 32],
    data: Option<DataChannel>,
    created: Instant,
    active_since: Option<Instant>,
}

impl KeyState {
    fn new(id: u8, tls_cfg: &Arc<rustls::ClientConfig>, reset_opcode: u8) -> Result<KeyState> {
        let name = rustls::pki_types::ServerName::try_from("openvpn-server").unwrap().to_owned();
        let tls = rustls::ClientConnection::new(tls_cfg.clone(), name)?;
        let mut pre_master = [0u8; 48];
        let mut rand1 = [0u8; 32];
        let mut rand2 = [0u8; 32];
        let mut r = rand::thread_rng();
        rand::Rng::fill(&mut r, &mut pre_master[..]);
        rand::Rng::fill(&mut r, &mut rand1);
        rand::Rng::fill(&mut r, &mut rand2);
        let mut k = KeyState {
            id,
            tls,
            reset_opcode,
            send_next: 0,
            unacked: BTreeMap::new(),
            send_queue: VecDeque::new(),
            recv_next: 0,
            recv_buf: BTreeMap::new(),
            acks: Vec::new(),
            tls_started: false,
            km_sent: false,
            plain: Vec::new(),
            server_rand: None,
            pre_master,
            rand1,
            rand2,
            data: None,
            created: Instant::now(),
            active_since: None,
        };
        k.send_queue.push_back((reset_opcode, Vec::new()));
        Ok(k)
    }
}

pub struct Engine {
    cfg: Arc<OvpnConfig>,
    user: Option<String>,
    pass: Option<String>,
    wrap: Wrap,
    wkc: Option<Vec<u8>>,
    tls_cfg: Arc<rustls::ClientConfig>,
    pub local_sid: [u8; 8],
    remote_sid: Option<[u8; 8]>,
    keys: Vec<KeyState>,
    next_key_id: u8,
    pub out: VecDeque<Vec<u8>>,
    pub events: VecDeque<Event>,
    push_acc: String,
    pushed: Option<PushInfo>,
    push_req_at: Option<Instant>,
    push_tries: u32,
    cipher: Option<(CipherKind, Digest, bool)>,
    peer_id: Option<u32>,
    comp: Comp,
    started: Instant,
    last_rx: Instant,
    last_tx: Instant,
    ping_every: Duration,
    ping_restart: Duration,
    auth_token: Option<String>,
    warned_compressed: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

fn write_string(b: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    b.extend_from_slice(&((bytes.len() + 1) as u16).to_be_bytes());
    b.extend_from_slice(bytes);
    b.push(0);
}

impl Engine {
    pub fn new(cfg: Arc<OvpnConfig>, tls_cfg: Arc<rustls::ClientConfig>, user: Option<String>, pass: Option<String>) -> Result<Engine> {
        let digest = Digest::parse(&cfg.auth_digest).unwrap_or(Digest::Sha1);
        let (wrap, wkc, reset_op) = match &cfg.tls_wrap {
            TlsWrap::None => (Wrap::None, None, P_CONTROL_HARD_RESET_CLIENT_V2),
            TlsWrap::Auth { key, direction } => (Wrap::tls_auth(key, digest, *direction), None, P_CONTROL_HARD_RESET_CLIENT_V2),
            TlsWrap::Crypt { key } => (Wrap::tls_crypt(key), None, P_CONTROL_HARD_RESET_CLIENT_V2),
            TlsWrap::CryptV2 { key, wkc } => (Wrap::tls_crypt(key), Some(wkc.clone()), P_CONTROL_HARD_RESET_CLIENT_V3),
        };
        let mut sid = [0u8; 8];
        rand::Rng::fill(&mut rand::thread_rng(), &mut sid);
        let k0 = KeyState::new(0, &tls_cfg, reset_op)?;
        let now = Instant::now();
        let mut e = Engine {
            ping_every: Duration::from_secs(cfg.ping.unwrap_or(10)),
            ping_restart: Duration::from_secs(cfg.ping_restart.unwrap_or(60).min(60)),
            cfg,
            user,
            pass,
            wrap,
            wkc,
            tls_cfg,
            local_sid: sid,
            remote_sid: None,
            keys: vec![k0],
            next_key_id: 1,
            out: VecDeque::new(),
            events: VecDeque::new(),
            push_acc: String::new(),
            pushed: None,
            push_req_at: None,
            push_tries: 0,
            cipher: None,
            peer_id: None,
            comp: Comp::None,
            started: now,
            last_rx: now,
            last_tx: now,
            auth_token: None,
            warned_compressed: false,
            bytes_in: 0,
            bytes_out: 0,
        };
        e.flush_all();
        Ok(e)
    }

    pub fn is_connected(&self) -> bool {
        self.pushed.is_some()
    }

    // ---- control channel ------------------------------------------------------

    fn send_control(&mut self, ki: usize, opcode: u8, msg_id: Option<u32>) {
        let k = &mut self.keys[ki];
        let mut rest = Vec::with_capacity(64);
        let n = k.acks.len().min(4);
        let acks: Vec<u32> = k.acks.drain(..n).collect();
        rest.push(acks.len() as u8);
        for a in &acks {
            rest.extend_from_slice(&a.to_be_bytes());
        }
        if !acks.is_empty() {
            rest.extend_from_slice(&self.remote_sid.unwrap_or_default());
        }
        if let Some(id) = msg_id {
            rest.extend_from_slice(&id.to_be_bytes());
            if let Some(u) = k.unacked.get(&id) {
                rest.extend_from_slice(&u.payload);
            }
        }
        let op = (opcode << 3) | k.id;
        let mut pkt = self.wrap.wrap(op, &self.local_sid, &rest);
        if opcode == P_CONTROL_HARD_RESET_CLIENT_V3 {
            if let Some(w) = &self.wkc {
                pkt.extend_from_slice(w);
            }
        }
        self.out.push_back(pkt);
    }

    fn flush_key(&mut self, ki: usize) {
        loop {
            let k = &mut self.keys[ki];
            if k.unacked.len() >= SEND_WINDOW {
                break;
            }
            let Some((opcode, payload)) = k.send_queue.pop_front() else { break };
            let id = k.send_next;
            k.send_next += 1;
            k.unacked.insert(id, Unacked { opcode, payload, sent: Instant::now(), tries: 1 });
            self.send_control(ki, opcode, Some(id));
        }
        while !self.keys[ki].acks.is_empty() {
            self.send_control(ki, P_ACK_V1, None);
        }
    }

    fn flush_all(&mut self) {
        for i in 0..self.keys.len() {
            self.flush_key(i);
        }
    }

    fn key_index(&self, id: u8) -> Option<usize> {
        self.keys.iter().position(|k| k.id == id)
    }

    pub fn on_packet(&mut self, pkt: &[u8]) {
        if pkt.is_empty() {
            return;
        }
        let opcode = pkt[0] >> 3;
        let key_id = pkt[0] & 7;
        if opcode == P_DATA_V1 || opcode == P_DATA_V2 {
            self.on_data(pkt, opcode, key_id);
            return;
        }
        let Some((_op, sid, rest)) = self.wrap.unwrap(pkt) else {
            log::debug!("vpn: dropped control packet that failed authentication");
            return;
        };
        match self.remote_sid {
            None if opcode == P_CONTROL_HARD_RESET_SERVER_V2 => self.remote_sid = Some(sid),
            Some(r) if r == sid => {}
            _ => return,
        }
        self.last_rx = Instant::now();
        let mut c = crate::rfb::Cur::new(&rest);
        let Ok(n) = c.u8() else { return };
        let mut acks = Vec::new();
        for _ in 0..n {
            match c.u32() {
                Ok(a) => acks.push(a),
                Err(_) => return,
            }
        }
        if n > 0 && c.take(8).is_err() {
            return;
        }
        let ki = match self.key_index(key_id) {
            Some(i) => i,
            None if opcode == P_CONTROL_SOFT_RESET_V1 => {
                // server-initiated renegotiation
                match KeyState::new(key_id, &self.tls_cfg, P_CONTROL_SOFT_RESET_V1) {
                    Ok(k) => {
                        log::info!("VPN: server started key renegotiation (key {key_id})");
                        self.keys.push(k);
                        self.next_key_id = next_id(key_id);
                        self.keys.len() - 1
                    }
                    Err(_) => return,
                }
            }
            None => return,
        };
        for a in acks {
            self.keys[ki].unacked.remove(&a);
        }
        if opcode != P_ACK_V1 {
            let Ok(id) = c.u32() else { return };
            let payload = c.rest().to_vec();
            let k = &mut self.keys[ki];
            k.acks.push(id);
            if id >= k.recv_next {
                k.recv_buf.insert(id, (opcode, payload));
            }
            while let Some((op, p)) = {
                let k = &mut self.keys[ki];
                let next = k.recv_next;
                k.recv_buf.remove(&next)
            } {
                self.keys[ki].recv_next += 1;
                self.on_control_payload(ki, op, p);
                if ki >= self.keys.len() {
                    return;
                }
            }
        }
        self.flush_key(ki);
    }

    fn on_control_payload(&mut self, ki: usize, opcode: u8, payload: Vec<u8>) {
        match opcode {
            P_CONTROL_HARD_RESET_SERVER_V2 | P_CONTROL_SOFT_RESET_V1 => {
                if !self.keys[ki].tls_started {
                    self.keys[ki].tls_started = true;
                    self.drive_tls(ki);
                }
            }
            P_CONTROL_V1 => {
                let res = {
                    let k = &mut self.keys[ki];
                    let mut rd = &payload[..];
                    let mut r = Ok(());
                    while !rd.is_empty() {
                        if let Err(e) = k.tls.read_tls(&mut rd) {
                            r = Err(e.to_string());
                            break;
                        }
                        if let Err(e) = k.tls.process_new_packets() {
                            r = Err(e.to_string());
                            break;
                        }
                    }
                    r
                };
                if let Err(e) = res {
                    self.events.push_back(Event::Fatal(format!("TLS error with VPN server: {e}")));
                    return;
                }
                self.drive_tls(ki);
            }
            P_CONTROL_HARD_RESET_SERVER_V1 | P_CONTROL_HARD_RESET_CLIENT_V1 => {
                self.events.push_back(Event::Fatal("server only speaks the obsolete key-method 1".into()));
            }
            _ => {}
        }
    }

    fn queue_tls_output(&mut self, ki: usize) {
        let k = &mut self.keys[ki];
        while k.tls.wants_write() {
            let mut buf = Vec::new();
            if k.tls.write_tls(&mut buf).is_err() {
                break;
            }
            for chunk in buf.chunks(CONTROL_CHUNK) {
                k.send_queue.push_back((P_CONTROL_V1, chunk.to_vec()));
            }
        }
    }

    fn key_method_2(&self, ki: usize) -> Vec<u8> {
        let k = &self.keys[ki];
        let mut b = Vec::with_capacity(512);
        b.extend_from_slice(&[0, 0, 0, 0, 2]);
        b.extend_from_slice(&k.pre_master);
        b.extend_from_slice(&k.rand1);
        b.extend_from_slice(&k.rand2);
        let cipher = self.cfg.cipher.clone().unwrap_or_else(|| "AES-256-GCM".into());
        write_string(&mut b, &format!("V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto UDPv4,cipher {cipher},auth {},keysize 256,key-method 2,tls-client", self.cfg.auth_digest));
        if self.cfg.auth_user_pass {
            let pass = self.auth_token.clone().or_else(|| self.pass.clone()).unwrap_or_default();
            write_string(&mut b, self.user.as_deref().unwrap_or(""));
            write_string(&mut b, &pass);
        } else {
            b.extend_from_slice(&[0, 0, 0, 0]);
        }
        let mut ciphers: Vec<String> = if self.cfg.data_ciphers.is_empty() {
            vec!["AES-256-GCM".into(), "AES-128-GCM".into(), "CHACHA20-POLY1305".into()]
        } else {
            self.cfg.data_ciphers.iter().filter(|c| CipherKind::parse(c).is_some()).cloned().collect()
        };
        if let Some(c) = &self.cfg.cipher {
            if CipherKind::parse(c).is_some() && !ciphers.contains(c) {
                ciphers.push(c.clone());
            }
        }
        let peer_info = format!(
            "IV_VER=2.6.12\nIV_PLAT=win\nIV_PROTO=10\nIV_NCP=2\nIV_CIPHERS={}\nIV_TCPNL=1\nIV_GUI_VER=PortlessVNC_{}\n",
            ciphers.join(":"),
            env!("CARGO_PKG_VERSION")
        );
        write_string(&mut b, &peer_info);
        b
    }

    fn drive_tls(&mut self, ki: usize) {
        self.queue_tls_output(ki);
        if !self.keys[ki].tls.is_handshaking() && !self.keys[ki].km_sent {
            if let Err(e) = self.verify_server_identity(ki) {
                self.events.push_back(Event::Fatal(e.to_string()));
                return;
            }
            let km = self.key_method_2(ki);
            let k = &mut self.keys[ki];
            k.km_sent = true;
            let _ = k.tls.writer().write_all(&km);
            self.queue_tls_output(ki);
        }
        // plaintext from the server
        let mut tmp = [0u8; 4096];
        loop {
            match self.keys[ki].tls.reader().read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => self.keys[ki].plain.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        if self.keys[ki].km_sent && self.keys[ki].server_rand.is_none() {
            let p = &self.keys[ki].plain;
            if p.len() >= 5 + 64 + 2 {
                if p[..4] != [0, 0, 0, 0] || p[4] & 0x0F != 2 {
                    self.events.push_back(Event::Fatal("unexpected key exchange message from server".into()));
                    return;
                }
                let mut r1 = [0u8; 32];
                let mut r2 = [0u8; 32];
                r1.copy_from_slice(&p[5..37]);
                r2.copy_from_slice(&p[37..69]);
                let k = &mut self.keys[ki];
                k.server_rand = Some((r1, r2));
                k.plain.clear(); // the rest of this message (options, peer info) is informational
                if self.pushed.is_none() {
                    self.send_push_request(ki);
                } else if let Some((kind, digest, ekm)) = self.cipher {
                    // renegotiation: derive new keys with the negotiated cipher
                    if let Err(e) = self.derive_keys(ki, kind, digest, ekm) {
                        self.events.push_back(Event::Fatal(e.to_string()));
                    } else {
                        log::info!("VPN: key renegotiation complete");
                    }
                }
            }
        } else if self.keys[ki].server_rand.is_some() {
            self.process_control_messages(ki);
        }
        self.queue_tls_output(ki);
    }

    fn verify_server_identity(&self, ki: usize) -> Result<()> {
        let certs = self.keys[ki].tls.peer_certificates().ok_or_else(|| anyhow!("VPN server sent no certificate"))?;
        let leaf = certs.first().ok_or_else(|| anyhow!("VPN server sent no certificate"))?;
        if let Some((name, kind)) = &self.cfg.verify_x509_name {
            let cn = super::certs::subject_cn(leaf.as_ref()).unwrap_or_default();
            let ok = match kind.as_str() {
                "name" => &cn == name,
                "name-prefix" => cn.starts_with(name.as_str()),
                _ => name.contains(&format!("CN={cn}")) || name == &cn,
            };
            if !ok {
                bail!("VPN server certificate name '{cn}' does not match verify-x509-name '{name}'");
            }
        }
        Ok(())
    }

    fn send_push_request(&mut self, ki: usize) {
        let k = &mut self.keys[ki];
        let _ = k.tls.writer().write_all(b"PUSH_REQUEST\0");
        self.push_req_at = Some(Instant::now());
        self.push_tries += 1;
        self.queue_tls_output(ki);
    }

    fn process_control_messages(&mut self, ki: usize) {
        loop {
            let pos = match self.keys[ki].plain.iter().position(|&b| b == 0) {
                Some(p) => p,
                None => break,
            };
            let msg: Vec<u8> = self.keys[ki].plain.drain(..=pos).collect();
            let s = String::from_utf8_lossy(&msg[..msg.len() - 1]).trim().to_string();
            if s.is_empty() {
                continue;
            }
            self.on_control_message(ki, &s);
        }
    }

    fn on_control_message(&mut self, ki: usize, s: &str) {
        if let Some(rest) = s.strip_prefix("PUSH_REPLY") {
            if self.pushed.is_some() {
                return;
            }
            let rest = rest.trim_start_matches(',');
            if !self.push_acc.is_empty() {
                self.push_acc.push(',');
            }
            self.push_acc.push_str(rest);
            if rest.contains("push-continuation 2") {
                return; // more to come
            }
            let all = std::mem::take(&mut self.push_acc);
            match self.apply_push(ki, &all) {
                Ok(info) => {
                    let summary = format!("{}", self.cipher.map(|c| c.0.name()).unwrap_or("?"));
                    self.pushed = Some(info.clone());
                    self.events.push_back(Event::Connected(info, summary));
                }
                Err(e) => self.events.push_back(Event::Fatal(e.to_string())),
            }
        } else if let Some(r) = s.strip_prefix("AUTH_FAILED") {
            let r = r.trim_start_matches(',');
            if let Some(crv) = r.strip_prefix("CRV1:") {
                // CRV1:<flags>:<state_id>:<username_base64>:<challenge text>
                let parts: Vec<&str> = crv.splitn(4, ':').collect();
                if parts.len() == 4 {
                    use base64::Engine as _;
                    let user = base64::engine::general_purpose::STANDARD.decode(parts[2]).ok().map(|v| String::from_utf8_lossy(&v).into_owned()).unwrap_or_default();
                    self.events.push_back(Event::Challenge { state_id: parts[1].to_string(), user, text: parts[3].to_string(), echo: parts[0].contains('E') });
                    return;
                }
            }
            self.events.push_back(Event::AuthFailed(if r.is_empty() { "Authentication failed".into() } else { r.to_string() }));
        } else if s.starts_with("RESTART") {
            self.events.push_back(Event::Restart(format!("server requested restart ({s})")));
        } else if s.starts_with("HALT") {
            self.events.push_back(Event::Fatal(format!("server halted the connection ({s})")));
        } else if s.starts_with("AUTH_PENDING") {
            self.events.push_back(Event::Info("Waiting for the VPN server to approve the login (pending authentication)...".into()));
        } else if let Some(i) = s.strip_prefix("INFO_PRE,").or_else(|| s.strip_prefix("INFO,")) {
            self.events.push_back(Event::Info(i.to_string()));
        } else {
            log::debug!("vpn control message: {s}");
        }
    }

    fn apply_push(&mut self, ki: usize, opts: &str) -> Result<PushInfo> {
        let mut info = PushInfo { prefix: 24, mtu: 1500, ..Default::default() };
        let mut ifconfig: Option<(Ipv4Addr, String)> = None;
        for opt in opts.split(',') {
            let t: Vec<&str> = opt.split_whitespace().collect();
            let Some(&cmd) = t.first() else { continue };
            let a = |i: usize| t.get(i).copied().unwrap_or("");
            match cmd {
                "ifconfig" => {
                    if let Ok(ip) = a(1).parse() {
                        ifconfig = Some((ip, a(2).to_string()));
                    }
                }
                "route-gateway" => info.gateway = a(1).parse().ok(),
                "route" => {
                    if let Ok(net) = a(1).parse::<Ipv4Addr>() {
                        let mask: Ipv4Addr = a(2).parse().unwrap_or(Ipv4Addr::new(255, 255, 255, 255));
                        info.routes.push((net, u32::from(mask).count_ones() as u8));
                    }
                }
                "topology" => info.topology_subnet = a(1) == "subnet",
                "ping" => info.ping = a(1).parse().ok(),
                "ping-restart" => info.ping_restart = a(1).parse().ok(),
                "peer-id" => info.peer_id = a(1).parse().ok(),
                "cipher" => info.cipher = Some(a(1).to_uppercase()),
                "auth" => info.auth = Some(a(1).to_uppercase()),
                "key-derivation" => info.ekm |= a(1) == "tls-ekm",
                "protocol-flags" => info.ekm |= t.iter().any(|f| *f == "tls-ekm"),
                "comp-lzo" | "compress" => info.compress = Some(t.join(" ")),
                "tun-mtu" => info.mtu = a(1).parse().unwrap_or(1500),
                "auth-token" => info.auth_token = Some(a(1).to_string()),
                "redirect-gateway" => info.redirect_gateway = true,
                _ => {}
            }
        }
        let (ip, second) = ifconfig.ok_or_else(|| anyhow!("the VPN server did not assign an IPv4 address (no 'ifconfig' pushed)"))?;
        info.ip = Some(ip);
        let second_ip: Option<Ipv4Addr> = second.parse().ok();
        let is_mask = second_ip.map(|m| {
            let v = u32::from(m);
            v != 0 && v.leading_ones() + v.trailing_zeros() == 32 && (v >> 24) == 255
        });
        if is_mask == Some(true) {
            info.prefix = u32::from(second_ip.unwrap()).count_ones() as u8;
            info.topology_subnet = true;
        } else {
            // net30 / p2p: second address is the point-to-point peer
            info.prefix = 30;
            if info.gateway.is_none() {
                info.gateway = second_ip;
            }
        }
        if info.gateway.is_none() {
            let net = u32::from(ip) & (u32::MAX << (32 - info.prefix as u32));
            info.gateway = Some(Ipv4Addr::from(net + 1));
        }
        // cipher negotiation
        let cipher_name = info.cipher.clone().or_else(|| self.cfg.cipher.clone()).unwrap_or_else(|| "BF-CBC".into());
        let kind = crypto::check_supported(&cipher_name)?;
        let digest_name = info.auth.clone().unwrap_or_else(|| self.cfg.auth_digest.clone());
        let digest = Digest::parse(&digest_name).ok_or_else(|| anyhow!("unsupported auth digest {digest_name}"))?;
        self.cipher = Some((kind, digest, info.ekm));
        self.peer_id = info.peer_id;
        self.comp = match info.compress.as_deref().or(self.cfg.compress.as_deref()) {
            None => Comp::None,
            Some(c) if c.contains("stub-v2") || c.contains("lz4-v2") || c.contains("migrate") => Comp::V2,
            Some(c) if c.starts_with("comp-lzo") => Comp::Stub,
            Some(c) if c.trim() == "compress" || c.contains("stub") || c.contains("lz4") => Comp::Swap,
            Some(c) if c.contains("lzo") => Comp::Stub,
            Some(_) => Comp::None,
        };
        if let Some(p) = info.ping {
            self.ping_every = Duration::from_secs(p.max(1));
        }
        if let Some(p) = info.ping_restart {
            // never wait longer than a minute to notice a dead link
            self.ping_restart = Duration::from_secs(p.clamp(5, 60));
        }
        if info.auth_token.is_some() {
            self.auth_token = info.auth_token.clone();
        }
        self.derive_keys(ki, kind, digest, info.ekm)?;
        Ok(info)
    }

    fn derive_keys(&mut self, ki: usize, kind: CipherKind, digest: Digest, ekm: bool) -> Result<()> {
        let remote_sid = self.remote_sid.ok_or_else(|| anyhow!("no server session"))?;
        let k = &mut self.keys[ki];
        let (sr1, sr2) = k.server_rand.ok_or_else(|| anyhow!("key exchange incomplete"))?;
        let block = if ekm {
            k.tls.export_keying_material(vec![0u8; 256], b"EXPORTER-OpenVPN-datakeys", None).map_err(|e| anyhow!("TLS key export failed: {e}"))?
        } else {
            crypto::openvpn_prf_keys(&k.pre_master, &k.rand1, &sr1, &k.rand2, &sr2, &self.local_sid, &remote_sid)
        };
        k.data = Some(DataChannel::new(kind, digest, &block));
        k.active_since = Some(Instant::now());
        Ok(())
    }

    // ---- data channel ---------------------------------------------------------

    fn send_key(&self) -> Option<usize> {
        self.keys.iter().enumerate().filter(|(_, k)| k.data.is_some()).max_by_key(|(_, k)| k.active_since).map(|(i, _)| i)
    }

    fn frame(&self, ip: &[u8]) -> Vec<u8> {
        match self.comp {
            Comp::None => ip.to_vec(),
            Comp::Stub => {
                let mut v = Vec::with_capacity(ip.len() + 1);
                v.push(0xFA);
                v.extend_from_slice(ip);
                v
            }
            Comp::Swap => {
                if ip.is_empty() {
                    return vec![0xFB];
                }
                let mut v = Vec::with_capacity(ip.len() + 1);
                v.push(0xFB);
                v.extend_from_slice(&ip[1..]);
                v.push(ip[0]);
                v
            }
            Comp::V2 => {
                if ip.first() == Some(&0x50) {
                    let mut v = vec![0x50, 0x00];
                    v.extend_from_slice(ip);
                    v
                } else {
                    ip.to_vec()
                }
            }
        }
    }

    fn unframe(&mut self, d: Vec<u8>) -> Option<Vec<u8>> {
        let compressed = |s: &mut Self| {
            if !s.warned_compressed {
                s.warned_compressed = true;
                s.events.push_back(Event::Info("The VPN server sends compressed packets, which are not supported. Disable compression on the server (allow-compression no / compress stub-v2).".into()));
            }
            None
        };
        match self.comp {
            Comp::None => Some(d),
            Comp::Stub | Comp::Swap => match d.first() {
                Some(0xFA) => Some(d[1..].to_vec()),
                Some(0xFB) => {
                    let mut v = Vec::with_capacity(d.len());
                    if d.len() > 1 {
                        v.push(d[d.len() - 1]);
                        v.extend_from_slice(&d[1..d.len() - 1]);
                    }
                    Some(v)
                }
                Some(_) => compressed(self),
                None => None,
            },
            Comp::V2 => {
                if d.first() == Some(&0x50) {
                    if d.get(1) == Some(&0x00) { Some(d[2..].to_vec()) } else { compressed(self) }
                } else {
                    Some(d)
                }
            }
        }
    }

    pub fn send_ip(&mut self, ip: &[u8]) {
        if self.pushed.is_none() {
            return;
        }
        let payload = self.frame(ip);
        self.send_data(&payload);
    }

    fn send_data(&mut self, payload: &[u8]) {
        let Some(ki) = self.send_key() else { return };
        let header: Vec<u8> = match self.peer_id {
            Some(pid) => vec![(P_DATA_V2 << 3) | self.keys[ki].id, (pid >> 16) as u8, (pid >> 8) as u8, pid as u8],
            None => vec![(P_DATA_V1 << 3) | self.keys[ki].id],
        };
        let pkt = self.keys[ki].data.as_mut().unwrap().encrypt(&header, payload);
        self.bytes_out += pkt.len() as u64;
        self.out.push_back(pkt);
        self.last_tx = Instant::now();
    }

    fn on_data(&mut self, pkt: &[u8], opcode: u8, key_id: u8) {
        let Some(ki) = self.key_index(key_id) else { return };
        let hl = if opcode == P_DATA_V2 { 4 } else { 1 };
        let Some(dc) = self.keys[ki].data.as_mut() else { return };
        let Some(plain) = dc.decrypt(pkt, hl) else {
            log::debug!("vpn: data packet failed to decrypt");
            return;
        };
        self.last_rx = Instant::now();
        self.bytes_in += pkt.len() as u64;
        let Some(ip) = self.unframe(plain) else { return };
        if ip.len() >= 16 && (ip[..16] == PING_MAGIC || ip[..16] == OCC_MAGIC) {
            return;
        }
        if ip.first().map(|b| b >> 4) == Some(4) {
            self.events.push_back(Event::Ip(ip));
        }
    }

    // ---- timers -----------------------------------------------------------------

    pub fn tick(&mut self) {
        let now = Instant::now();
        // retransmissions (rebuilt so replay-protected packet ids stay fresh)
        for ki in 0..self.keys.len() {
            let due: Vec<u32> = self.keys[ki]
                .unacked
                .iter()
                .filter(|(_, u)| now.duration_since(u.sent) >= Duration::from_secs((1u64 << u.tries.min(3)).min(8)))
                .map(|(id, _)| *id)
                .collect();
            for id in due {
                let opcode = {
                    let u = self.keys[ki].unacked.get_mut(&id).unwrap();
                    u.sent = now;
                    u.tries += 1;
                    u.opcode
                };
                self.send_control(ki, opcode, Some(id));
            }
        }
        self.flush_all();
        // initial handshake timeout
        if self.pushed.is_none() && now.duration_since(self.started) > Duration::from_secs(60) {
            let msg = if self.remote_sid.is_none() {
                "no answer from the VPN server (check address/port/protocol, and tls-auth/tls-crypt key)"
            } else {
                "TLS handshake with the VPN server timed out"
            };
            self.events.push_back(Event::Restart(msg.into()));
            self.started = now;
        }
        // PUSH_REQUEST retry
        if self.pushed.is_none() {
            if let Some(t) = self.push_req_at {
                if now.duration_since(t) > Duration::from_secs(3) && self.push_tries < 20 {
                    if let Some(ki) = self.key_index(0) {
                        self.send_push_request(ki);
                        self.flush_key(ki);
                    }
                }
            }
            return;
        }
        // keepalive
        if now.duration_since(self.last_tx) >= self.ping_every {
            let p = self.frame(&PING_MAGIC);
            self.send_data(&p);
        }
        if now.duration_since(self.last_rx) >= self.ping_restart {
            self.events.push_back(Event::Restart("the VPN server stopped responding (ping timeout)".into()));
            self.last_rx = now;
        }
        // client-initiated renegotiation
        let newest_age = self.keys.iter().filter_map(|k| k.active_since).max().map(|t| now.duration_since(t));
        let negotiating = self.keys.iter().any(|k| k.data.is_none());
        if !negotiating && self.cfg.reneg_sec > 0 && newest_age.map(|a| a > Duration::from_secs(self.cfg.reneg_sec)).unwrap_or(false) {
            let id = self.next_key_id;
            self.next_key_id = next_id(id);
            if let Ok(k) = KeyState::new(id, &self.tls_cfg, P_CONTROL_SOFT_RESET_V1) {
                log::info!("VPN: renegotiating data channel keys (key {id})");
                self.keys.push(k);
                let ki = self.keys.len() - 1;
                self.flush_key(ki);
            }
        }
        // retire old keys 60 s after a newer one became active
        if let Some(newest) = self.keys.iter().filter_map(|k| k.active_since).max() {
            if now.duration_since(newest) > Duration::from_secs(60) {
                self.keys.retain(|k| k.active_since.map(|t| t == newest).unwrap_or(true));
            }
        }
        // abandon renegotiations that never complete
        self.keys.retain(|k| k.data.is_some() || now.duration_since(k.created) < Duration::from_secs(90) || k.id == 0);
    }

    /// Tell the server we are leaving (explicit-exit-notify for UDP).
    pub fn send_exit(&mut self) {
        if self.pushed.is_some() {
            let mut p = OCC_MAGIC.to_vec();
            p.push(OCC_EXIT);
            let f = self.frame(&p);
            self.send_data(&f);
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

fn next_id(id: u8) -> u8 {
    if id >= 7 { 1 } else { id + 1 }
}
