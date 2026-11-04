//! VNC viewer session: connects to any VNC server (standard RFB 3.3-3.8 with
//! None / VNC Auth / VeNCrypt-X509), and enables the PortlessVNC extension
//! (audio, UTF-8 clipboard, file transfer, adaptive quality) when the server
//! is another PortlessVNC instance.

use crate::app::Core;
use crate::config::{AudioMode, QualityMode};
use crate::ext;
use crate::hub::Peer;
use crate::rfb::decode::{decode_rect, DecoderState, FrameBuffer, RectResult, RemoteCursor};
use crate::rfb::*;
use crate::tls::{HandshakeIo, RecordingVerifier, Transport};
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use parking_lot::Mutex;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq)]
pub enum State {
    Connecting(String),
    /// Waiting for the user to approve the server's certificate fingerprint.
    VerifyFingerprint { fingerprint: String, previous: Option<String> },
    /// Waiting for credentials.
    NeedCredentials { username: bool, message: String },
    Connected,
    Closed(String),
}

pub enum Answer {
    Fingerprint(bool),
    Credentials(String, String),
    Cancel,
}

pub struct Target {
    pub host: String,
    pub port: u16,
}

/// Parse "host", "host:display" (display < 100 => 5900+display), "host:port"
/// or "host::port"; IPv6 in brackets.
pub fn parse_address(s: &str) -> Option<Target> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some((h, p)) = s.split_once("::") {
        return Some(Target { host: h.trim_matches(['[', ']']).to_string(), port: p.parse().ok()? });
    }
    if s.starts_with('[') {
        let end = s.find(']')?;
        let host = s[1..end].to_string();
        let rest = &s[end + 1..];
        let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).map(|n| if n < 100 { 5900 + n } else { n }).unwrap_or(5900);
        return Some(Target { host, port });
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let n: u16 = p.parse().ok()?;
            Some(Target { host: h.to_string(), port: if n < 100 { 5900 + n } else { n } })
        }
        _ => Some(Target { host: s.to_string(), port: 5900 }),
    }
}

/// How a session reaches its server.
#[derive(Clone)]
#[allow(dead_code)] // the Android client only uses Auto
pub enum Route {
    /// Decide by address: the VPN if it covers it, else directly (typed addresses).
    Auto,
    /// Never through a tunnel.
    Direct,
    /// Only through this tunnel.
    Tunnel(Arc<crate::vpn::VpnManager>),
    /// Only through the background service's VPN.
    ServiceRelay,
}

pub struct Session {
    pub id: u64,
    pub route: Route,
    /// The guest VPN this session belongs to.
    pub guest: Option<String>,
    pub title: String,
    pub address: String,
    pub state: Mutex<State>,
    pub fb: Mutex<FrameBuffer>,
    pub cursor: Mutex<Option<(RemoteCursor, u64)>>,
    pub desktop_name: Mutex<String>,
    pub native: AtomicBool,
    pub via_vpn: AtomicBool,
    qemu_keys: AtomicBool,
    closed: AtomicBool,
    prio_tx: Sender<Vec<u8>>,
    bulk_tx: Sender<Vec<u8>>,
    out_rx: Mutex<Option<(Receiver<Vec<u8>>, Receiver<Vec<u8>>)>>,
    answer_tx: Sender<Answer>,
    answer_rx: Receiver<Answer>,
    transport: Mutex<Option<Arc<Transport>>>,
    pub quality: Mutex<QualityMode>,
    pub audio: Mutex<AudioMode>,
    player: Mutex<Option<crate::audio::Player>>,
    pub bytes_in: AtomicU64,
    pub updates: AtomicU64,
    pub rtt_ms: AtomicU64,
    pub server_stats: Mutex<String>,
    pub started: Instant,
    core: Arc<Core>,
    initial_user: String,
    initial_pass: String,
}

impl Session {
    pub fn start(core: Arc<Core>, address: &str, username: &str, password: &str) -> Arc<Session> {
        let (q, a) = {
            let c = core.cfg.read();
            (c.viewer.quality, c.viewer.audio)
        };
        Self::start_with(core, address, username, password, q, a)
    }

    /// Like start, with this connection's own picture quality and sound.
    pub fn start_with(core: Arc<Core>, address: &str, username: &str, password: &str, q: QualityMode, a: AudioMode) -> Arc<Session> {
        Self::start_routed(core, address, username, password, q, a, Route::Auto, None)
    }

    /// Like start_with, for a saved client: reached only the way it was assigned.
    #[allow(clippy::too_many_arguments)]
    pub fn start_routed(core: Arc<Core>, address: &str, username: &str, password: &str, q: QualityMode, a: AudioMode, route: Route, guest: Option<String>) -> Arc<Session> {
        let id = crate::hub::new_peer_id();
        let (prio_tx, prio_rx) = unbounded();
        let (bulk_tx, bulk_rx) = bounded(16);
        let (answer_tx, answer_rx) = unbounded();
        let s = Arc::new(Session {
            id,
            route,
            guest,
            title: format!("{address} - PortlessVNC #{id}"),
            address: address.to_string(),
            state: Mutex::new(State::Connecting("Connecting...".into())),
            fb: Mutex::new(FrameBuffer::new(1, 1)),
            cursor: Mutex::new(None),
            desktop_name: Mutex::new(String::new()),
            native: AtomicBool::new(false),
            via_vpn: AtomicBool::new(false),
            qemu_keys: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            prio_tx,
            bulk_tx,
            out_rx: Mutex::new(Some((prio_rx, bulk_rx))),
            answer_tx,
            answer_rx,
            transport: Mutex::new(None),
            quality: Mutex::new(q),
            audio: Mutex::new(a),
            player: Mutex::new(None),
            bytes_in: AtomicU64::new(0),
            updates: AtomicU64::new(0),
            rtt_ms: AtomicU64::new(0),
            server_stats: Mutex::new(String::new()),
            started: Instant::now(),
            core,
            initial_user: username.to_string(),
            initial_pass: password.to_string(),
        });
        let me = s.clone();
        std::thread::Builder::new()
            .name("viewer".into())
            .spawn(move || {
                let res = me.run();
                let msg = match res {
                    Ok(()) => "Disconnected".to_string(),
                    Err(e) => e.to_string(),
                };
                me.closed.store(true, Ordering::SeqCst);
                if let Some(t) = me.transport.lock().take() {
                    t.shutdown();
                }
                me.core.hub.unregister(me.id);
                *me.state.lock() = State::Closed(msg);
                crate::util::request_repaint();
            })
            .ok();
        s
    }

    pub fn answer(&self, a: Answer) {
        let _ = self.answer_tx.send(a);
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let _ = self.answer_tx.send(Answer::Cancel);
        if let Some(t) = self.transport.lock().as_ref() {
            t.shutdown();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn set_state(&self, s: State) {
        *self.state.lock() = s;
        crate::util::request_repaint();
    }

    fn wait_answer(&self) -> io::Result<Answer> {
        loop {
            match self.answer_rx.recv_timeout(Duration::from_millis(300)) {
                Ok(Answer::Cancel) => return Err(io::Error::new(io::ErrorKind::Interrupted, "Cancelled")),
                Ok(a) => return Ok(a),
                Err(_) if self.is_closed() => return Err(io::Error::new(io::ErrorKind::Interrupted, "Cancelled")),
                Err(_) => {}
            }
        }
    }

    fn credentials(&self, need_user: bool, tried: &mut bool, message: &str) -> io::Result<(String, String)> {
        if !*tried && !self.initial_pass.is_empty() && (!need_user || !self.initial_user.is_empty()) {
            *tried = true;
            return Ok((self.initial_user.clone(), self.initial_pass.clone()));
        }
        *tried = true;
        self.set_state(State::NeedCredentials { username: need_user, message: message.to_string() });
        match self.wait_answer()? {
            Answer::Credentials(u, p) => {
                self.set_state(State::Connecting("Authenticating...".into()));
                Ok((u, p))
            }
            _ => Err(io::Error::new(io::ErrorKind::Interrupted, "Cancelled")),
        }
    }

    // ---- connection ---------------------------------------------------------

    fn dial(&self, t: &Target) -> io::Result<TcpStream> {
        let addrs: Vec<SocketAddr> = (t.host.as_str(), t.port).to_socket_addrs()?.collect();
        let mut last = io::Error::new(io::ErrorKind::NotFound, "host not found");
        for a in addrs {
            let tunnel = match &self.route {
                Route::Auto if self.core.vpn.routes_to(a.ip()) => Some(self.core.vpn.clone()),
                Route::Tunnel(vpn) => Some(vpn.clone()),
                _ => None,
            };
            if let Some(vpn) = tunnel {
                self.via_vpn.store(true, Ordering::Relaxed);
                self.set_state(State::Connecting(format!("Connecting to {a} through the VPN tunnel...")));
                match vpn.dial(a, Duration::from_secs(10)) {
                    Ok(s) => return Ok(s),
                    Err(e) => last = e,
                }
                continue;
            }
            if matches!(self.route, Route::ServiceRelay) {
                self.via_vpn.store(true, Ordering::Relaxed);
                self.set_state(State::Connecting(format!("Connecting to {a} through the service's VPN...")));
                match crate::vpn::relay::dial(a, Duration::from_secs(12)) {
                    Ok(s) => return Ok(s),
                    Err(e) => last = e,
                }
                continue;
            }
            self.set_state(State::Connecting(format!("Connecting to {a}...")));
            match TcpStream::connect_timeout(&a, Duration::from_secs(10)) {
                Ok(s) => return Ok(s),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn run(self: &Arc<Self>) -> io::Result<()> {
        let target = parse_address(&self.address).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address"))?;
        // different guest VPNs can use the same addresses for different computers
        let host_key = match &self.guest {
            Some(g) => format!("guest/{g}/{}:{}", target.host, target.port),
            None => format!("{}:{}", target.host, target.port),
        };
        let mut tcp = self.dial(&target)?;
        let _ = tcp.set_nodelay(true);
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(180)));
        self.set_state(State::Connecting("Negotiating...".into()));

        let mut ver = [0u8; 12];
        tcp.read_exact(&mut ver)?;
        if &ver[..4] != b"RFB " {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Not a VNC server"));
        }
        let major: u32 = std::str::from_utf8(&ver[4..7]).ok().and_then(|s| s.parse().ok()).unwrap_or(3);
        let mut minor: u32 = std::str::from_utf8(&ver[8..11]).ok().and_then(|s| s.parse().ok()).unwrap_or(3);
        if major > 3 || minor >= 8 {
            minor = 8;
        } else if minor == 7 {
            minor = 7;
        } else {
            minor = 3;
        }
        tcp.write_all(format!("RFB 003.00{minor}\n").as_bytes())?;

        let sec = if minor == 3 {
            let t = tcp.read_u32()?;
            if t == 0 {
                return Err(read_reason(&mut tcp));
            }
            t as u8
        } else {
            let n = tcp.read_u8()? as usize;
            if n == 0 {
                return Err(read_reason(&mut tcp));
            }
            let types = tcp.read_vec(n)?;
            let pick = [SEC_VENCRYPT, SEC_VNC_AUTH, SEC_NONE].into_iter().find(|t| types.contains(t));
            let Some(p) = pick else {
                let msg = if types.contains(&SEC_RA2) || types.iter().any(|&t| t >= 128) {
                    "This address is answered by RealVNC Server, not PortlessVNC. If you meant to reach PortlessVNC, use its VPN address (it is never blocked by other VNC servers) or the port shown in its Direct addresses list. To use RealVNC itself, set its Authentication to \"VNC password\"."
                } else {
                    "The server offers no supported security type."
                };
                return Err(io::Error::new(io::ErrorKind::Unsupported, format!("{msg} (offered: {types:?})")));
            };
            tcp.write_all(&[p])?;
            p
        };

        let mut tried = false;
        let transport: Transport = match sec {
            SEC_NONE => {
                if minor >= 8 {
                    check_result(&mut tcp, minor)?;
                }
                Transport::Plain(tcp)
            }
            SEC_VNC_AUTH => {
                let (_, pass) = self.credentials(false, &mut tried, "This server requires a VNC password")?;
                let mut ch = [0u8; 16];
                tcp.read_exact(&mut ch)?;
                tcp.write_all(&vncauth::response(&pass, &ch))?;
                check_result(&mut tcp, minor)?;
                self.remember_password(&pass);
                Transport::Plain(tcp)
            }
            SEC_VENCRYPT => {
                let mut v = [0u8; 2];
                tcp.read_exact(&mut v)?;
                tcp.write_all(&[0, 2])?;
                if tcp.read_u8()? != 0 {
                    return Err(io::Error::new(io::ErrorKind::Unsupported, "VeNCrypt version rejected"));
                }
                let n = tcp.read_u8()? as usize;
                let mut subs = Vec::new();
                for _ in 0..n {
                    subs.push(tcp.read_u32()?);
                }
                let sub = [VENC_X509_VNC, VENC_X509_PLAIN, VENC_X509_NONE]
                    .into_iter()
                    .find(|s| subs.contains(s))
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, format!("No supported VeNCrypt sub-type (offered {subs:?})")))?;
                tcp.write_all(&sub.to_be_bytes())?;
                if tcp.read_u8()? != 1 {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Server rejected TLS"));
                }
                let verifier = RecordingVerifier::new();
                let cfg = crate::tls::viewer_config(verifier.clone()).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let t = crate::tls::tls_client(cfg, tcp)?;
                let cert = verifier.seen.lock().clone().unwrap_or_default();
                self.verify_fingerprint(&host_key, &cert)?;
                {
                    let mut io = HandshakeIo(&t);
                    match sub {
                        VENC_X509_VNC => {
                            let (_, pass) = self.credentials(false, &mut tried, "This server requires a VNC password")?;
                            let mut ch = [0u8; 16];
                            io.read_exact(&mut ch)?;
                            io.write_all(&vncauth::response(&pass, &ch))?;
                            check_result(&mut io, minor)?;
                            self.remember_password(&pass);
                        }
                        VENC_X509_PLAIN => {
                            let (user, pass) = self.credentials(true, &mut tried, "Sign in with an account on the remote computer")?;
                            let mut b = Vec::new();
                            b.put_u32(user.len() as u32);
                            b.put_u32(pass.len() as u32);
                            b.extend_from_slice(user.as_bytes());
                            b.extend_from_slice(pass.as_bytes());
                            io.write_all(&b)?;
                            check_result(&mut io, minor)?;
                        }
                        _ => check_result(&mut io, minor)?,
                    }
                }
                t
            }
            other => return Err(io::Error::new(io::ErrorKind::Unsupported, format!("Unsupported security type {other}"))),
        };
        let transport = Arc::new(transport);
        *self.transport.lock() = Some(transport.clone());
        if self.is_closed() {
            return Ok(());
        }

        // ClientInit / ServerInit
        let mut io = HandshakeIo(&transport);
        io.write_all(&[1])?;
        let w = io.read_u16()? as usize;
        let h = io.read_u16()? as usize;
        let mut pfb = [0u8; 16];
        io.read_exact(&mut pfb)?;
        let nlen = io.read_u32()? as usize;
        let name = String::from_utf8_lossy(&io.read_vec(nlen.min(4096))?).into_owned();
        *self.desktop_name.lock() = name.clone();
        self.fb.lock().resize(w, h);
        let _ = transport.tcp().set_read_timeout(None);

        let (mut reader, writer) = transport.split()?;
        self.spawn_writer(writer);
        let pf = PixelFormat::rgbx();
        let mut m = vec![C2S_SET_PIXEL_FORMAT, 0, 0, 0];
        pf.write(&mut m);
        self.send_prio(m);
        self.send_encodings();
        self.request_update(false);
        self.set_state(State::Connected);
        log::info!("Connected to {} ({name}, {w}x{h})", self.address);
        {
            let mut c = self.core.cfg.write();
            // saved clients have their own way there; a recent address would lose it
            if matches!(self.route, Route::Auto) {
                c.add_recent(&self.address);
            }
        }
        self.core.save_config();
        let peer: Arc<dyn Peer> = self.clone();
        self.core.hub.register(&peer);
        self.read_loop(&mut reader, pf, &peer)
    }

    fn remember_password(&self, _pass: &str) {}

    fn verify_fingerprint(&self, host_key: &str, cert: &[u8]) -> io::Result<()> {
        let fp = crate::util::sha256_hex(cert);
        let known = self.core.cfg.read().known_hosts.get(host_key).cloned();
        if known.as_deref() == Some(fp.as_str()) {
            return Ok(());
        }
        self.set_state(State::VerifyFingerprint { fingerprint: fp.clone(), previous: known });
        match self.wait_answer()? {
            Answer::Fingerprint(true) => {
                self.core.cfg.write().known_hosts.insert(host_key.to_string(), fp);
                self.core.save_config();
                self.set_state(State::Connecting("Authenticating...".into()));
                Ok(())
            }
            _ => Err(io::Error::new(io::ErrorKind::PermissionDenied, "Server identity was not accepted")),
        }
    }

    fn spawn_writer(self: &Arc<Self>, mut w: Box<dyn Write + Send>) {
        let Some((prio, bulk)) = self.out_rx.lock().take() else { return };
        let me = self.clone();
        std::thread::Builder::new()
            .name("viewer-write".into())
            .spawn(move || {
                loop {
                    if me.is_closed() {
                        break;
                    }
                    let msg = match prio.try_recv() {
                        Ok(m) => m,
                        Err(_) => crossbeam_channel::select! {
                            recv(prio) -> m => match m { Ok(m) => m, Err(_) => break },
                            recv(bulk) -> m => match m { Ok(m) => m, Err(_) => break },
                            default(Duration::from_millis(500)) => continue,
                        },
                    };
                    if w.write_all(&msg).is_err() {
                        break;
                    }
                }
                me.close();
            })
            .ok();
    }

    fn send_prio(&self, m: Vec<u8>) {
        let _ = self.prio_tx.send(m);
    }

    pub fn send_encodings(&self) {
        let q = *self.quality.lock();
        let mut encs = vec![ENC_TIGHT, ENC_ZRLE, ENC_HEXTILE, ENC_COPYRECT, ENC_RAW, ENC_CURSOR, ENC_DESKTOP_SIZE, ENC_LAST_RECT, ENC_QEMU_EXT_KEY, ENC_PORTLESS_EXT];
        if let Some(l) = q.tight_level() {
            encs.push(ENC_QUALITY_0 + l as i32);
        }
        encs.push(ENC_COMPRESS_0 + if q == QualityMode::Low { 9 } else { 6 });
        let mut m = vec![C2S_SET_ENCODINGS, 0];
        m.put_u16(encs.len() as u16);
        for e in encs {
            m.put_i32(e);
        }
        self.send_prio(m);
        if self.is_native() {
            self.send_ext_prio(ext::QUALITY_CTRL, &[(q == QualityMode::Auto) as u8, q.tight_level().unwrap_or(9)]);
        }
    }

    pub fn set_quality(&self, q: QualityMode) {
        *self.quality.lock() = q;
        self.send_encodings();
        self.request_update(false);
    }

    pub fn set_audio(&self, a: AudioMode) {
        *self.audio.lock() = a;
        self.send_audio_ctrl();
    }

    fn send_audio_ctrl(&self) {
        if !self.is_native() {
            return;
        }
        let a = *self.audio.lock();
        let mut p = Vec::new();
        match a {
            AudioMode::Off => {
                p.put_u8(0);
                p.put_u32(0);
                *self.player.lock() = None;
            }
            AudioMode::Auto => {
                p.put_u8(1);
                p.put_u32(64_000);
            }
            AudioMode::Kbps(k) => {
                p.put_u8(2);
                p.put_u32(k * 1000);
            }
        }
        self.send_ext_prio(ext::AUDIO_CTRL, &p);
    }

    fn send_ext_prio(&self, sub: u8, payload: &[u8]) {
        self.send_prio(ext::frame(sub, payload));
    }

    pub fn request_update(&self, incremental: bool) {
        let (w, h) = {
            let fb = self.fb.lock();
            (fb.width as u16, fb.height as u16)
        };
        let mut m = vec![C2S_FB_UPDATE_REQUEST, incremental as u8];
        m.put_u16(0);
        m.put_u16(0);
        m.put_u16(w);
        m.put_u16(h);
        self.send_prio(m);
    }

    pub fn pointer(&self, x: u16, y: u16, mask: u8) {
        let mut m = vec![C2S_POINTER_EVENT, mask];
        m.put_u16(x);
        m.put_u16(y);
        self.send_prio(m);
    }

    pub fn key(&self, down: bool, keysym: u32, xt: u32) {
        if self.qemu_keys.load(Ordering::Relaxed) && xt != 0 {
            let mut m = vec![C2S_QEMU, 0];
            m.put_u16(down as u16);
            m.put_u32(keysym);
            m.put_u32(xt);
            self.send_prio(m);
        } else {
            let mut m = vec![C2S_KEY_EVENT, down as u8, 0, 0];
            m.put_u32(keysym);
            self.send_prio(m);
        }
    }

    /// Press the keys in order, then release them in reverse (keysym, XT scancode).
    pub fn key_combo(&self, keys: &[(u32, u32)]) {
        for &(k, x) in keys {
            self.key(true, k, x);
        }
        for &(k, x) in keys.iter().rev() {
            self.key(false, k, x);
        }
    }

    pub fn send_files(self: &Arc<Self>, paths: Vec<std::path::PathBuf>) {
        let peer: Arc<dyn Peer> = self.clone();
        self.core.hub.send_paths(peer, paths);
    }

    fn read_loop(self: &Arc<Self>, rd: &mut Box<dyn Read + Send>, pf: PixelFormat, peer: &Arc<dyn Peer>) -> io::Result<()> {
        let mut dec = DecoderState::new(pf);
        let mut cursor_gen = 0u64;
        let mut last_ping = Instant::now();
        let mut rd = CountingReader { inner: rd, count: &self.bytes_in };
        loop {
            if self.is_closed() {
                return Ok(());
            }
            let t = rd.read_u8()?;
            match t {
                S2C_FB_UPDATE => {
                    rd.read_u8()?;
                    let n = rd.read_u16()?;
                    let mut i = 0u32;
                    while n == 0xFFFF || i < n as u32 {
                        i += 1;
                        let x = rd.read_u16()?;
                        let y = rd.read_u16()?;
                        let w = rd.read_u16()?;
                        let h = rd.read_u16()?;
                        let enc = rd.read_i32()?;
                        let r = Rect::new(x, y, w, h);
                        let res = {
                            let mut fb = self.fb.lock();
                            decode_rect(&mut dec, r, enc, &mut rd, &mut fb)?
                        };
                        match res {
                            RectResult::DesktopSize(w, h) => {
                                self.fb.lock().resize(w, h);
                            }
                            RectResult::Cursor(c) => {
                                cursor_gen += 1;
                                *self.cursor.lock() = Some((c, cursor_gen));
                            }
                            RectResult::LastRect => break,
                            RectResult::PortlessAck(_) => {
                                self.on_native();
                                self.core.hub.note_sync_peer(peer);
                            }
                            RectResult::QemuKeyAck => self.qemu_keys.store(true, Ordering::Relaxed),
                            _ => {}
                        }
                    }
                    self.updates.fetch_add(1, Ordering::Relaxed);
                    self.request_update(true);
                    crate::util::request_repaint();
                    if self.is_native() && last_ping.elapsed() > Duration::from_secs(2) {
                        last_ping = Instant::now();
                        let t = self.started.elapsed().as_micros() as u64;
                        self.send_ext_prio(ext::PING, &t.to_be_bytes());
                    }
                }
                S2C_SET_COLOUR_MAP => {
                    rd.read_u8()?;
                    rd.read_u16()?;
                    let n = rd.read_u16()? as usize;
                    rd.skip(n * 6)?;
                }
                S2C_BELL => {}
                S2C_SERVER_CUT_TEXT => {
                    rd.skip(3)?;
                    let len = rd.read_i32()?;
                    if len < 0 {
                        rd.skip((-(len as i64)) as usize)?;
                    } else {
                        let text = rd.read_vec(len as usize)?;
                        if self.clipboard_enabled() && !self.is_native() {
                            self.core.hub.remote_text(latin1_to_string(&text));
                        }
                    }
                }
                MSG_PORTLESS_EXT => {
                    let sub = rd.read_u8()?;
                    let len = rd.read_u32()? as usize;
                    if len > ext::MAX_PAYLOAD {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "extension message too large"));
                    }
                    let payload = rd.read_vec(len)?;
                    self.handle_ext(sub, &payload, peer);
                }
                other => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Unknown server message {other}"))),
            }
        }
    }

    fn on_native(&self) {
        if self.native.swap(true, Ordering::SeqCst) {
            return;
        }
        log::info!("{} is a PortlessVNC server: audio, clipboard and file transfer enabled", self.address);
        self.send_ext_prio(ext::HELLO, &ext::hello(ext::CAP_AUDIO | ext::CAP_CLIPBOARD | ext::CAP_FILES));
        let q = *self.quality.lock();
        self.send_ext_prio(ext::QUALITY_CTRL, &[(q == QualityMode::Auto) as u8, q.tight_level().unwrap_or(9)]);
        self.send_audio_ctrl();
    }

    fn handle_ext(self: &Arc<Self>, sub: u8, payload: &[u8], peer: &Arc<dyn Peer>) {
        match sub {
            ext::HELLO => {}
            ext::AUDIO_FMT => {
                let mut p = self.player.lock();
                if p.is_none() && *self.audio.lock() != AudioMode::Off {
                    *p = Some(crate::audio::Player::start());
                }
            }
            ext::AUDIO_DATA => {
                if payload.len() > 4 {
                    let mut p = self.player.lock();
                    if p.is_none() && *self.audio.lock() != AudioMode::Off {
                        *p = Some(crate::audio::Player::start());
                    }
                    if let Some(pl) = p.as_ref() {
                        pl.push(payload[4..].to_vec());
                    }
                }
            }
            ext::PONG => {
                if payload.len() >= 8 {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(&payload[..8]);
                    let sent = u64::from_be_bytes(a);
                    let now = self.started.elapsed().as_micros() as u64;
                    self.rtt_ms.store(now.saturating_sub(sent) / 1000, Ordering::Relaxed);
                }
            }
            ext::STATS => {
                *self.server_stats.lock() = String::from_utf8_lossy(payload).into_owned();
            }
            _ => self.core.hub.handle_ext(peer, sub, payload),
        }
    }
}

struct CountingReader<'a> {
    inner: &'a mut Box<dyn Read + Send>,
    count: &'a AtomicU64,
}
impl Read for CountingReader<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(b)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

fn read_reason<R: Read>(r: &mut R) -> io::Error {
    let len = r.read_u32().unwrap_or(0) as usize;
    let msg = r.read_vec(len.min(4096)).map(|v| String::from_utf8_lossy(&v).into_owned()).unwrap_or_default();
    io::Error::new(io::ErrorKind::PermissionDenied, if msg.is_empty() { "Connection refused by server".into() } else { msg })
}

fn check_result<R: Read>(r: &mut R, minor: u32) -> io::Result<()> {
    let res = r.read_u32()?;
    if res == 0 {
        return Ok(());
    }
    if minor >= 8 {
        let e = read_reason(r);
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("Authentication failed: {e}")));
    }
    Err(io::Error::new(io::ErrorKind::PermissionDenied, "Authentication failed"))
}

impl Peer for Session {
    fn id(&self) -> u64 {
        self.id
    }
    fn label(&self) -> String {
        format!("server {}", self.address)
    }
    fn is_native(&self) -> bool {
        self.native.load(Ordering::Relaxed)
    }
    fn send_ext(&self, sub: u8, payload: &[u8]) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "session closed"));
        }
        let m = ext::frame(sub, payload);
        // file data and its terminators share one ordered queue
        if matches!(sub, ext::FILE_DATA | ext::FILE_END | ext::FILE_ERR) {
            self.bulk_tx.send(m).map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "session closed"))
        } else {
            self.prio_tx.send(m).map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "session closed"))
        }
    }
    fn send_clip_text(&self, text: &str) {
        if self.is_native() {
            let _ = self.send_ext(ext::CLIP_TEXT, text.as_bytes());
        } else {
            let t = string_to_latin1(text);
            let mut m = vec![C2S_CLIENT_CUT_TEXT, 0, 0, 0];
            m.put_u32(t.len() as u32);
            m.extend_from_slice(&t);
            self.send_prio(m);
        }
    }
    fn clipboard_enabled(&self) -> bool {
        self.core.cfg.read().viewer.share_clipboard
    }
    fn files_enabled(&self) -> bool {
        true
    }
}
