//! One connected VNC client: handshake, authentication, the update loop
//! (with adaptive quality), input, clipboard and audio.

use super::{Server, Snapshot};
use crate::config::AuthMode;
use crate::ext;
use crate::hub::Peer;
use crate::rfb::encode::{self, EncoderState, Frame};
use crate::rfb::*;
use crate::tls::{HandshakeIo, Transport};
use parking_lot::{Condvar, Mutex};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const AUDIO_LEVELS: [u32; 5] = [16_000, 32_000, 64_000, 96_000, 128_000];

#[derive(Clone)]
struct ClientPrefs {
    pf: PixelFormat,
    encoding: i32,
    jpeg_level: Option<u8>,
    compress_level: u8,
    cursor: bool,
    desktop_size: bool,
    qemu_key: bool,
    ext: bool,
}

struct UpdateState {
    prefs: ClientPrefs,
    /// Some(incremental) when the client has an outstanding update request
    pending: Option<bool>,
    ext_ack_pending: bool,
    qemu_ack_pending: bool,
    cursor_dirty: bool,
}

pub struct ClientConn {
    pub id: u64,
    pub addr: SocketAddr,
    pub via_vpn: bool,
    pub user: String,
    pub connected_at: Instant,
    pub native: AtomicBool,
    closed: AtomicBool,
    transport: Transport,
    writer: Mutex<Box<dyn Write + Send>>,
    upd: Mutex<UpdateState>,
    cond: Condvar,
    server: Arc<Server>,
    // audio control from the viewer: 0 = off, 1 = auto, 2 = fixed
    audio_mode: AtomicU8,
    audio_fixed: AtomicU32,
    audio_auto: AtomicU32,
    audio_started: AtomicBool,
    quality_auto: AtomicBool,
    /// Current JPEG quality used by the adaptive controller (0-100).
    pub jpeg_quality: AtomicU8,
    pub bytes_sent: AtomicU64,
    pub fb_size: Mutex<(u16, u16)>,
    key_seen: AtomicBool,
    mods: AtomicU8,
}

fn proto_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub fn handle(server: Arc<Server>, tcp: TcpStream, addr: SocketAddr, from_vpn: bool) {
    let _ = tcp.set_nodelay(true);
    // Was this connection bridged in from the VPN?
    // (the VPN stack registers the bridge right after connecting, so allow a
    // brief moment for the entry to appear)
    let mut bridged = None;
    if from_vpn {
        for _ in 0..15 {
            if let Some(real) = server.vpn_bridges.lock().remove(&addr.port()) {
                bridged = Some(real);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let (peer_addr, via_vpn) = match bridged {
        Some(real) => (real, true),
        None => (addr, from_vpn),
    };
    if server.blocked(peer_addr.ip()) {
        log::warn!("Rejected {peer_addr}: too many failed logins, try again in a minute");
        return;
    }
    // generous: the viewer may be waiting for its user to check the fingerprint
    // or type a password
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(180)));
    match handshake(&server, tcp, peer_addr) {
        Ok((transport, user)) => {
            let _ = transport.tcp().set_read_timeout(None);
            log::info!("Client connected: {peer_addr}{} ({user})", if via_vpn { " via VPN" } else { "" });
            if let Err(e) = run(server.clone(), transport, peer_addr, via_vpn, user) {
                log::debug!("client {peer_addr}: {e}");
            }
            log::info!("Client disconnected: {peer_addr}");
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied {
                server.note_failure(peer_addr.ip());
                log::warn!("Authentication failed for {peer_addr}");
            } else {
                log::info!("Handshake with {peer_addr} failed: {e}");
            }
        }
    }
    crate::util::request_repaint();
}

fn security_result<W: Write>(w: &mut W, minor: u32, ok: bool, reason: &str) -> io::Result<()> {
    let mut b = Vec::new();
    b.put_u32(if ok { 0 } else { 1 });
    if !ok && minor >= 8 {
        b.put_u32(reason.len() as u32);
        b.extend_from_slice(reason.as_bytes());
    }
    w.write_all(&b)
}

/// VNC challenge/response against the permanent password and/or the current
/// one-time password (which is rotated after a successful use).
fn vnc_auth<S: Read + Write>(s: &mut S, server: &Server) -> io::Result<bool> {
    let mut challenge = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut challenge);
    s.write_all(&challenge)?;
    let mut resp = [0u8; 16];
    s.read_exact(&mut resp)?;
    let (perm_on, perm) = {
        let c = server.cfg.read();
        (c.server.permanent_password, c.vnc_password())
    };
    if perm_on && !perm.is_empty() && vncauth::verify(&perm, &challenge, &resp) {
        return Ok(true);
    }
    if let Some(otp) = server.current_otp() {
        if vncauth::verify(&otp, &challenge, &resp) {
            server.rotate_otp();
            log::info!("One-time password used; a new one was generated");
            return Ok(true);
        }
    }
    Ok(false)
}

fn handshake(server: &Arc<Server>, mut tcp: TcpStream, addr: SocketAddr) -> io::Result<(Transport, String)> {
    tcp.write_all(b"RFB 003.008\n")?;
    let mut ver = [0u8; 12];
    tcp.read_exact(&mut ver)?;
    if &ver[..4] != b"RFB " {
        return Err(proto_err("not a VNC client"));
    }
    let minor: u32 = std::str::from_utf8(&ver[8..11]).ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let minor = if minor >= 8 { 8 } else if minor == 7 { 7 } else { 3 };

    let (auth, allow_classic) = {
        let c = server.cfg.read();
        (c.server.auth, c.server.allow_classic_auth)
    };
    let mut types: Vec<u8> = Vec::new();
    match auth {
        AuthMode::VncPassword => {
            types.push(SEC_VENCRYPT);
            if allow_classic {
                types.push(SEC_VNC_AUTH);
            }
        }
        AuthMode::SystemAccount => types.push(SEC_VENCRYPT),
        AuthMode::None => {
            types.push(SEC_VENCRYPT);
            types.push(SEC_NONE);
        }
    }
    let chosen = if minor >= 7 {
        let mut b = vec![types.len() as u8];
        b.extend_from_slice(&types);
        tcp.write_all(&b)?;
        let c = tcp.read_u8()?;
        if !types.contains(&c) {
            return Err(proto_err(format!("client chose unsupported security type {c}")));
        }
        c
    } else {
        // RFB 3.3: the server decides
        let c = if types.contains(&SEC_VNC_AUTH) {
            SEC_VNC_AUTH
        } else if types.contains(&SEC_NONE) {
            SEC_NONE
        } else {
            tcp.write_all(&0u32.to_be_bytes())?;
            let reason = b"This server requires a VeNCrypt (TLS) capable viewer";
            tcp.write_all(&(reason.len() as u32).to_be_bytes())?;
            tcp.write_all(reason)?;
            return Err(proto_err("RFB 3.3 client cannot use TLS"));
        };
        tcp.write_all(&(c as u32).to_be_bytes())?;
        c
    };

    let mut user = String::from("vnc");
    let transport = match chosen {
        SEC_NONE => {
            if minor >= 8 {
                security_result(&mut tcp, minor, true, "")?;
            }
            Transport::Plain(tcp)
        }
        SEC_VNC_AUTH => {
            let ok = vnc_auth(&mut tcp, server)?;
            security_result(&mut tcp, minor, ok, "Authentication failed")?;
            if !ok {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "bad password"));
            }
            Transport::Plain(tcp)
        }
        SEC_VENCRYPT => {
            tcp.write_all(&[0, 2])?;
            let mut v = [0u8; 2];
            tcp.read_exact(&mut v)?;
            if v != [0, 2] {
                tcp.write_all(&[1])?;
                return Err(proto_err("unsupported VeNCrypt version"));
            }
            tcp.write_all(&[0])?;
            let sub = match auth {
                AuthMode::VncPassword => VENC_X509_VNC,
                AuthMode::SystemAccount => VENC_X509_PLAIN,
                AuthMode::None => VENC_X509_NONE,
            };
            let mut b = vec![1u8];
            b.put_u32(sub);
            tcp.write_all(&b)?;
            let chosen_sub = tcp.read_u32()?;
            if chosen_sub != sub {
                tcp.write_all(&[0])?;
                return Err(proto_err(format!("client chose VeNCrypt subtype {chosen_sub}")));
            }
            tcp.write_all(&[1])?;
            let t = crate::tls::tls_server(server.tls_config(), tcp)?;
            {
                let mut io = HandshakeIo(&t);
                let ok = match chosen_sub {
                    VENC_X509_VNC => vnc_auth(&mut io, server)?,
                    VENC_X509_PLAIN => {
                        let ul = io.read_u32()? as usize;
                        let pl = io.read_u32()? as usize;
                        if ul > 1024 || pl > 1024 {
                            return Err(proto_err("credentials too long"));
                        }
                        let u = String::from_utf8_lossy(&io.read_vec(ul)?).into_owned();
                        let p = String::from_utf8_lossy(&io.read_vec(pl)?).into_owned();
                        // the one-time password also works here (any user name)
                        let otp_ok = server.current_otp().map(|o| o == p).unwrap_or(false);
                        if otp_ok {
                            server.rotate_otp();
                            log::info!("One-time password used; a new one was generated");
                        }
                        let ok = otp_ok || crate::platform::check_system_login(&u, &p);
                        user = u;
                        ok
                    }
                    _ => true,
                };
                security_result(&mut io, minor, ok, "Authentication failed")?;
                if !ok {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "bad credentials"));
                }
            }
            t
        }
        _ => return Err(proto_err("unexpected security type")),
    };
    let _ = addr;
    Ok((transport, user))
}

fn run(server: Arc<Server>, transport: Transport, addr: SocketAddr, via_vpn: bool, user: String) -> io::Result<()> {
    // ClientInit
    let shared = HandshakeIo(&transport).read_u8()?;
    let _ = shared;
    server.capture.acquire();
    let _release = scopeguard(server.clone());
    let snap = server.capture.wait_first(Duration::from_secs(5));
    let (w, h) = snap.frame.as_ref().map(|f| (f.width as u16, f.height as u16)).unwrap_or((1024, 768));

    // ServerInit
    let mut b = Vec::new();
    b.put_u16(w);
    b.put_u16(h);
    PixelFormat::bgrx().write(&mut b);
    let name = format!("{}@{}", crate::platform::current_user(), std::env::var("COMPUTERNAME").unwrap_or_else(|_| "PortlessVNC".into()));
    b.put_u32(name.len() as u32);
    b.extend_from_slice(name.as_bytes());
    HandshakeIo(&transport).write_all(&b)?;

    let (mut reader, writer) = transport.split()?;
    let conn = Arc::new(ClientConn {
        id: crate::hub::new_peer_id(),
        addr,
        via_vpn,
        user,
        connected_at: Instant::now(),
        native: AtomicBool::new(false),
        closed: AtomicBool::new(false),
        transport,
        writer: Mutex::new(writer),
        upd: Mutex::new(UpdateState {
            prefs: ClientPrefs { pf: PixelFormat::bgrx(), encoding: ENC_RAW, jpeg_level: None, compress_level: 6, cursor: false, desktop_size: false, qemu_key: false, ext: false },
            pending: None,
            ext_ack_pending: false,
            qemu_ack_pending: false,
            cursor_dirty: true,
        }),
        cond: Condvar::new(),
        server: server.clone(),
        audio_mode: AtomicU8::new(0),
        audio_fixed: AtomicU32::new(64_000),
        audio_auto: AtomicU32::new(64_000),
        audio_started: AtomicBool::new(false),
        quality_auto: AtomicBool::new(false),
        jpeg_quality: AtomicU8::new(80),
        bytes_sent: AtomicU64::new(0),
        fb_size: Mutex::new((w, h)),
        key_seen: AtomicBool::new(false),
        mods: AtomicU8::new(0),
    });
    server.clients.lock().push(conn.clone());
    let peer: Arc<dyn Peer> = conn.clone();
    server.hub.register(&peer);
    crate::util::request_repaint();

    let c2 = conn.clone();
    let updater = std::thread::Builder::new().name("vnc-update".into()).spawn(move || {
        if let Err(e) = c2.update_loop() {
            log::debug!("update loop ended: {e}");
        }
        c2.close();
    })?;

    let res = conn.read_loop(&mut reader, &peer);
    conn.close();
    let _ = updater.join();
    server.clients.lock().retain(|c| c.id != conn.id);
    server.hub.unregister(conn.id);
    res
}

struct Release(Arc<Server>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.capture.release();
    }
}
fn scopeguard(s: Arc<Server>) -> Release {
    Release(s)
}

impl ClientConn {
    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.transport.shutdown();
            self.cond.notify_all();
        }
    }

    /// Track Ctrl/Alt; Ctrl+Alt+Del is performed by the service (SendSAS)
    /// because Windows ignores it as injected input. Returns true if handled.
    fn secure_attention(&self, down: bool, keysym: u32) -> bool {
        let bit = match keysym {
            0xffe3 | 0xffe4 => 1u8,
            0xffe9 | 0xffea => 2,
            _ => 0,
        };
        if bit != 0 {
            let m = self.mods.load(Ordering::Relaxed);
            self.mods.store(if down { m | bit } else { m & !bit }, Ordering::Relaxed);
            return false;
        }
        if keysym == 0xffff && self.mods.load(Ordering::Relaxed) == 3 {
            #[cfg(windows)]
            if crate::platform::service::request_sas() {
                if down {
                    log::info!("Ctrl+Alt+Del from {}", self.addr);
                }
                return true;
            }
        }
        false
    }

    fn note_key(&self) {
        if !self.key_seen.swap(true, Ordering::Relaxed) {
            log::info!("Receiving keyboard input from {}", self.addr);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn write_all(&self, data: &[u8]) -> io::Result<()> {
        let mut w = self.writer.lock();
        w.write_all(data)?;
        w.flush()?;
        self.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Like send_ext but drops the message if the connection is busy
    /// (used for real-time audio so it never queues up behind video).
    fn try_send_ext(&self, sub: u8, payload: &[u8], wait: Duration) -> bool {
        if let Some(mut w) = self.writer.try_lock_for(wait) {
            let f = ext::frame(sub, payload);
            let ok = w.write_all(&f).is_ok();
            self.bytes_sent.fetch_add(f.len() as u64, Ordering::Relaxed);
            ok
        } else {
            false
        }
    }

    pub fn audio_bitrate(&self) -> Option<u32> {
        match self.audio_mode.load(Ordering::Relaxed) {
            0 => None,
            1 => Some(self.audio_auto.load(Ordering::Relaxed)),
            _ => Some(self.audio_fixed.load(Ordering::Relaxed)),
        }
    }

    fn read_loop(self: &Arc<Self>, rd: &mut Box<dyn Read + Send>, peer: &Arc<dyn Peer>) -> io::Result<()> {
        let mut prev_mask = 0u8;
        loop {
            let t = match rd.read_u8() {
                Ok(t) => t,
                Err(e) if self.is_closed() => return Err(e),
                Err(e) => return Err(e),
            };
            match t {
                C2S_SET_PIXEL_FORMAT => {
                    let mut b = [0u8; 19];
                    rd.read_exact(&mut b)?;
                    let pf = PixelFormat::parse(&b[3..19]);
                    if !pf.is_valid_true_color() {
                        return Err(proto_err("colour-map pixel formats are not supported"));
                    }
                    let mut u = self.upd.lock();
                    u.prefs.pf = pf;
                    u.cursor_dirty = true;
                }
                C2S_SET_ENCODINGS => {
                    rd.read_u8()?;
                    let n = rd.read_u16()? as usize;
                    let mut encs = Vec::with_capacity(n);
                    for _ in 0..n {
                        encs.push(rd.read_i32()?);
                    }
                    self.set_encodings(&encs);
                }
                C2S_FB_UPDATE_REQUEST => {
                    let incremental = rd.read_u8()? != 0;
                    rd.skip(8)?;
                    let mut u = self.upd.lock();
                    u.pending = Some(match u.pending {
                        Some(prev) => prev && incremental,
                        None => incremental,
                    });
                    drop(u);
                    self.cond.notify_all();
                }
                C2S_KEY_EVENT => {
                    let down = rd.read_u8()? != 0;
                    rd.skip(2)?;
                    let keysym = rd.read_u32()?;
                    self.note_key();
                    if !self.secure_attention(down, keysym) {
                        crate::platform::input::key_sym(down, keysym);
                    }
                }
                C2S_POINTER_EVENT => {
                    let mask = rd.read_u8()?;
                    let x = rd.read_u16()? as i32;
                    let y = rd.read_u16()? as i32;
                    let origin = self.server.capture.snapshot().origin;
                    crate::platform::input::pointer(x, y, origin, mask, prev_mask);
                    prev_mask = mask;
                }
                C2S_CLIENT_CUT_TEXT => {
                    rd.skip(3)?;
                    let len = rd.read_i32()?;
                    if len < 0 {
                        rd.skip((-(len as i64)) as usize)?; // extended clipboard (not negotiated)
                    } else {
                        if len as usize > 16 * 1024 * 1024 {
                            return Err(proto_err("cut text too large"));
                        }
                        let text = rd.read_vec(len as usize)?;
                        if self.clipboard_enabled() && !self.native.load(Ordering::Relaxed) {
                            self.server.hub.remote_text(latin1_to_string(&text));
                        }
                    }
                }
                C2S_QEMU => {
                    let sub = rd.read_u8()?;
                    if sub != 0 {
                        return Err(proto_err(format!("unsupported QEMU message {sub}")));
                    }
                    let down = rd.read_u16()? != 0;
                    let keysym = rd.read_u32()?;
                    let keycode = rd.read_u32()?;
                    self.note_key();
                    if !self.secure_attention(down, keysym) {
                        crate::platform::input::key_scancode(down, keycode, keysym);
                    }
                }
                MSG_PORTLESS_EXT => {
                    let sub = rd.read_u8()?;
                    let len = rd.read_u32()? as usize;
                    if len > ext::MAX_PAYLOAD {
                        return Err(proto_err("extension message too large"));
                    }
                    let payload = rd.read_vec(len)?;
                    self.handle_ext(sub, &payload, peer);
                }
                other => return Err(proto_err(format!("unknown client message {other}"))),
            }
        }
    }

    fn set_encodings(self: &Arc<Self>, encs: &[i32]) {
        let mut u = self.upd.lock();
        let p = &mut u.prefs;
        p.encoding = *encs.iter().find(|e| matches!(**e, ENC_TIGHT | ENC_ZRLE | ENC_HEXTILE | ENC_RAW)).unwrap_or(&ENC_RAW);
        p.jpeg_level = encs.iter().find(|e| (ENC_QUALITY_0..=ENC_QUALITY_9).contains(*e)).map(|e| (e - ENC_QUALITY_0) as u8);
        p.compress_level = encs.iter().find(|e| (ENC_COMPRESS_0..=ENC_COMPRESS_9).contains(*e)).map(|e| (e - ENC_COMPRESS_0) as u8).unwrap_or(6);
        let had_cursor = p.cursor;
        p.cursor = encs.contains(&ENC_CURSOR);
        p.desktop_size = encs.contains(&ENC_DESKTOP_SIZE);
        let wants_qemu = encs.contains(&ENC_QEMU_EXT_KEY);
        if wants_qemu && !p.qemu_key {
            u.qemu_ack_pending = true;
        }
        u.prefs.qemu_key = wants_qemu;
        let wants_ext = encs.contains(&ENC_PORTLESS_EXT);
        if wants_ext && !u.prefs.ext {
            u.ext_ack_pending = true;
        }
        u.prefs.ext = wants_ext;
        if u.prefs.cursor && !had_cursor {
            u.cursor_dirty = true;
        }
        if let Some(l) = u.prefs.jpeg_level {
            self.jpeg_quality.store(TIGHT_JPEG_QUALITY[l as usize], Ordering::Relaxed);
        }
        let name = match u.prefs.encoding {
            ENC_TIGHT => "Tight",
            ENC_ZRLE => "ZRLE",
            ENC_HEXTILE => "Hextile",
            _ => "Raw",
        };
        log::debug!("client {} encoding {name}, jpeg {:?}", self.addr, u.prefs.jpeg_level);
    }

    fn handle_ext(self: &Arc<Self>, sub: u8, payload: &[u8], peer: &Arc<dyn Peer>) {
        let mut c = Cur::new(payload);
        match sub {
            ext::HELLO => {
                let _ = c.u16();
                let _ = c.u32();
                let name = c.str16().unwrap_or_default();
                log::info!("{} is a PortlessVNC viewer ({name}): audio, clipboard and file transfer available", self.addr);
                self.server.hub.note_sync_peer(peer);
            }
            ext::AUDIO_CTRL => {
                let mode = c.u8().unwrap_or(0);
                let rate = c.u32().unwrap_or(64_000).clamp(8_000, 256_000);
                let allowed = self.server.cfg.read().server.share_audio;
                self.audio_mode.store(if allowed { mode.min(2) } else { 0 }, Ordering::Relaxed);
                self.audio_fixed.store(rate, Ordering::Relaxed);
                if allowed && mode != 0 && !self.audio_started.swap(true, Ordering::SeqCst) {
                    let me = self.clone();
                    std::thread::Builder::new().name("vnc-audio".into()).spawn(move || me.audio_loop()).ok();
                }
            }
            ext::QUALITY_CTRL => {
                let auto = c.u8().unwrap_or(1) != 0;
                self.quality_auto.store(auto, Ordering::Relaxed);
            }
            ext::PING => {
                let _ = self.send_ext(ext::PONG, payload);
            }
            _ => self.server.hub.handle_ext(peer, sub, payload),
        }
    }

    fn audio_loop(self: Arc<Self>) {
        let sub = self.server.audio.subscribe();
        let mut enc = match crate::audio::Encoder::new(self.audio_bitrate().unwrap_or(64_000)) {
            Ok(e) => e,
            Err(e) => {
                log::warn!("Opus encoder: {e}");
                self.audio_started.store(false, Ordering::SeqCst);
                return;
            }
        };
        let mut fmt = Vec::new();
        fmt.put_u32(crate::audio::RATE);
        fmt.put_u8(2);
        let _ = self.send_ext(ext::AUDIO_FMT, &fmt);
        let mut seq = 0u32;
        log::info!("Streaming audio to {}", self.addr);
        while !self.is_closed() {
            let Some(rate) = self.audio_bitrate() else { break };
            enc.set_bitrate(rate);
            let frame = match sub.rx.recv_timeout(Duration::from_millis(500)) {
                Ok(f) => f,
                Err(_) => continue,
            };
            if let Some(pkt) = enc.encode(&frame) {
                let mut p = Vec::with_capacity(pkt.len() + 4);
                p.put_u32(seq);
                p.extend_from_slice(&pkt);
                if !self.try_send_ext(ext::AUDIO_DATA, &p, Duration::from_millis(15)) {
                    // link busy: lower the adaptive bitrate a notch
                    self.adjust_audio(-1);
                }
            }
            seq = seq.wrapping_add(1);
        }
        self.audio_started.store(false, Ordering::SeqCst);
        log::info!("Audio stream to {} stopped", self.addr);
    }

    fn adjust_audio(&self, dir: i32) {
        let cur = self.audio_auto.load(Ordering::Relaxed);
        let idx = AUDIO_LEVELS.iter().position(|&l| l >= cur).unwrap_or(2) as i32;
        let n = (idx + dir).clamp(0, AUDIO_LEVELS.len() as i32 - 1) as usize;
        self.audio_auto.store(AUDIO_LEVELS[n], Ordering::Relaxed);
    }

    fn update_loop(self: &Arc<Self>) -> io::Result<()> {
        let mut enc = EncoderState::new(6);
        let mut last: Option<Arc<Frame>> = None;
        let mut last_seq = u64::MAX;
        let mut last_cursor_seq = 0u64;
        let mut fast_updates = 0u32;
        loop {
            // 1. wait for an update request
            let incremental = {
                let mut u = self.upd.lock();
                while u.pending.is_none() && !self.is_closed() {
                    self.cond.wait_for(&mut u, Duration::from_millis(500));
                }
                if self.is_closed() {
                    return Ok(());
                }
                u.pending.unwrap()
            };
            // 2. wait for something to send
            let snap: Snapshot = loop {
                if self.is_closed() {
                    return Ok(());
                }
                let s = self.server.capture.wait_newer(last_seq, last_cursor_seq, Duration::from_millis(250));
                let u = self.upd.lock();
                let cursor_news = u.prefs.cursor && (s.cursor_seq != last_cursor_seq || u.cursor_dirty) && s.cursor.is_some();
                let forced = !u.pending.unwrap_or(true) || u.ext_ack_pending || u.qemu_ack_pending;
                if !u.prefs.cursor {
                    last_cursor_seq = s.cursor_seq; // cursor changes are irrelevant to this client
                }
                if s.frame.is_some() && (s.seq != last_seq || cursor_news || forced || !incremental) {
                    break s;
                }
            };
            let Some(frame) = snap.frame.clone() else { continue };
            let (prefs, incremental, ext_ack, qemu_ack, cursor_dirty) = {
                let mut u = self.upd.lock();
                let inc = u.pending.take().unwrap_or(true);
                let r = (u.prefs.clone(), inc, u.ext_ack_pending, u.qemu_ack_pending, u.cursor_dirty);
                u.ext_ack_pending = false;
                u.qemu_ack_pending = false;
                u.cursor_dirty = false;
                r
            };

            let mut body = Vec::with_capacity(64 * 1024);
            let mut count: u16 = 0;
            if ext_ack {
                put_rect_header(&mut body, Rect::new(ext::VERSION, 0, 0, 0), ENC_PORTLESS_EXT);
                count += 1;
            }
            if qemu_ack {
                put_rect_header(&mut body, Rect::new(0, 0, 0, 0), ENC_QEMU_EXT_KEY);
                count += 1;
            }
            // resolution change
            let (fw, fh) = (frame.width as u16, frame.height as u16);
            let mut full = !incremental;
            {
                let mut sz = self.fb_size.lock();
                if *sz != (fw, fh) {
                    if prefs.desktop_size {
                        put_rect_header(&mut body, Rect::new(0, 0, fw, fh), ENC_DESKTOP_SIZE);
                        count += 1;
                        *sz = (fw, fh);
                        full = true;
                    }
                }
            }
            let (cw, ch) = *self.fb_size.lock();
            // cursor shape
            if prefs.cursor && (snap.cursor_seq != last_cursor_seq || cursor_dirty) {
                if let Some(cs) = &snap.cursor {
                    put_cursor(&mut body, cs, &prefs.pf);
                    count += 1;
                }
            }
            last_cursor_seq = snap.cursor_seq;

            let rects: Vec<Rect> = if full || snap.seq != last_seq {
                let base = if full { None } else { last.as_deref() };
                encode::diff_rects(base, &frame)
                    .into_iter()
                    .filter_map(|r| clip(r, cw, ch))
                    .collect()
            } else {
                Vec::new()
            };
            let jpeg_q = self.current_jpeg_quality(&prefs);
            for r in &rects {
                count += match prefs.encoding {
                    ENC_TIGHT => encode::encode_tight(&mut enc, &frame, *r, &prefs.pf, jpeg_q, &mut body),
                    ENC_ZRLE => encode::encode_zrle(&mut enc, &frame, *r, &prefs.pf, &mut body),
                    ENC_HEXTILE => encode::encode_hextile(&frame, *r, &prefs.pf, &mut body),
                    _ => encode::encode_raw(&frame, *r, &prefs.pf, &mut body),
                };
            }
            last_seq = snap.seq;
            last = Some(frame);
            if count == 0 {
                // nothing to send yet: keep the request pending
                let mut u = self.upd.lock();
                if u.pending.is_none() {
                    u.pending = Some(true);
                }
                continue;
            }
            let mut msg = Vec::with_capacity(body.len() + 4);
            msg.push(S2C_FB_UPDATE);
            msg.push(0);
            msg.put_u16(count);
            msg.extend_from_slice(&body);
            let t0 = Instant::now();
            self.write_all(&msg)?;
            let dt = t0.elapsed();
            if ext_ack {
                self.native.store(true, Ordering::Relaxed);
                let caps = ext::CAP_AUDIO | ext::CAP_CLIPBOARD | ext::CAP_FILES;
                self.send_ext(ext::HELLO, &ext::hello(caps))?;
            }
            self.adapt(dt, msg.len(), &mut fast_updates);
        }
    }

    fn current_jpeg_quality(&self, prefs: &ClientPrefs) -> Option<u8> {
        prefs.jpeg_level?;
        if self.quality_auto.load(Ordering::Relaxed) {
            Some(self.jpeg_quality.load(Ordering::Relaxed))
        } else {
            prefs.jpeg_level.map(|l| TIGHT_JPEG_QUALITY[l as usize])
        }
    }

    /// Adaptive controller: if writing an update blocked (socket buffers full
    /// = link saturated), lower JPEG quality and audio bitrate; when updates
    /// flow freely, raise them again.
    fn adapt(&self, dt: Duration, bytes: usize, fast: &mut u32) {
        let ms = dt.as_millis() as u64;
        let auto_video = self.quality_auto.load(Ordering::Relaxed);
        let q = self.jpeg_quality.load(Ordering::Relaxed);
        if ms > 120 {
            *fast = 0;
            if auto_video {
                self.jpeg_quality.store(q.saturating_sub(10).max(20), Ordering::Relaxed);
            }
            if ms > 250 {
                self.adjust_audio(-1);
            }
        } else if ms < 25 {
            *fast += 1;
            if *fast >= 10 {
                *fast = 0;
                if auto_video && bytes > 0 {
                    self.jpeg_quality.store((q + 5).min(92), Ordering::Relaxed);
                }
                self.adjust_audio(1);
            }
        }
    }
}

fn clip(r: Rect, w: u16, h: u16) -> Option<Rect> {
    if r.x >= w || r.y >= h {
        return None;
    }
    let rw = r.w.min(w - r.x);
    let rh = r.h.min(h - r.y);
    if rw == 0 || rh == 0 { None } else { Some(Rect::new(r.x, r.y, rw, rh)) }
}

fn put_cursor(out: &mut Vec<u8>, cs: &super::CursorShape, pf: &PixelFormat) {
    let (w, h) = (cs.width, cs.height);
    put_rect_header(out, Rect::new(cs.hot_x as u16, cs.hot_y as u16, w as u16, h as u16), ENC_CURSOR);
    for i in 0..w * h {
        let p = &cs.bgra[i * 4..i * 4 + 4];
        pf.put_value(out, pf.pack(p[2], p[1], p[0]));
    }
    let row = (w + 7) / 8;
    for y in 0..h {
        let mut bytes = vec![0u8; row];
        for x in 0..w {
            if cs.bgra[(y * w + x) * 4 + 3] > 127 {
                bytes[x / 8] |= 0x80 >> (x % 8);
            }
        }
        out.extend_from_slice(&bytes);
    }
}

impl Peer for ClientConn {
    fn id(&self) -> u64 {
        self.id
    }
    fn label(&self) -> String {
        format!("viewer {}", self.addr)
    }
    fn is_native(&self) -> bool {
        self.native.load(Ordering::Relaxed)
    }
    fn send_ext(&self, sub: u8, payload: &[u8]) -> io::Result<()> {
        if !self.is_native() && sub != ext::HELLO {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "peer is not a PortlessVNC viewer"));
        }
        self.write_all(&ext::frame(sub, payload))
    }
    fn send_clip_text(&self, text: &str) {
        if self.is_native() {
            let _ = self.send_ext(ext::CLIP_TEXT, text.as_bytes());
        } else {
            let t = string_to_latin1(text);
            let mut b = vec![S2C_SERVER_CUT_TEXT, 0, 0, 0];
            b.put_u32(t.len() as u32);
            b.extend_from_slice(&t);
            let _ = self.write_all(&b);
        }
    }
    fn clipboard_enabled(&self) -> bool {
        self.server.cfg.read().server.share_clipboard
    }
    fn files_enabled(&self) -> bool {
        self.server.cfg.read().server.allow_file_transfer
    }
}
