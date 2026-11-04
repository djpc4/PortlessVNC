//! `PortlessVNC --selftest`: headless end-to-end check of the server and
//! viewer over loopback (native TLS path, classic VNC auth path, encoders,
//! decoders and file transfer). Uses a throw-away settings folder.

use crate::rfb::decode::{decode_rect, DecoderState, FrameBuffer, RectResult};
use crate::rfb::*;
use crate::viewer::{Answer, Session, State};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const PORT: u16 = 5977;
const PASSWORD: &str = "t3stPw!";
/// The selftest runs VPN-only (no firewall prompt), so it talks to the
/// server through its private loopback listener.
static BRIDGE: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

fn step(name: &str, r: anyhow::Result<String>) -> bool {
    match r {
        Ok(detail) => {
            println!("[ OK ] {name}: {detail}");
            true
        }
        Err(e) => {
            println!("[FAIL] {name}: {e:#}");
            false
        }
    }
}

pub fn run() -> i32 {
    let dir = std::env::temp_dir().join(format!("portlessvnc-selftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("PORTLESS_CONFIG_DIR", &dir);
    let core = match crate::app::Core::new() {
        Ok(c) => c,
        Err(e) => {
            println!("[FAIL] core: {e:#}");
            return 1;
        }
    };
    {
        let mut c = core.cfg.write();
        c.server.port = PORT;
        c.server.listen_direct = false;
        c.set_vnc_password(PASSWORD);
        c.download_dir = dir.join("downloads").to_string_lossy().into_owned();
    }
    core.save_config();
    core.server.restart();
    std::thread::sleep(Duration::from_millis(600));
    let mut ok = true;

    // 1. native viewer session (VeNCrypt X509Vnc + extension)
    let bridge = core.server.vpn_bridge_port();
    BRIDGE.store(bridge, std::sync::atomic::Ordering::SeqCst);
    let s = Session::start(core.clone(), &format!("127.0.0.1::{bridge}"), "", PASSWORD);
    ok &= step("PortlessVNC viewer -> server (TLS, fingerprint, VNC password)", (|| {
        let t0 = Instant::now();
        loop {
            let st = s.state.lock().clone();
            match st {
                State::VerifyFingerprint { .. } => s.answer(Answer::Fingerprint(true)),
                State::Connected if s.updates.load(std::sync::atomic::Ordering::Relaxed) >= 2 => break,
                State::Closed(m) => anyhow::bail!("closed: {m}"),
                State::NeedCredentials { .. } => anyhow::bail!("password was rejected"),
                _ => {}
            }
            if t0.elapsed() > Duration::from_secs(15) {
                anyhow::bail!("timeout in state {st:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let fb = s.fb.lock();
        let nonblack = fb.pixels.iter().filter(|&&p| p & 0x00FF_FFFF != 0).count();
        Ok(format!("{}x{}, {} updates, {:.1}% non-black pixels, {} KB received", fb.width, fb.height, s.updates.load(std::sync::atomic::Ordering::Relaxed), nonblack as f64 * 100.0 / fb.pixels.len().max(1) as f64, s.bytes_in.load(std::sync::atomic::Ordering::Relaxed) / 1024))
    })());
    ok &= step("extension negotiated (audio/clipboard/files)", (|| {
        let t0 = Instant::now();
        while !s.native.load(std::sync::atomic::Ordering::Relaxed) {
            if t0.elapsed() > Duration::from_secs(5) {
                anyhow::bail!("server did not acknowledge the PortlessVNC extension");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok("both sides are PortlessVNC".into())
    })());
    ok &= step("file transfer viewer -> server", (|| {
        let src = dir.join("hello.bin");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i * 31 % 251) as u8).collect();
        std::fs::write(&src, &data)?;
        s.send_files(vec![src]);
        let dest = dir.join("downloads").join("hello.bin");
        let t0 = Instant::now();
        loop {
            if let Ok(got) = std::fs::read(&dest) {
                if got.len() == data.len() {
                    anyhow::ensure!(got == data, "content mismatch");
                    return Ok(format!("{} bytes intact", got.len()));
                }
            }
            if t0.elapsed() > Duration::from_secs(10) {
                anyhow::bail!("file did not arrive");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })());
    s.close();

    // 2. classic client: VNC auth, ZRLE
    ok &= step("standard VNC client (classic VNC auth, ZRLE)", classic_client(&[ENC_ZRLE, ENC_CURSOR, ENC_DESKTOP_SIZE], PASSWORD));
    ok &= step("standard VNC client (Hextile + Raw)", classic_client(&[ENC_HEXTILE, ENC_RAW], PASSWORD));
    ok &= step("wrong password is rejected", match classic_client(&[ENC_RAW], "nope") {
        Ok(_) => Err(anyhow::anyhow!("wrong password accepted!")),
        Err(e) => Ok(format!("rejected ({e})")),
    });

    // 3. one-time password: works once, then rotates
    core.cfg.write().server.one_time_password = true;
    let otp = core.server.current_otp().unwrap_or_default();
    ok &= step("one-time password accepted", classic_client(&[ENC_RAW], &otp));
    ok &= step("same one-time password rejected the second time", match classic_client(&[ENC_RAW], &otp) {
        Ok(_) => Err(anyhow::anyhow!("reused OTP accepted!")),
        Err(_) => Ok(format!("rotated to a new code ({} chars)", core.server.current_otp().unwrap_or_default().len())),
    });
    core.cfg.write().server.permanent_password = false;
    ok &= step("permanent password off -> permanent password rejected", match classic_client(&[ENC_RAW], PASSWORD) {
        Ok(_) => Err(anyhow::anyhow!("permanent password still accepted")),
        Err(_) => Ok("rejected".into()),
    });

    core.server.disconnect_all();
    let _ = std::fs::remove_dir_all(&dir);
    println!("{}", if ok { "SELFTEST PASSED" } else { "SELFTEST FAILED" });
    if ok { 0 } else { 1 }
}

/// `PortlessVNC --vpntest <profile.ovpn>` (credentials from PVNC_VPN_USER /
/// PVNC_VPN_PASS): connect, report what the server pushed, ping the gateway,
/// try a TCP connection to the gateway through the tunnel, disconnect.
pub fn vpn_test(path: &str) -> i32 {
    let dir = std::env::temp_dir().join(format!("portlessvnc-vpntest-{}", std::process::id()));
    std::env::set_var("PORTLESS_CONFIG_DIR", &dir);
    let core = match crate::app::Core::new() {
        Ok(c) => c,
        Err(e) => {
            println!("[FAIL] core: {e:#}");
            return 1;
        }
    };
    let cfg = match crate::vpn::ovpn::OvpnConfig::load(std::path::Path::new(path)) {
        Ok(c) => c,
        Err(e) => {
            println!("[FAIL] profile: {e:#}");
            return 1;
        }
    };
    println!("[ OK ] profile parsed: {} remote(s), wrap {:?}, auth {}, user/pass {}", cfg.remotes.len(), std::mem::discriminant(&cfg.tls_wrap), cfg.auth_digest, cfg.auth_user_pass);
    for w in &cfg.warnings {
        println!("       note: {w}");
    }
    {
        let mut c = core.cfg.write();
        c.server.port = 5980;
        c.server.listen_direct = false;
        c.set_vnc_password(PASSWORD);
    }
    core.server.restart();
    core.vpn.connect(crate::vpn::ConnectRequest {
        profile_name: "test".into(),
        config: cfg,
        username: std::env::var("PVNC_VPN_USER").ok(),
        password: std::env::var("PVNC_VPN_PASS").ok(),
    });
    let t0 = Instant::now();
    let mut last = String::new();
    let mut code = 1;
    loop {
        let st = core.vpn.status();
        let s = format!("{:?}", st.state);
        if s != last {
            println!("       [{:>5.1}s] {s}", t0.elapsed().as_secs_f32());
            last = s;
        }
        match &st.state {
            crate::vpn::VpnState::Connected => {
                if st.gateway_checked || t0.elapsed() > Duration::from_secs(60) {
                    let i = st.info.clone().unwrap_or_default();
                    println!("[ OK ] connected: ip {:?}/{} gateway {:?} cipher {} peer-id {:?} ekm {} compress {:?} routes {:?}", i.ip, i.prefix, i.gateway, st.cipher, i.peer_id, i.ekm, i.compress, i.routes);
                    println!("[{}] gateway ping: {:?}", if st.gateway_rtt.is_some() { " OK " } else { "WARN" }, st.gateway_rtt);
                    if let Some(gw) = i.gateway {
                        for port in [443u16, 80, 22] {
                            let r = core.vpn.dial(std::net::SocketAddr::from((gw, port)), Duration::from_secs(4));
                            println!("       TCP {gw}:{port} through tunnel: {}", match r {
                                Ok(_) => "connected".to_string(),
                                Err(e) => e.to_string(),
                            });
                        }
                    }
                    if let Some(ip) = i.ip {
                        let r = classic_client_at(std::net::SocketAddr::from((ip, 5980)), &[ENC_ZRLE], PASSWORD);
                        println!("[{}] inbound VNC via VPN address {ip}:5980 (LAN -> pfSense -> tunnel -> this app): {}", if r.is_ok() { " OK " } else { "FAIL" }, match r { Ok(s) => s, Err(e) => format!("{e:#}") });
                    }
                    // keep the tunnel up briefly to watch keepalives
                    std::thread::sleep(Duration::from_secs(12));
                    let st = core.vpn.status();
                    println!("       after 12s: {:?}, {} bytes in / {} out", st.state, st.bytes_in, st.bytes_out);
                    code = if st.state == crate::vpn::VpnState::Connected { 0 } else { 1 };
                    break;
                }
            }
            crate::vpn::VpnState::Failed(_) | crate::vpn::VpnState::AuthFailed(_) => break,
            _ => {}
        }
        if t0.elapsed() > Duration::from_secs(90) {
            println!("[FAIL] timed out");
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    core.vpn.disconnect();
    std::thread::sleep(Duration::from_millis(500));
    let _ = std::fs::remove_dir_all(&dir);
    println!("{}", if code == 0 { "VPNTEST PASSED" } else { "VPNTEST FAILED" });
    code
}

fn vpn_core(tag: &str, port: u16, path: &str) -> anyhow::Result<std::sync::Arc<crate::app::Core>> {
    let dir = std::env::temp_dir().join(format!("portlessvnc-pair-{tag}-{}", std::process::id()));
    std::env::set_var("PORTLESS_CONFIG_DIR", &dir);
    let core = crate::app::Core::new()?;
    {
        let mut c = core.cfg.write();
        c.server.port = port;
        c.server.listen_direct = false;
        c.set_vnc_password(PASSWORD);
        c.download_dir = dir.join("downloads").to_string_lossy().into_owned();
    }
    core.save_config();
    core.server.restart();
    let cfg = crate::vpn::ovpn::OvpnConfig::load(std::path::Path::new(path))?;
    core.vpn.connect(crate::vpn::ConnectRequest { profile_name: tag.into(), config: cfg, username: std::env::var("PVNC_VPN_USER").ok(), password: std::env::var("PVNC_VPN_PASS").ok() });
    Ok(core)
}

/// `--vpnpair <profile>`: two complete instances (A and B) each join the VPN;
/// A opens a PortlessVNC session to B's VPN address through its own tunnel.
pub fn vpn_pair(path: &str) -> i32 {
    // Pretend another VNC server (RealVNC) owns B's port locally.
    let fake = std::net::TcpListener::bind(("127.0.0.1", 5992)).ok();
    if let Some(l) = fake.as_ref().and_then(|l| l.try_clone().ok()) {
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s = s;
                let _ = s.write_all(b"RFB 005.000\n");
            }
        });
        println!("       (fake RealVNC is holding 127.0.0.1:5992 for this test)");
    }
    let (a, b) = match (vpn_core("A", 5991, path), vpn_core("B", 5992, path)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            println!("[FAIL] setup: {e:#}");
            return 1;
        }
    };
    let t0 = Instant::now();
    let (ia, ib) = loop {
        if let (Some(x), Some(y)) = (a.vpn.vpn_ip(), b.vpn.vpn_ip()) {
            break (x, y);
        }
        if t0.elapsed() > Duration::from_secs(60) {
            println!("[FAIL] both VPN clients did not connect: A {:?} / B {:?}", a.vpn.status().state, b.vpn.status().state);
            return 1;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    println!("[ OK ] instance A VPN address {ia}, instance B VPN address {ib} ({:.1}s)", t0.elapsed().as_secs_f32());
    let mut ok = step(&format!("A routes {ib} through its tunnel"), if a.vpn.routes_to(ib.into()) { Ok("yes".into()) } else { Err(anyhow::anyhow!("no")) });
    let s = Session::start(a.clone(), &format!("{ib}::5992"), "", PASSWORD);
    ok &= step(&format!("A views B at {ib}::5992 (client-to-client over VPN)"), (|| {
        let t0 = Instant::now();
        loop {
            let st = s.state.lock().clone();
            match st {
                State::VerifyFingerprint { .. } => s.answer(Answer::Fingerprint(true)),
                State::Connected if s.updates.load(std::sync::atomic::Ordering::Relaxed) >= 2 && s.native.load(std::sync::atomic::Ordering::Relaxed) => break,
                State::Closed(m) => anyhow::bail!("closed: {m}"),
                State::NeedCredentials { .. } => anyhow::bail!("password rejected"),
                _ => {}
            }
            if t0.elapsed() > Duration::from_secs(30) {
                anyhow::bail!("timeout in state {st:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let fb = s.fb.lock();
        let nonblack = fb.pixels.iter().filter(|&&p| p & 0x00FF_FFFF != 0).count();
        Ok(format!("{}x{}, via_vpn={}, native ext, {:.0}% non-black, {} KB over the tunnel in {:.1}s", fb.width, fb.height, s.via_vpn.load(std::sync::atomic::Ordering::Relaxed), nonblack as f64 * 100.0 / fb.pixels.len().max(1) as f64, s.bytes_in.load(std::sync::atomic::Ordering::Relaxed) / 1024, t0.elapsed().as_secs_f32()))
    })());
    let seen_by_b = b.server.client_list().iter().any(|c| c.via_vpn && c.addr.ip() == std::net::IpAddr::V4(ia));
    ok &= step("B sees the viewer as a VPN client", if seen_by_b { Ok(format!("viewer {ia} [VPN]")) } else { Err(anyhow::anyhow!("not listed")) });
    ok &= step("isolation: other services on B are NOT reachable over the VPN", (|| {
        // a stand-in "other service" on this computer (e.g. what RealVNC or RDP would be)
        let other = std::net::TcpListener::bind(("127.0.0.1", 18080))?;
        std::thread::spawn(move || {
            for s in other.incoming().flatten() {
                let mut s = s;
                let _ = s.write_all(b"OTHER-SERVICE");
            }
        });
        let probe = || -> bool {
            match a.vpn.dial(std::net::SocketAddr::from((ib, 18080)), Duration::from_secs(4)) {
                Ok(mut s) => {
                    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                    let mut buf = [0u8; 13];
                    s.read_exact(&mut buf).is_ok() && &buf == b"OTHER-SERVICE"
                }
                Err(_) => false,
            }
        };
        anyhow::ensure!(!probe(), "port 18080 was reachable while sharing is off!");
        b.cfg.write().server.vpn_expose_all = true;
        let reachable = probe();
        b.cfg.write().server.vpn_expose_all = false;
        anyhow::ensure!(reachable, "opt-in sharing did not work");
        Ok("blocked by default; reachable only with the opt-in".into())
    })());
    ok &= step("shared text A <-> B", (|| {
        a.hub.note_local_edit("hello from A".into());
        let t0 = Instant::now();
        while b.hub.note_text() != "hello from A" {
            anyhow::ensure!(t0.elapsed() < Duration::from_secs(5), "B did not receive A's text");
            std::thread::sleep(Duration::from_millis(20));
        }
        anyhow::ensure!(b.hub.note_unread() && b.hub.note_window.load(std::sync::atomic::Ordering::Relaxed), "B's window did not pop open");
        b.hub.note_local_edit("hello from A\nhi back from B".into());
        let t1 = Instant::now();
        while a.hub.note_text() != "hello from A\nhi back from B" {
            anyhow::ensure!(t1.elapsed() < Duration::from_secs(5), "A did not receive B's reply");
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(format!("A->B in {} ms, B->A in {} ms", (t1 - t0).as_millis(), t1.elapsed().as_millis()))
    })());
    ok &= step("file A -> B over VPN", (|| {
        let src = std::env::temp_dir().join(format!("pvnc-pair-{}.bin", std::process::id()));
        let data: Vec<u8> = (0..1_000_000u32).map(|i| (i * 7 % 253) as u8).collect();
        std::fs::write(&src, &data)?;
        let t = Instant::now();
        s.send_files(vec![src.clone()]);
        let dest = std::path::PathBuf::from(b.cfg.read().download_dir.clone()).join(src.file_name().unwrap());
        loop {
            if let Ok(got) = std::fs::read(&dest) {
                if got.len() == data.len() {
                    anyhow::ensure!(got == data, "content mismatch");
                    let _ = std::fs::remove_file(&src);
                    return Ok(format!("1 MB intact in {:.1}s", t.elapsed().as_secs_f32()));
                }
            }
            if t.elapsed() > Duration::from_secs(30) {
                anyhow::bail!("file did not arrive");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })());
    s.close();
    a.vpn.disconnect();
    b.vpn.disconnect();
    std::thread::sleep(Duration::from_millis(500));
    println!("{}", if ok { "VPNPAIR PASSED" } else { "VPNPAIR FAILED" });
    if ok { 0 } else { 1 }
}

fn save_bmp(fb: &crate::rfb::decode::FrameBuffer, path: &str) -> std::io::Result<()> {
    let (w, h) = (fb.width, fb.height);
    let row = (w * 3 + 3) & !3;
    let size = 54 + row * h;
    let mut b = Vec::with_capacity(size);
    b.extend_from_slice(b"BM");
    b.extend_from_slice(&(size as u32).to_le_bytes());
    b.extend_from_slice(&[0, 0, 0, 0, 54, 0, 0, 0, 40, 0, 0, 0]);
    b.extend_from_slice(&(w as i32).to_le_bytes());
    b.extend_from_slice(&(h as i32).to_le_bytes());
    b.extend_from_slice(&[1, 0, 24, 0, 0, 0, 0, 0]);
    b.extend_from_slice(&((row * h) as u32).to_le_bytes());
    b.extend_from_slice(&[0u8; 16]);
    for y in (0..h).rev() {
        for x in 0..w {
            let p = fb.pixels[y * w + x];
            b.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8]);
        }
        b.extend(std::iter::repeat(0u8).take(row - w * 3));
    }
    std::fs::write(path, b)
}

fn xt_scancode(c: char) -> u32 {
    const LETTERS: [u32; 26] = [0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1f, 0x14, 0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c];
    match c {
        'a'..='z' => LETTERS[c as usize - 'a' as usize],
        ' ' => 0x39,
        _ => 0,
    }
}

/// `--keyremote <profile.ovpn> <addr> <out.bmp> [x y] [text]`: join the VPN,
/// view <addr>, optionally click (x,y), type <text> (first half as keysyms,
/// second half as scancodes) and save the remote screen to <out.bmp>.
/// Credentials: PVNC_VPN_USER / PVNC_VPN_PASS / PVNC_VNC_PASS.
pub fn key_remote(args: &[String]) -> i32 {
    let (Some(profile), Some(addr), Some(out)) = (args.first(), args.get(1), args.get(2)) else {
        println!("usage: --keyremote profile.ovpn addr out.bmp [x y] [text]");
        return 2;
    };
    let click: Option<(u16, u16)> = match (args.get(3).and_then(|v| v.parse().ok()), args.get(4).and_then(|v| v.parse().ok())) {
        (Some(x), Some(y)) => Some((x, y)),
        _ => None,
    };
    let text = args.get(if click.is_some() { 5 } else { 3 }).cloned().unwrap_or_default();
    let core = match vpn_core("K", 5995, profile) {
        Ok(c) => c,
        Err(e) => {
            println!("[FAIL] {e:#}");
            return 1;
        }
    };
    let t0 = Instant::now();
    while core.vpn.vpn_ip().is_none() {
        if t0.elapsed() > Duration::from_secs(40) {
            println!("[FAIL] VPN: {:?}", core.vpn.status().state);
            return 1;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    println!("[ OK ] VPN up as {:?}", core.vpn.vpn_ip());
    let pass = std::env::var("PVNC_VNC_PASS").unwrap_or_default();
    let s = Session::start(core.clone(), addr, "", &pass);
    let t0 = Instant::now();
    loop {
        let st = s.state.lock().clone();
        match st {
            State::VerifyFingerprint { .. } => s.answer(Answer::Fingerprint(true)),
            State::Connected if s.updates.load(std::sync::atomic::Ordering::Relaxed) >= 2 => break,
            State::Closed(m) => {
                println!("[FAIL] session: {m}");
                return 1;
            }
            State::NeedCredentials { .. } => {
                println!("[FAIL] password rejected");
                return 1;
            }
            _ => {}
        }
        if t0.elapsed() > Duration::from_secs(30) {
            println!("[FAIL] timeout ({st:?})");
            return 1;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("[ OK ] connected to {addr} ({}, native={})", s.desktop_name.lock(), s.native.load(std::sync::atomic::Ordering::Relaxed));
    std::thread::sleep(Duration::from_millis(1500));
    if let Some((x, y)) = click {
        s.pointer(x, y, 0);
        std::thread::sleep(Duration::from_millis(100));
        s.pointer(x, y, 1);
        std::thread::sleep(Duration::from_millis(80));
        s.pointer(x, y, 0);
        std::thread::sleep(Duration::from_millis(400));
        println!("       clicked at {x},{y}");
    }
    if !text.is_empty() {
        let half = text.chars().count() / 2;
        for (i, c) in text.chars().enumerate() {
            let keysym = crate::platform::input::char_to_keysym(c);
            let xt = if i >= half { xt_scancode(c) } else { 0 };
            s.key(true, keysym, xt);
            std::thread::sleep(Duration::from_millis(25));
            s.key(false, keysym, xt);
            std::thread::sleep(Duration::from_millis(25));
        }
        println!("       typed {} chars ({} as keysyms, rest as scancodes)", text.chars().count(), half);
        std::thread::sleep(Duration::from_millis(1500));
    }
    let r = save_bmp(&s.fb.lock(), out);
    println!("[{}] snapshot -> {out}", if r.is_ok() { " OK " } else { "FAIL" });
    s.close();
    core.vpn.disconnect();
    std::thread::sleep(Duration::from_millis(500));
    0
}

/// `--remote addr out.bmp [op...]`: drive a VNC server directly (no VPN) for
/// troubleshooting, then save a snapshot. Password from PVNC_VNC_PASS. Ops:
/// `click:x,y` `dbl:x,y` `right:x,y` `type:text` `key:win+r` `wait:ms`.
pub fn remote(args: &[String]) -> i32 {
    let (Some(addr), Some(out)) = (args.first(), args.get(1)) else {
        println!("usage: --remote addr out.bmp [click:x,y] [dbl:x,y] [right:x,y] [type:text] [key:win+r] [wait:ms]");
        return 2;
    };
    let dir = std::env::temp_dir().join(format!("portlessvnc-remote-{}", std::process::id()));
    std::env::set_var("PORTLESS_CONFIG_DIR", &dir);
    let core = match crate::app::Core::new() {
        Ok(c) => c,
        Err(e) => {
            println!("[FAIL] {e:#}");
            return 1;
        }
    };
    let pass = std::env::var("PVNC_VNC_PASS").unwrap_or_default();
    let s = Session::start(core.clone(), addr, "", &pass);
    let t0 = Instant::now();
    loop {
        let st = s.state.lock().clone();
        match st {
            State::VerifyFingerprint { .. } => s.answer(Answer::Fingerprint(true)),
            State::Connected if s.updates.load(std::sync::atomic::Ordering::Relaxed) >= 1 => break,
            State::Closed(m) => {
                println!("[FAIL] session: {m}");
                return 1;
            }
            State::NeedCredentials { .. } => {
                println!("[FAIL] password rejected");
                return 1;
            }
            _ => {}
        }
        if t0.elapsed() > Duration::from_secs(30) {
            println!("[FAIL] timeout ({st:?})");
            return 1;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("[ OK ] connected to {addr} ({})", s.desktop_name.lock());
    std::thread::sleep(Duration::from_millis(800));
    let xy = |v: &str| -> Option<(u16, u16)> {
        let (x, y) = v.split_once(',')?;
        Some((x.trim().parse().ok()?, y.trim().parse().ok()?))
    };
    let click = |x: u16, y: u16, mask: u8| {
        s.pointer(x, y, 0);
        std::thread::sleep(Duration::from_millis(80));
        s.pointer(x, y, mask);
        std::thread::sleep(Duration::from_millis(60));
        s.pointer(x, y, 0);
        std::thread::sleep(Duration::from_millis(80));
    };
    for op in &args[2..] {
        let (kind, val) = op.split_once(':').unwrap_or((op, ""));
        match kind {
            "click" | "right" | "dbl" => {
                let Some((x, y)) = xy(val) else {
                    println!("[FAIL] bad position: {op}");
                    continue;
                };
                click(x, y, if kind == "right" { 4 } else { 1 });
                if kind == "dbl" {
                    click(x, y, 1);
                }
            }
            "type" => {
                for c in val.chars() {
                    let keysym = crate::platform::input::char_to_keysym(c);
                    s.key(true, keysym, 0);
                    std::thread::sleep(Duration::from_millis(20));
                    s.key(false, keysym, 0);
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            "key" => {
                let keys: Vec<(u32, u32)> = val
                    .split('+')
                    .filter_map(|k| {
                        Some(match k.to_ascii_lowercase().as_str() {
                            "win" => crate::keys::WIN,
                            "ctrl" => crate::keys::CTRL,
                            "alt" => crate::keys::ALT,
                            "shift" => crate::keys::SHIFT,
                            "enter" => (0xff0d, 0x1c),
                            "esc" => (0xff1b, 0x01),
                            "tab" => (0xff09, 0x0f),
                            o if o.chars().count() == 1 => (crate::platform::input::char_to_keysym(o.chars().next()?), 0),
                            _ => return None,
                        })
                    })
                    .collect();
                s.key_combo(&keys);
            }
            "wait" => std::thread::sleep(Duration::from_millis(val.parse().unwrap_or(500))),
            _ => println!("[FAIL] unknown op: {op}"),
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    std::thread::sleep(Duration::from_millis(1500));
    let r = save_bmp(&s.fb.lock(), out);
    println!("[{}] snapshot -> {out}", if r.is_ok() { " OK " } else { "FAIL" });
    s.close();
    std::thread::sleep(Duration::from_millis(300));
    let _ = std::fs::remove_dir_all(&dir);
    0
}

fn classic_client(encs: &[i32], password: &str) -> anyhow::Result<String> {
    classic_client_at(std::net::SocketAddr::from(([127, 0, 0, 1], BRIDGE.load(std::sync::atomic::Ordering::SeqCst))), encs, password)
}

fn classic_client_at(addr: std::net::SocketAddr, encs: &[i32], password: &str) -> anyhow::Result<String> {
    let mut t = TcpStream::connect_timeout(&addr, Duration::from_secs(8))?;
    t.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut ver = [0u8; 12];
    t.read_exact(&mut ver)?;
    t.write_all(b"RFB 003.008\n")?;
    let n = t.read_u8()? as usize;
    let types = t.read_vec(n)?;
    anyhow::ensure!(types.contains(&SEC_VNC_AUTH), "server did not offer VNC auth: {types:?}");
    t.write_all(&[SEC_VNC_AUTH])?;
    let mut ch = [0u8; 16];
    t.read_exact(&mut ch)?;
    t.write_all(&vncauth::response(password, &ch))?;
    let res = t.read_u32()?;
    if res != 0 {
        let l = t.read_u32()? as usize;
        let msg = String::from_utf8_lossy(&t.read_vec(l)?).into_owned();
        anyhow::bail!("auth failed: {msg}");
    }
    t.write_all(&[1])?;
    let w = t.read_u16()? as usize;
    let h = t.read_u16()? as usize;
    t.skip(16)?;
    let nl = t.read_u32()? as usize;
    let name = String::from_utf8_lossy(&t.read_vec(nl)?).into_owned();
    // ask for a 16-bit format to exercise pixel conversion
    let pf = PixelFormat { bpp: 16, depth: 16, big_endian: false, true_color: true, rmax: 31, gmax: 63, bmax: 31, rshift: 11, gshift: 5, bshift: 0 };
    let mut m = vec![C2S_SET_PIXEL_FORMAT, 0, 0, 0];
    pf.write(&mut m);
    m.push(C2S_SET_ENCODINGS);
    m.push(0);
    m.put_u16(encs.len() as u16);
    for e in encs {
        m.put_i32(*e);
    }
    m.extend_from_slice(&[C2S_FB_UPDATE_REQUEST, 0]);
    m.put_u16(0);
    m.put_u16(0);
    m.put_u16(w as u16);
    m.put_u16(h as u16);
    t.write_all(&m)?;
    let mut fb = FrameBuffer::new(w, h);
    let mut dec = DecoderState::new(pf);
    let mut rects = 0;
    loop {
        let typ = t.read_u8()?;
        anyhow::ensure!(typ == S2C_FB_UPDATE, "unexpected message {typ}");
        t.read_u8()?;
        let n = t.read_u16()?;
        let mut pixels = false;
        for _ in 0..n {
            let r = Rect::new(t.read_u16()?, t.read_u16()?, t.read_u16()?, t.read_u16()?);
            let enc = t.read_i32()?;
            if let RectResult::Pixels = decode_rect(&mut dec, r, enc, &mut t, &mut fb)? {
                pixels = true;
                rects += 1;
            }
        }
        if pixels {
            break;
        }
    }
    let nonblack = fb.pixels.iter().filter(|&&p| p & 0x00FF_FFFF != 0).count();
    Ok(format!("'{name}' {w}x{h}, {rects} rects decoded, {:.1}% non-black", nonblack as f64 * 100.0 / (w * h).max(1) as f64))
}
