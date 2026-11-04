//! VNC server: listener, shared screen-capture service and client registry.

mod conn;

pub use conn::ClientConn;

use crate::audio::AudioHub;
use crate::config::Config;
use crate::hub::Hub;
use crate::rfb::encode::Frame;
use crate::tls::ServerIdentity;
use parking_lot::{Condvar, Mutex, RwLock};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct CursorShape {
    pub width: usize,
    pub height: usize,
    pub hot_x: usize,
    pub hot_y: usize,
    /// BGRA, straight alpha
    pub bgra: Vec<u8>,
}

// ---- capture service -------------------------------------------------------

#[derive(Clone, Default)]
pub struct Snapshot {
    pub frame: Option<Arc<Frame>>,
    pub seq: u64,
    pub cursor: Option<Arc<CursorShape>>,
    pub cursor_seq: u64,
    pub origin: (i32, i32),
}

pub struct CaptureService {
    snap: Mutex<Snapshot>,
    cond: Condvar,
    users: AtomicUsize,
    running: AtomicBool,
    pub monitor: AtomicUsize,
    pub fps: AtomicU32,
    pub error: Mutex<Option<String>>,
}

impl CaptureService {
    fn new(monitor: usize, fps: u32) -> Arc<Self> {
        Arc::new(CaptureService {
            snap: Mutex::new(Snapshot::default()),
            cond: Condvar::new(),
            users: AtomicUsize::new(0),
            running: AtomicBool::new(false),
            monitor: AtomicUsize::new(monitor),
            fps: AtomicU32::new(fps.clamp(1, 120)),
            error: Mutex::new(None),
        })
    }

    pub fn acquire(self: &Arc<Self>) {
        self.users.fetch_add(1, Ordering::SeqCst);
        if !self.running.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            std::thread::Builder::new().name("capture".into()).spawn(move || me.run()).ok();
        }
    }

    pub fn release(&self) {
        self.users.fetch_sub(1, Ordering::SeqCst);
    }

    fn run(self: Arc<Self>) {
        let mut monitor = self.monitor.load(Ordering::Relaxed);
        let mut cap: Option<crate::platform::capture::Capturer> = None;
        while self.users.load(Ordering::SeqCst) > 0 {
            // service mode: follow the sign-in / UAC / lock-screen desktop
            #[cfg(windows)]
            if crate::config::machine_mode() {
                if let Some(name) = crate::platform::desktop::sync_thread() {
                    log::info!("capture: switched to the '{name}' desktop");
                    cap = None;
                }
            }
            let want = self.monitor.load(Ordering::Relaxed);
            if want != monitor {
                monitor = want;
                cap = None;
            }
            if cap.is_none() {
                match crate::platform::capture::Capturer::new(monitor) {
                    Ok(c) => {
                        *self.error.lock() = None;
                        cap = Some(c);
                    }
                    Err(e) => {
                        let msg = format!("Screen capture failed: {e}");
                        if self.error.lock().as_deref() != Some(&msg) {
                            log::warn!("{msg}");
                        }
                        *self.error.lock() = Some(msg);
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                }
            }
            let c = cap.as_mut().unwrap();
            let interval = Duration::from_millis(1000 / self.fps.load(Ordering::Relaxed).max(1) as u64);
            let t0 = Instant::now();
            let frame = c.capture(interval.as_millis() as u32);
            let cursor = c.cursor();
            let origin = c.origin();
            let mut changed = false;
            {
                let mut s = self.snap.lock();
                s.origin = origin;
                match frame {
                    Ok(Some(f)) => {
                        s.frame = Some(Arc::new(f));
                        s.seq += 1;
                        changed = true;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        log::warn!("capture: {e}");
                        cap = None;
                    }
                }
                if let Some(cs) = cursor {
                    s.cursor = Some(Arc::new(cs));
                    s.cursor_seq += 1;
                    changed = true;
                }
            }
            if changed {
                self.cond.notify_all();
            }
            let el = t0.elapsed();
            if el < interval {
                std::thread::sleep(interval - el);
            }
        }
        self.running.store(false, Ordering::SeqCst);
        if self.users.load(Ordering::SeqCst) > 0 && !self.running.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            std::thread::spawn(move || me.run());
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        self.snap.lock().clone()
    }

    /// Wait until the frame or cursor is newer than the given sequence numbers.
    pub fn wait_newer(&self, seq: u64, cursor_seq: u64, timeout: Duration) -> Snapshot {
        let mut s = self.snap.lock();
        if s.seq == seq && s.cursor_seq == cursor_seq {
            self.cond.wait_for(&mut s, timeout);
        }
        s.clone()
    }

    /// Wait (up to `timeout`) for the first frame after startup.
    pub fn wait_first(&self, timeout: Duration) -> Snapshot {
        let deadline = Instant::now() + timeout;
        let mut s = self.snap.lock();
        while s.frame.is_none() && Instant::now() < deadline {
            self.cond.wait_for(&mut s, Duration::from_millis(100));
        }
        s.clone()
    }
}

// ---- server -----------------------------------------------------------------

#[derive(Clone, Default)]
pub struct ServerStatus {
    pub listening: Option<SocketAddr>,
    pub error: Option<String>,
    /// Configured port that was taken by another program (we fell back)
    pub busy_port: Option<u16>,
}

pub struct Server {
    pub cfg: Arc<RwLock<Config>>,
    pub hub: Arc<Hub>,
    pub audio: Arc<AudioHub>,
    pub identity: ServerIdentity,
    tls_cfg: Arc<rustls::ServerConfig>,
    pub capture: Arc<CaptureService>,
    pub clients: Mutex<Vec<Arc<ClientConn>>>,
    pub status: Mutex<ServerStatus>,
    /// Loopback source port of a VPN-bridged connection -> real VPN peer.
    pub vpn_bridges: Mutex<HashMap<u16, SocketAddr>>,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    generation: AtomicUsize,
    /// Current one-time password (never saved to disk)
    otp: Mutex<String>,
    vpn_port: std::sync::atomic::AtomicU16,
    /// The background service hosts this computer: don't host from this process.
    suppressed: AtomicBool,
}

impl Server {
    pub fn new(cfg: Arc<RwLock<Config>>, hub: Arc<Hub>, audio: Arc<AudioHub>, identity: ServerIdentity) -> anyhow::Result<Arc<Server>> {
        let tls_cfg = crate::tls::server_config(&identity)?;
        let (mon, fps) = {
            let c = cfg.read();
            (c.server.monitor, c.server.max_fps)
        };
        Ok(Arc::new(Server {
            cfg,
            hub,
            audio,
            identity,
            tls_cfg,
            capture: CaptureService::new(mon, fps),
            clients: Mutex::new(Vec::new()),
            status: Mutex::new(ServerStatus::default()),
            vpn_bridges: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            generation: AtomicUsize::new(0),
            otp: Mutex::new(crate::util::random_password(8)),
            vpn_port: std::sync::atomic::AtomicU16::new(0),
            suppressed: AtomicBool::new(false),
        }))
    }

    /// (Re)start the listener according to the current config.
    pub fn restart(self: &Arc<Self>) {
        let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let (enabled, port, direct, mon, fps, bind_ip) = {
            let c = self.cfg.read();
            let ip: std::net::IpAddr = c.server.bind_address.parse().unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));
            (c.server.enabled, c.server.port, c.server.listen_direct, c.server.monitor, c.server.max_fps, ip)
        };
        self.capture.monitor.store(mon, Ordering::Relaxed);
        self.capture.fps.store(fps.clamp(1, 120), Ordering::Relaxed);
        if !enabled || self.suppressed.load(Ordering::SeqCst) {
            self.vpn_port.store(0, Ordering::SeqCst);
            *self.status.lock() = ServerStatus::default();
            self.disconnect_all();
            return;
        }
        // 1. Private loopback listener for the VPN bridge. Its port is picked
        //    by the OS, so it can never collide with another VNC server.
        match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => {
                let p = l.local_addr().map(|a| a.port()).unwrap_or(0);
                self.vpn_port.store(p, Ordering::SeqCst);
                self.spawn_accept(l, gen, true);
            }
            Err(e) => {
                self.vpn_port.store(0, Ordering::SeqCst);
                log::warn!("VPN bridge listener failed: {e}");
            }
        }
        // 2. Direct (LAN/WAN) listener on the configured port, falling back to
        //    the next ports if another program (e.g. RealVNC) already has it.
        if !direct {
            *self.status.lock() = ServerStatus { listening: None, error: None, busy_port: None };
            crate::util::request_repaint();
            return;
        }
        let me = self.clone();
        std::thread::Builder::new()
            .name("vnc-bind".into())
            .spawn(move || {
                let candidates: Vec<u16> = (0..10u16).filter_map(|i| port.checked_add(i)).collect();
                // the previous listener may still hold the port for a moment
                for attempt in 0..8 {
                    for &p in &candidates {
                        if me.generation.load(Ordering::SeqCst) != gen {
                            return;
                        }
                        let bind = SocketAddr::new(bind_ip, p);
                        if let Ok(l) = TcpListener::bind(bind) {
                            let busy = (p != port).then_some(port);
                            match busy {
                                Some(b) => log::info!("Port {b} is used by another program; direct connections use port {p} (the VPN address still uses {b})"),
                                None => log::info!("VNC server listening on {bind}"),
                            }
                            *me.status.lock() = ServerStatus { listening: Some(bind), error: None, busy_port: busy };
                            crate::util::request_repaint();
                            me.spawn_accept(l, gen, false);
                            return;
                        }
                        if attempt == 0 && p == port {
                            // our own previous listener may be closing; retry the preferred port first
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
                *me.status.lock() = ServerStatus { listening: None, error: Some(format!("Ports {}-{} are all in use", port, port.saturating_add(9))), busy_port: Some(port) };
                log::warn!("VNC server could not bind any port from {port}");
                crate::util::request_repaint();
            })
            .ok();
    }

    fn spawn_accept(self: &Arc<Self>, l: TcpListener, gen: usize, vpn: bool) {
        let me = self.clone();
        std::thread::Builder::new()
            .name(if vpn { "vnc-listen-vpn" } else { "vnc-listen" }.into())
            .spawn(move || {
                let _ = l.set_nonblocking(true);
                while me.generation.load(Ordering::SeqCst) == gen {
                    match l.accept() {
                        Ok((s, addr)) => {
                            let _ = s.set_nonblocking(false);
                            let me2 = me.clone();
                            std::thread::Builder::new().name("vnc-client".into()).spawn(move || conn::handle(me2, s, addr, vpn)).ok();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
                        Err(e) => {
                            log::warn!("accept: {e}");
                            std::thread::sleep(Duration::from_millis(200));
                        }
                    }
                }
            })
            .ok();
    }

    /// Port of the private loopback listener the VPN bridge connects to (0 = none).
    pub fn vpn_bridge_port(&self) -> u16 {
        if self.cfg.read().server.enabled { self.vpn_port.load(Ordering::SeqCst) } else { 0 }
    }

    /// Port actually used for direct connections (may differ from the configured one).
    pub fn direct_port(&self) -> Option<u16> {
        self.status.lock().listening.map(|a| a.port())
    }

    pub fn set_suppressed(&self, on: bool) {
        self.suppressed.store(on, Ordering::SeqCst);
    }

    pub fn suppressed(&self) -> bool {
        self.suppressed.load(Ordering::SeqCst)
    }

    /// The one-time password, if that option is enabled.
    pub fn current_otp(&self) -> Option<String> {
        if self.cfg.read().server.one_time_password { Some(self.otp.lock().clone()) } else { None }
    }

    pub fn rotate_otp(&self) {
        *self.otp.lock() = crate::util::random_password(8);
        crate::util::request_repaint();
    }

    pub fn tls_config(&self) -> Arc<rustls::ServerConfig> {
        self.tls_cfg.clone()
    }

    pub fn port(&self) -> u16 {
        self.cfg.read().server.port
    }

    pub fn disconnect_all(&self) {
        for c in self.clients.lock().iter() {
            c.close();
        }
    }

    pub fn client_list(&self) -> Vec<Arc<ClientConn>> {
        self.clients.lock().clone()
    }

    fn blocked(&self, ip: IpAddr) -> bool {
        let f = self.failures.lock();
        matches!(f.get(&ip), Some((n, t)) if *n >= 5 && t.elapsed() < Duration::from_secs(60))
    }

    fn note_failure(&self, ip: IpAddr) {
        let mut f = self.failures.lock();
        let e = f.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() > Duration::from_secs(60) {
            *e = (0, Instant::now());
        }
        e.0 += 1;
        e.1 = Instant::now();
    }
}
