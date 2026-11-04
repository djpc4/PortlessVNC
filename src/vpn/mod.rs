//! Built-in OpenVPN client (userspace, no TUN/TAP driver, no admin rights).
//!
//! Connects to any standard OpenVPN server (pfSense, OPNsense, OpenVPN
//! Community/Access Server, ...) using a normal .ovpn profile, and runs a
//! private TCP/IP stack on the assigned VPN address. Other machines on the
//! VPN can then reach this computer's VNC server at that address without any
//! port forwarding (the server must allow client-to-client traffic).

pub mod certs;
pub mod crypto;
pub mod engine;
pub mod netstack;
pub mod ovpn;
pub mod relay;

use crate::config::Config;
use crate::server::Server;
use engine::{Engine, Event, PushInfo};
use netstack::{NetCmd, NetConfig, NetHandle};
use ovpn::{OvpnConfig, Proto, Proxy};
use parking_lot::{Mutex, RwLock};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};

#[derive(Clone, Debug, PartialEq)]
pub enum VpnState {
    Disconnected,
    Connecting(String),
    Connected,
    Reconnecting(String),
    Failed(String),
    AuthFailed(String),
    Challenge { text: String, echo: bool },
}

#[derive(Clone, Debug)]
pub struct VpnStatus {
    pub state: VpnState,
    pub profile: String,
    pub info: Option<PushInfo>,
    pub server: Option<SocketAddr>,
    pub cipher: String,
    pub since: Option<Instant>,
    pub gateway_rtt: Option<Duration>,
    pub gateway_checked: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl Default for VpnStatus {
    fn default() -> Self {
        VpnStatus { state: VpnState::Disconnected, profile: String::new(), info: None, server: None, cipher: String::new(), since: None, gateway_rtt: None, gateway_checked: false, bytes_in: 0, bytes_out: 0 }
    }
}

/// The port the VNC server listens on inside a tunnel: never on a guest VPN.
fn inbound_port(guest: bool, server_enabled: bool, port: u16) -> Option<u16> {
    (server_enabled && !guest).then_some(port)
}

#[cfg(test)]
mod inbound_tests {
    #[test]
    fn a_guest_vpn_never_listens() {
        assert_eq!(super::inbound_port(true, true, 5900), None);
        assert_eq!(super::inbound_port(true, false, 5900), None);
        assert_eq!(super::inbound_port(false, true, 5900), Some(5900));
        assert_eq!(super::inbound_port(false, false, 5900), None);
    }
}

pub struct ConnectRequest {
    pub profile_name: String,
    pub config: OvpnConfig,
    pub username: Option<String>,
    pub password: Option<String>,
}

struct Pending {
    challenge: Option<(String, String)>, // state_id, user
    req: Option<Arc<ConnectRequest>>,
}

pub struct VpnManager {
    rt: tokio::runtime::Runtime,
    cfg: Arc<RwLock<Config>>,
    server: Arc<Server>,
    /// Outbound only: nothing on this computer can be reached through this VPN.
    guest: bool,
    pub status: Arc<Mutex<VpnStatus>>,
    net: Arc<Mutex<Option<NetHandle>>>,
    stop: Mutex<Option<(Arc<Notify>, Arc<AtomicBool>)>>,
    pending: Mutex<Pending>,
}

impl VpnManager {
    pub fn new(cfg: Arc<RwLock<Config>>, server: Arc<Server>) -> Arc<VpnManager> {
        Self::build(cfg, server, false)
    }

    /// A guest VPN: only for connecting out to its clients. The VNC server does
    /// not listen on it and no local port is forwarded, whatever the settings say.
    pub fn new_guest(cfg: Arc<RwLock<Config>>, server: Arc<Server>) -> Arc<VpnManager> {
        Self::build(cfg, server, true)
    }

    fn build(cfg: Arc<RwLock<Config>>, server: Arc<Server>, guest: bool) -> Arc<VpnManager> {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().thread_name("vpn").build().expect("tokio runtime");
        Arc::new(VpnManager { rt, cfg, server, guest, status: Arc::new(Mutex::new(VpnStatus::default())), net: Arc::new(Mutex::new(None)), stop: Mutex::new(None), pending: Mutex::new(Pending { challenge: None, req: None }) })
    }

    pub fn status(&self) -> VpnStatus {
        self.status.lock().clone()
    }

    pub fn vpn_ip(&self) -> Option<Ipv4Addr> {
        let s = self.status.lock();
        if s.state == VpnState::Connected { s.info.as_ref().and_then(|i| i.ip) } else { None }
    }

    pub fn connect(self: &Arc<Self>, req: ConnectRequest) {
        self.disconnect();
        let req = Arc::new(req);
        self.pending.lock().req = Some(req.clone());
        let stop = Arc::new(Notify::new());
        let stopped = Arc::new(AtomicBool::new(false));
        *self.stop.lock() = Some((stop.clone(), stopped.clone()));
        {
            let mut s = self.status.lock();
            *s = VpnStatus { state: VpnState::Connecting("Starting...".into()), profile: req.profile_name.clone(), ..Default::default() };
        }
        let me = self.clone();
        self.rt.spawn(async move { me.tunnel_main(req, stop, stopped).await });
    }

    /// Answer a dynamic (CRV1) challenge from the server.
    pub fn answer_challenge(self: &Arc<Self>, response: &str) {
        let (ch, req) = {
            let p = self.pending.lock();
            (p.challenge.clone(), p.req.clone())
        };
        if let (Some((state_id, user)), Some(req)) = (ch, req) {
            let r = ConnectRequest { profile_name: req.profile_name.clone(), config: req.config.clone(), username: Some(user), password: Some(format!("CRV1::{state_id}::{response}")) };
            self.connect(r);
        }
    }

    pub fn disconnect(&self) {
        if let Some((n, flag)) = self.stop.lock().take() {
            flag.store(true, Ordering::SeqCst);
            n.notify_waiters();
            n.notify_one();
        }
        *self.net.lock() = None;
        let mut s = self.status.lock();
        if !matches!(s.state, VpnState::Failed(_) | VpnState::AuthFailed(_) | VpnState::Challenge { .. }) {
            s.state = VpnState::Disconnected;
        }
        s.info = None;
        crate::util::request_repaint();
    }

    /// Should a connection to `ip` go through the tunnel?
    pub fn routes_to(&self, ip: IpAddr) -> bool {
        let IpAddr::V4(ip) = ip else { return false };
        let s = self.status.lock();
        if s.state != VpnState::Connected || self.net.lock().is_none() {
            return false;
        }
        let Some(info) = s.info.as_ref() else { return false };
        let in_net = |net: Ipv4Addr, prefix: u8| {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        };
        if let Some(own) = info.ip {
            if in_net(own, info.prefix) {
                return true;
            }
        }
        info.routes.iter().any(|(n, p)| in_net(*n, *p)) || Some(ip) == info.gateway
    }

    /// Open a TCP connection through the tunnel (blocking).
    pub fn dial(&self, addr: SocketAddr, timeout: Duration) -> io::Result<std::net::TcpStream> {
        let SocketAddr::V4(v4) = addr else { return Err(io::Error::new(io::ErrorKind::Unsupported, "IPv6 over the VPN is not supported")) };
        let net = self.net.lock().clone().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "VPN not connected"))?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        net.cmd.send(NetCmd::Dial { addr: v4, timeout, reply: tx }).map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "VPN stack stopped"))?;
        let s = self.rt.block_on(async { tokio::time::timeout(timeout + Duration::from_secs(2), rx).await });
        match s {
            Ok(Ok(r)) => {
                let st = r?;
                st.set_nonblocking(false)?;
                Ok(st)
            }
            _ => Err(io::Error::new(io::ErrorKind::TimedOut, "VPN connection timed out")),
        }
    }

    fn set_state(&self, st: VpnState) {
        self.status.lock().state = st;
        crate::util::request_repaint();
    }

    async fn tunnel_main(self: Arc<Self>, req: Arc<ConnectRequest>, stop: Arc<Notify>, stopped: Arc<AtomicBool>) {
        let mut backoff = Duration::from_secs(2);
        loop {
            if stopped.load(Ordering::SeqCst) {
                break;
            }
            let since_before = self.status.lock().since;
            let res = self.run_once(&req, &stop, &stopped).await;
            *self.net.lock() = None;
            let (ever_connected, connected_this_run) = {
                let mut s = self.status.lock();
                s.info = None;
                (s.since.is_some(), s.since != since_before)
            };
            if stopped.load(Ordering::SeqCst) {
                break;
            }
            if connected_this_run {
                backoff = Duration::from_secs(2); // it was working: retry quickly
            }
            // "Keep the VPN connected": once this profile has worked, treat
            // server-side errors as temporary and keep retrying.
            // (the service always keeps trying: at boot the network or server may not be ready yet)
            let persistent = self.cfg.read().vpn.keep_connected && (ever_connected || crate::config::machine_mode());
            match res {
                Ok(Exit::Stopped) => break,
                Ok(Exit::Fatal(m)) if persistent => {
                    log::warn!("VPN: {m}; will keep retrying (Keep the VPN connected is on)");
                    self.set_state(VpnState::Reconnecting(m));
                    backoff = backoff.max(Duration::from_secs(15));
                }
                Ok(Exit::Fatal(m)) => {
                    log::warn!("VPN: {m}");
                    self.set_state(VpnState::Failed(m));
                    break;
                }
                Ok(Exit::AuthFailed(m)) if persistent => {
                    // don't hammer the account: try again in 5 minutes
                    log::warn!("VPN authentication failed: {m}; retrying in 5 minutes");
                    self.set_state(VpnState::Reconnecting(format!("login rejected ({m}) - retrying in 5 minutes")));
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(300)) => {}
                        _ = stop.notified() => break,
                    }
                    continue;
                }
                Ok(Exit::AuthFailed(m)) => {
                    log::warn!("VPN authentication failed: {m}");
                    self.set_state(VpnState::AuthFailed(m));
                    break;
                }
                Ok(Exit::Challenge { state_id, user, text, echo }) => {
                    self.pending.lock().challenge = Some((state_id, user));
                    self.set_state(VpnState::Challenge { text, echo });
                    break;
                }
                Ok(Exit::Restart(m)) | Err(Exit::Restart(m)) => {
                    log::info!("VPN: {m}; reconnecting in {}s", backoff.as_secs());
                    self.set_state(VpnState::Reconnecting(m));
                }
                Err(e) => {
                    let m = format!("{e:?}");
                    log::info!("VPN: {m}; reconnecting in {}s", backoff.as_secs());
                    self.set_state(VpnState::Reconnecting(m));
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = stop.notified() => break,
            }
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
        log::info!("VPN disconnected");
    }

    async fn run_once(self: &Arc<Self>, req: &Arc<ConnectRequest>, stop: &Arc<Notify>, stopped: &Arc<AtomicBool>) -> Result<Exit, Exit> {
        let cfg = Arc::new(req.config.clone());
        let tls = certs::tls_config(&cfg).map_err(|e| Exit::Fatal(format!("{e:#}")))?;
        let mut last_err = String::from("no usable remote");
        for remote in &cfg.remotes {
            if stopped.load(Ordering::SeqCst) {
                return Ok(Exit::Stopped);
            }
            self.set_state(VpnState::Connecting(format!("Contacting {}:{} ({:?})...", remote.host, remote.port, remote.proto)));
            let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((remote.host.as_str(), remote.port)).await {
                Ok(a) => a.collect(),
                Err(e) => {
                    last_err = format!("cannot resolve {}: {e}", remote.host);
                    continue;
                }
            };
            for addr in addrs.into_iter().filter(|a| a.is_ipv4()).chain(std::iter::empty()) {
                let link = match Link::open(addr, remote.proto, cfg.proxy.as_ref(), &remote.host, remote.port).await {
                    Ok(l) => l,
                    Err(e) => {
                        last_err = format!("{addr}: {e}");
                        continue;
                    }
                };
                self.status.lock().server = Some(addr);
                match self.session(link, cfg.clone(), tls.clone(), req, stop).await {
                    Ok(x) => return Ok(x),
                    Err(Exit::Restart(m)) => last_err = m,
                    Err(other) => return Err(other),
                }
            }
        }
        Err(Exit::Restart(last_err))
    }

    async fn session(self: &Arc<Self>, mut link: Link, cfg: Arc<OvpnConfig>, tls: Arc<rustls::ClientConfig>, req: &Arc<ConnectRequest>, stop: &Arc<Notify>) -> Result<Exit, Exit> {
        let mut eng = Engine::new(cfg, tls, req.username.clone(), req.password.clone()).map_err(|e| Exit::Fatal(format!("{e:#}")))?;
        self.set_state(VpnState::Connecting("TLS handshake with the VPN server...".into()));
        let (ip_out_tx, mut ip_out_rx) = mpsc::channel::<Vec<u8>>(1024);
        let mut net: Option<NetHandle> = None;
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let mut stats_at = Instant::now();
        let mut gw_ping_at: Option<Instant> = None;
        // wall-clock time of the last loop pass: a big jump means the PC slept
        let mut last_wall = std::time::SystemTime::now();
        loop {
            let wall = std::time::SystemTime::now();
            let gap = wall.duration_since(last_wall).unwrap_or_default();
            last_wall = wall;
            if gap > Duration::from_secs(15) && eng.is_connected() {
                return Err(Exit::Restart(format!("the computer was asleep or the clock jumped ({}s); reconnecting", gap.as_secs())));
            }
            while let Some(p) = eng.out.pop_front() {
                link.send(p).await.map_err(|e| Exit::Restart(format!("send failed: {e}")))?;
            }
            while let Some(ev) = eng.events.pop_front() {
                match ev {
                    Event::Connected(info, cipher) => {
                        let ip = info.ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
                        log::info!("VPN connected: this computer is {ip}/{} (cipher {cipher})", info.prefix);
                        let (enabled, port) = {
                            let c = self.server.cfg.read();
                            (c.server.enabled, c.server.port)
                        };
                        let nc = NetConfig { ip, prefix: info.prefix, gateway: info.gateway.unwrap_or(ip), mtu: (info.mtu as usize).min(1400).max(576), listen_port: inbound_port(self.guest, enabled, port), outbound_only: self.guest };
                        let h = netstack::start(nc, ip_out_tx.clone(), self.server.clone());
                        net = Some(h.clone());
                        *self.net.lock() = Some(h);
                        {
                            let mut s = self.status.lock();
                            s.state = VpnState::Connected;
                            s.info = Some(info);
                            s.cipher = cipher;
                            s.since = Some(Instant::now());
                            s.gateway_rtt = None;
                            s.gateway_checked = false;
                        }
                        gw_ping_at = Some(Instant::now() + Duration::from_millis(500));
                        crate::util::request_repaint();
                    }
                    Event::Ip(p) => {
                        if let Some(n) = net.as_ref() {
                            if n.ip_in.try_send(p).is_err() {
                                log::debug!("vpn: inbound packet dropped (netstack busy)");
                            }
                        }
                    }
                    Event::AuthFailed(m) => return Ok(Exit::AuthFailed(m)),
                    Event::Challenge { state_id, user, text, echo } => return Ok(Exit::Challenge { state_id, user, text, echo }),
                    Event::Restart(m) => return Err(Exit::Restart(m)),
                    Event::Fatal(m) => return Ok(Exit::Fatal(m)),
                    Event::Info(m) => {
                        log::info!("VPN: {m}");
                        if !eng.is_connected() {
                            self.set_state(VpnState::Connecting(m));
                        }
                    }
                }
            }
            if stats_at.elapsed() > Duration::from_secs(1) {
                stats_at = Instant::now();
                let mut s = self.status.lock();
                s.bytes_in = eng.bytes_in;
                s.bytes_out = eng.bytes_out;
            }
            if let (Some(t), Some(n)) = (gw_ping_at, net.as_ref()) {
                if Instant::now() >= t {
                    gw_ping_at = None;
                    let gw = self.status.lock().info.as_ref().and_then(|i| i.gateway);
                    if let Some(gw) = gw {
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        let _ = n.cmd.send(NetCmd::Ping { target: gw, reply: tx });
                        let st = self.status.clone();
                        tokio::spawn(async move {
                            let r = rx.await.ok().flatten();
                            let mut s = st.lock();
                            s.gateway_rtt = r;
                            s.gateway_checked = true;
                            crate::util::request_repaint();
                        });
                    }
                }
            }
            tokio::select! {
                _ = stop.notified() => {
                    eng.send_exit();
                    while let Some(p) = eng.out.pop_front() {
                        let _ = link.send(p).await;
                    }
                    return Ok(Exit::Stopped);
                }
                p = link.rx.recv() => match p {
                    Some(p) => eng.on_packet(&p),
                    None => return Err(Exit::Restart("connection to the VPN server was lost".into())),
                },
                ip = ip_out_rx.recv() => {
                    if let Some(ip) = ip {
                        eng.send_ip(&ip);
                        while let Ok(ip) = ip_out_rx.try_recv() {
                            eng.send_ip(&ip);
                        }
                    }
                }
                _ = tick.tick() => eng.tick(),
            }
        }
    }
}

#[derive(Debug)]
enum Exit {
    Stopped,
    Restart(String),
    Fatal(String),
    AuthFailed(String),
    Challenge { state_id: String, user: String, text: String, echo: bool },
}

// ---- transport ---------------------------------------------------------------

struct Link {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: LinkTx,
}

enum LinkTx {
    Udp(Arc<tokio::net::UdpSocket>),
    Tcp(mpsc::Sender<Vec<u8>>),
}

impl Link {
    async fn open(addr: SocketAddr, proto: Proto, proxy: Option<&Proxy>, host: &str, port: u16) -> io::Result<Link> {
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(1024);
        match proto {
            Proto::Udp => {
                if proxy.is_some() {
                    return Err(io::Error::new(io::ErrorKind::Unsupported, "proxies only work with TCP profiles"));
                }
                // large socket buffers so bursts from the tunnel are not dropped
                let raw = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
                let _ = raw.set_recv_buffer_size(4 << 20);
                let _ = raw.set_send_buffer_size(2 << 20);
                raw.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
                raw.set_nonblocking(true)?;
                let sock = tokio::net::UdpSocket::from_std(raw.into())?;
                sock.connect(addr).await?;
                let sock = Arc::new(sock);
                let rs = sock.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    loop {
                        match rs.recv(&mut buf).await {
                            Ok(n) => {
                                if in_tx.send(buf[..n].to_vec()).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue, // ICMP port unreachable on Windows
                            Err(_) => break,
                        }
                    }
                });
                Ok(Link { rx: in_rx, tx: LinkTx::Udp(sock) })
            }
            Proto::Tcp => {
                let stream = match proxy {
                    None => tokio::time::timeout(Duration::from_secs(15), tokio::net::TcpStream::connect(addr)).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??,
                    Some(p) => connect_via_proxy(p, host, port).await?,
                };
                let _ = stream.set_nodelay(true);
                let (mut rd, mut wr) = stream.into_split();
                tokio::spawn(async move {
                    loop {
                        let mut len = [0u8; 2];
                        if rd.read_exact(&mut len).await.is_err() {
                            break;
                        }
                        let n = u16::from_be_bytes(len) as usize;
                        let mut buf = vec![0u8; n];
                        if rd.read_exact(&mut buf).await.is_err() {
                            break;
                        }
                        if in_tx.send(buf).await.is_err() {
                            break;
                        }
                    }
                });
                let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);
                tokio::spawn(async move {
                    while let Some(p) = out_rx.recv().await {
                        let mut f = Vec::with_capacity(p.len() + 2);
                        f.extend_from_slice(&(p.len() as u16).to_be_bytes());
                        f.extend_from_slice(&p);
                        if wr.write_all(&f).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(Link { rx: in_rx, tx: LinkTx::Tcp(out_tx) })
            }
        }
    }

    async fn send(&mut self, p: Vec<u8>) -> io::Result<()> {
        match &self.tx {
            LinkTx::Udp(s) => {
                match s.send(&p).await {
                    Ok(_) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Ok(()),
                    Err(e) => Err(e),
                }
            }
            LinkTx::Tcp(tx) => tx.send(p).await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "link closed")),
        }
    }
}

async fn connect_via_proxy(p: &Proxy, host: &str, port: u16) -> io::Result<tokio::net::TcpStream> {
    match p {
        Proxy::Http { host: ph, port: pp, auth } => {
            let mut s = tokio::net::TcpStream::connect((ph.as_str(), *pp)).await?;
            let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
            if let Some((u, pw)) = auth {
                use base64::Engine as _;
                req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{pw}"))));
            }
            req.push_str("\r\n");
            s.write_all(req.as_bytes()).await?;
            let mut resp = Vec::new();
            let mut b = [0u8; 1];
            while !resp.ends_with(b"\r\n\r\n") && resp.len() < 8192 {
                s.read_exact(&mut b).await?;
                resp.push(b[0]);
            }
            let line = String::from_utf8_lossy(&resp);
            if !line.split_whitespace().nth(1).map(|c| c == "200").unwrap_or(false) {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("HTTP proxy refused: {}", line.lines().next().unwrap_or(""))));
            }
            Ok(s)
        }
        Proxy::Socks { host: ph, port: pp } => {
            let mut s = tokio::net::TcpStream::connect((ph.as_str(), *pp)).await?;
            s.write_all(&[5, 1, 0]).await?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await?;
            if r != [5, 0] {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "SOCKS proxy requires authentication"));
            }
            let mut m = vec![5, 1, 0, 3, host.len() as u8];
            m.extend_from_slice(host.as_bytes());
            m.extend_from_slice(&port.to_be_bytes());
            s.write_all(&m).await?;
            let mut head = [0u8; 4];
            s.read_exact(&mut head).await?;
            if head[1] != 0 {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("SOCKS proxy error {}", head[1])));
            }
            let skip = match head[3] {
                1 => 4,
                4 => 16,
                3 => {
                    let mut l = [0u8; 1];
                    s.read_exact(&mut l).await?;
                    l[0] as usize
                }
                _ => 0,
            } + 2;
            let mut tmp = vec![0u8; skip];
            s.read_exact(&mut tmp).await?;
            Ok(s)
        }
    }
}
