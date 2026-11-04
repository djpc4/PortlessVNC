//! Userspace TCP/IP stack on the VPN address (smoltcp). This replaces a TUN
//! adapter: no driver, no admin rights, and no change to the system's
//! routing. Only PortlessVNC's own connections use the tunnel.
//!
//! * Inbound: TCP connections to <vpn-ip>:<vnc-port> are bridged to the local
//!   VNC server over loopback.
//! * Outbound: `Dial` opens a TCP connection through the tunnel and hands back
//!   an ordinary `std::net::TcpStream` (the other end of a loopback pair).

use crate::server::Server;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{icmp, tcp};
use smoltcp::wire::{HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Semaphore};

pub enum NetCmd {
    Dial { addr: SocketAddrV4, timeout: Duration, reply: oneshot::Sender<io::Result<std::net::TcpStream>> },
    Data { id: u64, data: Vec<u8> },
    LocalClosed { id: u64 },
    Ping { target: Ipv4Addr, reply: oneshot::Sender<Option<Duration>> },
}

#[derive(Clone)]
pub struct NetHandle {
    pub cmd: mpsc::UnboundedSender<NetCmd>,
    pub ip_in: mpsc::Sender<Vec<u8>>,
}

struct Dev {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}
struct RxT(Vec<u8>);
struct TxT<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for RxT {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
impl<'a> TxToken for TxT<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push(b);
        r
    }
}
impl Device for Dev {
    type RxToken<'a> = RxT where Self: 'a;
    type TxToken<'a> = TxT<'a> where Self: 'a;
    fn receive(&mut self, _t: smoltcp::time::Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxT(p), TxT(&mut self.tx)))
    }
    fn transmit(&mut self, _t: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxT(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

struct Bridge {
    id: u64,
    handle: SocketHandle,
    pending: VecDeque<Vec<u8>>,
    credit: Arc<Semaphore>,
    to_local: Option<mpsc::Sender<Vec<u8>>>,
    local_closed: bool,
    connected: bool,
    dial: Option<(oneshot::Sender<io::Result<std::net::TcpStream>>, Instant)>,
}

const BRIDGE_CREDIT: usize = 512 * 1024;
const LISTENERS: usize = 4;

fn tcp_socket() -> tcp::Socket<'static> {
    // smoltcp has no congestion control: a moderate window keeps bursts
    // within what the UDP path and socket buffers absorb.
    let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 256 * 1024]), tcp::SocketBuffer::new(vec![0; 256 * 1024]));
    s.set_congestion_control(tcp::CongestionControl::Cubic);
    s.set_nagle_enabled(false);
    s.set_ack_delay(None);
    s.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
    s.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
    s
}

fn loopback_pair() -> io::Result<(std::net::TcpStream, std::net::TcpStream)> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    let a = std::net::TcpStream::connect(l.local_addr()?)?;
    let (b, _) = l.accept()?;
    let _ = a.set_nodelay(true);
    let _ = b.set_nodelay(true);
    Ok((a, b))
}

fn spawn_pumps(stream: std::net::TcpStream, id: u64, cmd: mpsc::UnboundedSender<NetCmd>, credit: Arc<Semaphore>) -> io::Result<mpsc::Sender<Vec<u8>>> {
    stream.set_nonblocking(true)?;
    let s = tokio::net::TcpStream::from_std(stream)?;
    let (mut rd, mut wr) = s.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            match credit.acquire_many(n as u32).await {
                Ok(p) => p.forget(),
                Err(_) => break,
            }
            if cmd.send(NetCmd::Data { id, data: buf[..n].to_vec() }).is_err() {
                return;
            }
        }
        let _ = cmd.send(NetCmd::LocalClosed { id });
    });
    tokio::spawn(async move {
        while let Some(d) = rx.recv().await {
            if wr.write_all(&d).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    Ok(tx)
}

/// Destination port of an IPv4 TCP SYN (without ACK) addressed to `ip`.
fn tcp_syn_port(p: &[u8], ip: Ipv4Addr) -> Option<u16> {
    if p.len() < 20 || p[0] >> 4 != 4 || p[9] != 6 || p[16..20] != ip.octets() {
        return None;
    }
    let ihl = (p[0] & 0x0f) as usize * 4;
    let t = p.get(ihl..ihl + 14)?;
    let flags = t[13];
    (flags & 0x02 != 0 && flags & 0x10 == 0).then(|| u16::from_be_bytes([t[2], t[3]]))
}

pub struct NetConfig {
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
    pub mtu: usize,
    pub listen_port: Option<u16>,
    /// Guest VPN: never accept anything inbound (also overrides vpn_expose_all).
    pub outbound_only: bool,
}

/// Start the stack; returns the handle and keeps running until the tunnel
/// drops `ip_in` or every handle is gone.
pub fn start(nc: NetConfig, ip_out: mpsc::Sender<Vec<u8>>, server: Arc<Server>) -> NetHandle {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (in_tx, in_rx) = mpsc::channel(1024);
    let handle = NetHandle { cmd: cmd_tx.clone(), ip_in: in_tx };
    tokio::spawn(run(nc, ip_out, in_rx, cmd_rx, cmd_tx, server));
    handle
}

async fn run(nc: NetConfig, ip_out: mpsc::Sender<Vec<u8>>, mut ip_in: mpsc::Receiver<Vec<u8>>, mut cmd_rx: mpsc::UnboundedReceiver<NetCmd>, cmd_tx: mpsc::UnboundedSender<NetCmd>, server: Arc<Server>) {
    let start = Instant::now();
    let now = || smoltcp::time::Instant::from_millis(start.elapsed().as_millis() as i64);
    let mut dev = Dev { rx: VecDeque::new(), tx: Vec::new(), mtu: nc.mtu };
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, now());
    let o = nc.ip.octets();
    let g = nc.gateway.octets();
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3])), nc.prefix));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(g[0], g[1], g[2], g[3]));
    let mut sockets = SocketSet::new(Vec::new());

    // (listening socket, port). The VNC port always; other ports only when
    // "Let VPN peers reach other services on this computer" is on.
    let mut listeners: Vec<(SocketHandle, u16)> = Vec::new();
    let add_listener = |sockets: &mut SocketSet<'static>, port: u16| -> Option<SocketHandle> {
        let mut s = tcp_socket();
        s.listen(port).ok()?;
        Some(sockets.add(s))
    };
    if let Some(p) = nc.listen_port {
        for _ in 0..LISTENERS {
            if let Some(h) = add_listener(&mut sockets, p) {
                listeners.push((h, p));
            }
        }
    }
    let icmp_h = {
        let mut s = icmp::Socket::new(
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
        );
        let _ = s.bind(icmp::Endpoint::Ident(0x504c));
        sockets.add(s)
    };
    let mut ping: Option<(oneshot::Sender<Option<Duration>>, Instant, u16)> = None;
    let mut ping_seq: u16 = 0;

    let mut bridges: Vec<Bridge> = Vec::new();
    let mut next_id: u64 = 1;
    let mut next_port: u16 = 49152 + (rand::random::<u16>() % 10000);
    let mut stats = (0u64, 0u64, 0u64, 0u64); // in pkts, out pkts, dropped out, out bytes
    let mut stats_at = Instant::now();

    loop {
        iface.poll(now(), &mut dev, &mut sockets);

        // new inbound connections
        {
            let mut i = 0;
            while i < listeners.len() {
                let (h, port) = listeners[i];
                let st = sockets.get_mut::<tcp::Socket>(h).state();
                if st == tcp::State::Listen {
                    i += 1;
                    continue;
                }
                listeners.remove(i);
                let is_vnc = Some(port) == nc.listen_port;
                let expose = !nc.outbound_only && server.cfg.read().server.vpn_expose_all;
                if is_vnc || expose {
                    if let Some(nh) = add_listener(&mut sockets, port) {
                        listeners.push((nh, port));
                    }
                }
                let remote = sockets.get_mut::<tcp::Socket>(h).remote_endpoint();
                let local = if is_vnc {
                    // Hand the connection to PortlessVNC's own private loopback
                    // listener - never to whatever else may own the VNC port.
                    let accept = server.cfg.read().server.accept_via_vpn;
                    let bridge_port = server.vpn_bridge_port();
                    if accept && bridge_port != 0 { std::net::TcpStream::connect(("127.0.0.1", bridge_port)) } else { Err(io::Error::new(io::ErrorKind::PermissionDenied, "VPN connections disabled")) }
                } else if expose {
                    log::info!("VPN: forwarding a connection to local port {port}");
                    std::net::TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(3))
                } else {
                    Err(io::Error::new(io::ErrorKind::PermissionDenied, "other services are not shared over the VPN"))
                };
                match local {
                    Ok(ls) => {
                        let _ = ls.set_nodelay(true);
                        if is_vnc {
                            if let (Ok(la), Some(re)) = (ls.local_addr(), remote) {
                                if let IpAddress::Ipv4(v4) = re.addr {
                                    let peer = SocketAddr::from((v4.octets(), re.port));
                                    server.vpn_bridges.lock().insert(la.port(), peer);
                                }
                            }
                        }
                        let id = next_id;
                        next_id += 1;
                        let credit = Arc::new(Semaphore::new(BRIDGE_CREDIT));
                        match spawn_pumps(ls, id, cmd_tx.clone(), credit.clone()) {
                            Ok(tx) => bridges.push(Bridge { id, handle: h, pending: VecDeque::new(), credit, to_local: Some(tx), local_closed: false, connected: true, dial: None }),
                            Err(_) => sockets.get_mut::<tcp::Socket>(h).abort(),
                        }
                    }
                    Err(_) => sockets.get_mut::<tcp::Socket>(h).abort(),
                }
            }
        }

        // service bridges
        let mut remove: Vec<usize> = Vec::new();
        for (bi, b) in bridges.iter_mut().enumerate() {
            let s = sockets.get_mut::<tcp::Socket>(b.handle);
            if let Some((reply, deadline)) = b.dial.take() {
                match s.state() {
                    tcp::State::Established => match loopback_pair().and_then(|(client, inner)| Ok((client, spawn_pumps(inner, b.id, cmd_tx.clone(), b.credit.clone())?))) {
                        Ok((client, tx)) => {
                            b.to_local = Some(tx);
                            b.connected = true;
                            let _ = reply.send(Ok(client));
                        }
                        Err(e) => {
                            s.abort();
                            let _ = reply.send(Err(e));
                        }
                    },
                    tcp::State::Closed | tcp::State::TimeWait => {
                        let _ = reply.send(Err(io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused through the VPN")));
                        remove.push(bi);
                        continue;
                    }
                    _ if Instant::now() > deadline => {
                        s.abort();
                        let _ = reply.send(Err(io::Error::new(io::ErrorKind::TimedOut, "no answer through the VPN (port closed/filtered, or the VPN server does not allow client-to-client traffic)")));
                        remove.push(bi);
                        continue;
                    }
                    _ => {
                        b.dial = Some((reply, deadline));
                        continue;
                    }
                }
            }
            // remote -> local
            if let Some(tx) = b.to_local.as_ref() {
                while s.can_recv() {
                    let Ok(permit) = tx.try_reserve() else { break };
                    let data = s.recv(|buf| {
                        let n = buf.len().min(32 * 1024);
                        (n, buf[..n].to_vec())
                    });
                    match data {
                        Ok(d) if !d.is_empty() => permit.send(d),
                        _ => break,
                    }
                }
                let remote_done = matches!(s.state(), tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait | tcp::State::Closed);
                if remote_done && !s.can_recv() && b.connected {
                    b.to_local = None; // remote finished sending: close our write side
                }
            }
            // local -> remote
            while let Some(front) = b.pending.front_mut() {
                if !s.can_send() {
                    break;
                }
                match s.send_slice(front) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        b.credit.add_permits(n);
                        front.drain(..n);
                        if front.is_empty() {
                            b.pending.pop_front();
                        }
                    }
                }
            }
            if b.local_closed && b.pending.is_empty() && s.may_send() {
                s.close();
            }
            if b.connected && s.state() == tcp::State::Closed {
                remove.push(bi);
            }
        }
        for &bi in remove.iter().rev() {
            let b = bridges.remove(bi);
            b.credit.close();
            sockets.remove(b.handle);
        }

        // ping replies
        {
            let s = sockets.get_mut::<icmp::Socket>(icmp_h);
            while s.can_recv() {
                let Ok((data, _from)) = s.recv() else { break };
                if let Ok(pkt) = Icmpv4Packet::new_checked(data) {
                    if let Ok(Icmpv4Repr::EchoReply { seq_no, .. }) = Icmpv4Repr::parse(&pkt, &ChecksumCapabilities::default()) {
                        if let Some((reply, sent, seq)) = ping.take() {
                            if seq == seq_no {
                                let _ = reply.send(Some(sent.elapsed()));
                            } else {
                                ping = Some((reply, sent, seq));
                            }
                        }
                    }
                }
            }
            if let Some((reply, sent, seq)) = ping.take() {
                if sent.elapsed() > Duration::from_secs(4) {
                    let _ = reply.send(None);
                } else {
                    ping = Some((reply, sent, seq));
                }
            }
        }

        iface.poll(now(), &mut dev, &mut sockets);
        for p in dev.tx.drain(..) {
            stats.1 += 1;
            stats.3 += p.len() as u64;
            if ip_out.try_send(p).is_err() {
                stats.2 += 1;
            }
        }
        if stats_at.elapsed() >= Duration::from_secs(1) {
            if stats.0 + stats.1 > 0 {
                log::debug!("netstack: in {} pkts, out {} pkts ({} KB), dropped-out {}, bridges {}", stats.0, stats.1, stats.3 / 1024, stats.2, bridges.len());
            }
            stats = (0, 0, 0, 0);
            stats_at = Instant::now();
        }

        let delay = iface.poll_delay(now(), &sockets).map(|d| d.total_millis()).unwrap_or(50).min(50);
        let busy = bridges.iter().any(|b| !b.pending.is_empty() || b.dial.is_some());
        let delay = if busy { delay.min(5) } else { delay };
        tokio::select! {
            biased;
            p = ip_in.recv() => match p {
                Some(p) => {
                    let mut batch = vec![p];
                    while let Ok(p) = ip_in.try_recv() {
                        batch.push(p);
                    }
                    let expose = !nc.outbound_only && server.cfg.read().server.vpn_expose_all;
                    for p in batch {
                        // opt-in "other services": open a listener on demand for
                        // the port a peer is connecting to (smoltcp has no wildcard listen)
                        if expose {
                            if let Some(port) = tcp_syn_port(&p, nc.ip) {
                                if !listeners.iter().any(|(_, lp)| *lp == port) {
                                    if let Some(h) = add_listener(&mut sockets, port) {
                                        listeners.push((h, port));
                                    }
                                }
                            }
                        }
                        dev.rx.push_back(p);
                        stats.0 += 1;
                    }
                }
                None => break,
            },
            c = cmd_rx.recv() => match c {
                Some(NetCmd::Data { id, data }) => {
                    if let Some(b) = bridges.iter_mut().find(|b| b.id == id) {
                        b.pending.push_back(data);
                    }
                }
                Some(NetCmd::LocalClosed { id }) => {
                    if let Some(b) = bridges.iter_mut().find(|b| b.id == id) {
                        b.local_closed = true;
                    }
                }
                Some(NetCmd::Dial { addr, timeout, reply }) => {
                    let mut s = tcp_socket();
                    next_port = if next_port >= 65000 { 49152 } else { next_port + 1 };
                    let ip = addr.ip().octets();
                    let ep = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(ip[0], ip[1], ip[2], ip[3])), addr.port());
                    match s.connect(iface.context(), ep, next_port) {
                        Ok(()) => {
                            let h = sockets.add(s);
                            let id = next_id;
                            next_id += 1;
                            bridges.push(Bridge { id, handle: h, pending: VecDeque::new(), credit: Arc::new(Semaphore::new(BRIDGE_CREDIT)), to_local: None, local_closed: false, connected: false, dial: Some((reply, Instant::now() + timeout)) });
                        }
                        Err(e) => {
                            let _ = reply.send(Err(io::Error::new(io::ErrorKind::Other, format!("{e:?}"))));
                        }
                    }
                }
                Some(NetCmd::Ping { target, reply }) => {
                    ping_seq = ping_seq.wrapping_add(1);
                    let s = sockets.get_mut::<icmp::Socket>(icmp_h);
                    let repr = Icmpv4Repr::EchoRequest { ident: 0x504c, seq_no: ping_seq, data: b"PortlessVNC-ping" };
                    let t = target.octets();
                    if let Ok(buf) = s.send(repr.buffer_len(), IpAddress::Ipv4(Ipv4Address::new(t[0], t[1], t[2], t[3]))) {
                        let mut pkt = Icmpv4Packet::new_unchecked(buf);
                        repr.emit(&mut pkt, &ChecksumCapabilities::default());
                        ping = Some((reply, Instant::now(), ping_seq));
                    } else {
                        let _ = reply.send(None);
                    }
                }
                None => break,
            },
            _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
        }
    }
    log::debug!("vpn netstack stopped");
}
