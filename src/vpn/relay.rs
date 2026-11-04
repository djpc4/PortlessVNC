//! Lets this computer's own window reach clients through the background
//! service's VPN. The tunnel lives inside the service's process, and a second
//! login with the same profile could make the VPN server drop the service.
//!
//! The service listens on loopback only and needs the token from its public
//! folder, so it is reachable only from this computer (any local account can
//! read that folder, as with the service's other requests). It only opens
//! connections to addresses inside the VPN; it is not a general proxy.

use super::VpnManager;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_CONNECTIONS: usize = 32;
const TOKEN_FILE: &str = "relay.token";

/// Service side: start the relay. Returns its port (0 = not available).
#[allow(dead_code)] // the Android client has no service
pub fn start(vpn: Arc<VpnManager>) -> u16 {
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            log::warn!("relay: {e}");
            return 0;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let token = crate::util::random_password(40);
    let dir = crate::servicectl::public_dir();
    let _ = std::fs::create_dir_all(&dir);
    let tmp = dir.join(".relay.token.tmp");
    if std::fs::write(&tmp, &token).and_then(|_| std::fs::rename(&tmp, dir.join(TOKEN_FILE))).is_err() {
        log::warn!("relay: could not publish its token");
        return 0;
    }
    serve(listener, token, move |a: SocketAddr| {
        if a.ip().is_loopback() || !vpn.routes_to(a.ip()) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not on the service's VPN", a.ip())));
        }
        vpn.dial(a, Duration::from_secs(10))
    });
    port
}

fn serve<D>(listener: TcpListener, token: String, dial: D)
where
    D: Fn(SocketAddr) -> io::Result<TcpStream> + Send + Sync + 'static,
{
    let dial = Arc::new(dial);
    let token = Arc::new(token);
    let active = Arc::new(AtomicUsize::new(0));
    std::thread::Builder::new()
        .name("vpn-relay".into())
        .spawn(move || {
            for conn in listener.incoming().flatten() {
                if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    active.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let (dial, token, active) = (dial.clone(), token.clone(), active.clone());
                let spawned = std::thread::Builder::new().name("vpn-relay-conn".into()).spawn(move || {
                    handle(conn, &token, &*dial);
                    active.fetch_sub(1, Ordering::SeqCst);
                });
                if let Err(e) = spawned {
                    log::warn!("relay: {e}");
                }
            }
        })
        .ok();
}

fn handle<D: Fn(SocketAddr) -> io::Result<TcpStream>>(mut conn: TcpStream, token: &str, dial: &D) {
    let _ = conn.set_nodelay(true);
    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
    let Ok(line) = read_line(&mut conn) else { return };
    let mut parts = line.split(' ');
    let (Some("PVNC-RELAY"), Some(given), Some(addr), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else { return };
    if given != token {
        log::warn!("relay: refused a connection with the wrong token");
        let _ = conn.write_all(b"ERR not allowed\n");
        return;
    }
    let target = addr.parse::<SocketAddr>().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad address")).and_then(dial);
    let far = match target {
        Ok(s) => s,
        Err(e) => {
            let _ = conn.write_all(format!("ERR {}\n", e.to_string().replace('\n', " ")).as_bytes());
            return;
        }
    };
    if conn.write_all(b"OK\n").is_err() {
        return;
    }
    let _ = conn.set_read_timeout(None);
    let _ = far.set_nodelay(true);
    bridge(conn, far);
}

/// Pass bytes both ways until either side closes.
fn bridge(a: TcpStream, b: TcpStream) {
    let (Ok(mut a2), Ok(mut b2)) = (a.try_clone(), b.try_clone()) else { return };
    let (mut a1, mut b1) = (a, b);
    let t = std::thread::Builder::new().name("vpn-relay-up".into()).spawn(move || {
        let _ = io::copy(&mut a1, &mut b2);
        let _ = a1.shutdown(Shutdown::Both);
        let _ = b2.shutdown(Shutdown::Both);
    });
    if t.is_err() {
        return;
    }
    let _ = io::copy(&mut b1, &mut a2);
    let _ = b1.shutdown(Shutdown::Both);
    let _ = a2.shutdown(Shutdown::Both);
    if let Ok(t) = t {
        let _ = t.join();
    }
}

/// One line, read byte by byte so nothing after it is consumed.
fn read_line(s: &mut TcpStream) -> io::Result<String> {
    let mut out = Vec::with_capacity(96);
    let mut b = [0u8; 1];
    loop {
        if s.read(&mut b)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if b[0] == b'\n' {
            return String::from_utf8(out).map_err(|_| io::ErrorKind::InvalidData.into());
        }
        out.push(b[0]);
        if out.len() > 512 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
}

/// Window side: connect to `addr` through the service's VPN.
pub fn dial(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let status = crate::servicectl::read_status().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "The PortlessVNC service is not running"))?;
    if status.relay_port == 0 {
        return Err(io::Error::new(io::ErrorKind::Unsupported, format!("The service is version {}: use \"Update service\" so this window can use its VPN", status.version)));
    }
    let token = std::fs::read_to_string(crate::servicectl::public_dir().join(TOKEN_FILE))?;
    dial_port(status.relay_port, token.trim(), addr, timeout)
}

fn dial_port(port: u16, token: &str, addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(3))?;
    let _ = s.set_nodelay(true);
    s.set_read_timeout(Some(timeout))?;
    s.write_all(format!("PVNC-RELAY {token} {addr}\n").as_bytes())?;
    let reply = read_line(&mut s)?;
    if reply != "OK" {
        let why = reply.strip_prefix("ERR ").unwrap_or("the service refused the connection");
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, why.to_string()));
    }
    s.set_read_timeout(None)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for a computer on the VPN: answers with what it receives.
    fn echo_server() -> SocketAddr {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let a = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let mut r = c.try_clone().unwrap();
                let mut w = c;
                std::thread::spawn(move || {
                    let _ = io::copy(&mut r, &mut w);
                });
            }
        });
        a
    }

    fn relay(allowed: SocketAddr) -> u16 {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        serve(l, "secret".into(), move |a| {
            if a == allowed {
                TcpStream::connect(a)
            } else {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "not on the VPN"))
            }
        });
        port
    }

    #[test]
    fn passes_data_both_ways() {
        let echo = echo_server();
        let port = relay(echo);
        let mut s = dial_port(port, "secret", echo, Duration::from_secs(3)).unwrap();
        s.write_all(b"hello through the relay").unwrap();
        let mut back = [0u8; 23];
        s.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello through the relay");
    }

    #[test]
    fn refuses_the_wrong_token() {
        let echo = echo_server();
        let port = relay(echo);
        let e = dial_port(port, "wrong", echo, Duration::from_secs(3)).unwrap_err();
        assert!(e.to_string().contains("not allowed"), "{e}");
    }

    #[test]
    fn refuses_addresses_off_the_vpn() {
        let echo = echo_server();
        let port = relay(echo);
        let other: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let e = dial_port(port, "secret", other, Duration::from_secs(3)).unwrap_err();
        assert!(e.to_string().contains("not on the VPN"), "{e}");
    }

    #[test]
    fn a_malformed_request_gets_nothing() {
        let echo = echo_server();
        let port = relay(echo);
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(format!("GET / HTTP/1.1 {echo}\n").as_bytes()).unwrap();
        let mut b = [0u8; 8];
        assert_eq!(s.read(&mut b).unwrap_or(0), 0);
    }
}
