//! Addresses others can use to reach this computer directly (LAN / public).

use parking_lot::Mutex;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct LocalAddr {
    pub iface: String,
    pub ip: IpAddr,
}

pub fn local_addrs() -> Vec<LocalAddr> {
    let mut v: Vec<LocalAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter(|i| match i.ip() {
            IpAddr::V4(a) => !a.is_link_local(),
            IpAddr::V6(a) => (a.segments()[0] & 0xffc0) != 0xfe80 && !a.is_loopback(),
        })
        .map(|i| LocalAddr { iface: i.name.clone(), ip: i.ip() })
        .collect();
    v.sort_by_key(|a| (a.ip.is_ipv6(), a.iface.clone()));
    v
}

/// Look up the public IPv4 address (plain HTTP to api.ipify.org) in the background.
pub fn lookup_public_ip(out: Arc<Mutex<Option<String>>>) {
    std::thread::Builder::new()
        .name("public-ip".into())
        .spawn(move || {
            let res = (|| -> std::io::Result<String> {
                let addr = std::net::ToSocketAddrs::to_socket_addrs(&("api.ipify.org", 80))?.find(|a| a.is_ipv4()).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "dns"))?;
                let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
                s.set_read_timeout(Some(Duration::from_secs(5)))?;
                s.write_all(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: PortlessVNC\r\nConnection: close\r\n\r\n")?;
                let mut resp = String::new();
                s.read_to_string(&mut resp)?;
                let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").trim().to_string();
                match body.parse::<IpAddr>() {
                    Ok(ip) => Ok(ip.to_string()),
                    Err(_) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad reply")),
                }
            })();
            *out.lock() = Some(res.unwrap_or_else(|_| "unavailable".into()));
            crate::util::request_repaint();
        })
        .ok();
}
