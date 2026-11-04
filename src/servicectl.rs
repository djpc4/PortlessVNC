//! Shared bits of the background-service mode.
//!
//! Layout (machine-wide):
//!   %ProgramData%\PortlessVNC\            config, certificate, VPN profile (SYSTEM + Administrators only)
//!   %ProgramData%\PortlessVNC\public\     status.json, readable by every user
//!   %ProgramData%\PortlessVNC\public\requests\   small request files users may drop (e.g. new one-time password)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SERVICE_NAME: &str = "PortlessVNC";

pub fn machine_dir() -> PathBuf {
    // (tests can point the service folder somewhere else)
    if let Some(d) = std::env::var_os("PVNC_MACHINE_DIR") {
        return PathBuf::from(d);
    }
    #[cfg(windows)]
    return std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("PortlessVNC");
    #[cfg(not(windows))]
    return PathBuf::from("/etc/portlessvnc");
}

pub fn public_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("PVNC_MACHINE_DIR") {
        return PathBuf::from(d).join("public");
    }
    #[cfg(windows)]
    return machine_dir().join("public");
    // Linux: settings stay root-only in /etc; status and requests live here
    #[cfg(not(windows))]
    return PathBuf::from("/var/lib/portlessvnc/public");
}

pub fn requests_dir() -> PathBuf {
    public_dir().join("requests")
}

pub fn install_dir() -> PathBuf {
    #[cfg(windows)]
    return std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files")).join("PortlessVNC");
    #[cfg(not(windows))]
    return PathBuf::from("/opt/portlessvnc");
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ViewerInfo {
    pub addr: String,
    pub via_vpn: bool,
    pub native: bool,
}

/// What the service publishes for the user's window.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Status {
    pub version: String,
    pub updated: u64,
    pub vpn_state: String,
    pub vpn_ip: Option<String>,
    pub vpn_profile: String,
    pub vpn_detail: String,
    pub direct_port: Option<u16>,
    pub vpn_port: u16,
    pub otp: Option<String>,
    pub permanent_password: bool,
    pub fingerprint: String,
    pub viewers: Vec<ViewerInfo>,
    pub desktop: String,
    // VPN details for the client-style panel
    pub vpn_profiles: Vec<String>,
    pub vpn_selected: usize,
    pub vpn_user: String,
    pub vpn_remote: String,
    pub vpn_password_saved: bool,
    /// profile asks for username/password
    pub vpn_needs_login: bool,
    /// static-challenge prompt of the profile (text, echo)
    pub vpn_static_challenge: Option<(String, bool)>,
    /// the user pressed Disconnect (stays off until Connect)
    pub vpn_off: bool,
}

/// "Login..." from the user's window.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VpnLogin {
    pub user: String,
    pub pass: String,
    pub otp: Option<String>,
    pub remember: bool,
}

/// "Import .ovpn..." from the user's window.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VpnImport {
    pub name: String,
    pub text: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn write_status(mut s: Status) {
    s.updated = now();
    s.version = env!("CARGO_PKG_VERSION").to_string();
    let dir = public_dir();
    let _ = std::fs::create_dir_all(&dir);
    let tmp = dir.join("status.json.tmp");
    if std::fs::write(&tmp, serde_json::to_vec_pretty(&s).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(tmp, dir.join("status.json"));
    }
}

/// Shared text as seen by the service (for the signed-in user's window).
pub fn write_note(version: u64, text: &str) {
    let dir = public_dir();
    let tmp = dir.join("note.json.tmp");
    if std::fs::write(&tmp, serde_json::to_vec(&(version, text)).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(tmp, dir.join("note.json"));
    }
}

pub fn read_note() -> Option<(u64, String)> {
    serde_json::from_slice(&std::fs::read(public_dir().join("note.json")).ok()?).ok()
}

/// The service's status, if it is running (updated within the last 10 s).
pub fn read_status() -> Option<Status> {
    let s: Status = serde_json::from_slice(&std::fs::read(public_dir().join("status.json")).ok()?).ok()?;
    (now().saturating_sub(s.updated) <= 10).then_some(s)
}

/// Ask the service for something (any user may do this).
pub fn request(name: &str) {
    request_with(name, b"1");
}

/// Request with a payload (JSON). The service picks it up within a quarter
/// second and deletes it.
pub fn request_with(name: &str, data: &[u8]) {
    let dir = requests_dir();
    let _ = std::fs::create_dir_all(&dir);
    let tmp = dir.join(format!(".{name}.tmp"));
    if std::fs::write(&tmp, data).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join(name));
    }
}

pub fn request_json<T: Serialize>(name: &str, v: &T) {
    request_with(name, &serde_json::to_vec(v).unwrap_or_default());
}

/// Collect and remove pending requests (service side): (name, payload).
pub fn take_requests() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(requests_dir()) {
        for e in rd.flatten() {
            let Some(n) = e.file_name().to_str().map(|s| s.to_string()) else { continue };
            if n.starts_with('.') {
                continue; // still being written
            }
            let data = std::fs::read(e.path()).unwrap_or_default();
            let _ = std::fs::remove_file(e.path());
            out.push((n, data));
        }
    }
    out
}

