//! Persistent settings (JSON in %APPDATA%\PortlessVNC, or next to the exe in
//! portable mode when a `portable.txt` file exists beside it).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthMode {
    /// Standard VNC password (max 8 characters, as in every VNC server).
    VncPassword,
    /// Windows account username + password (checked with LogonUser).
    SystemAccount,
    /// No authentication (not recommended).
    None,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum QualityMode {
    Auto,
    High,
    Medium,
    Low,
    Lossless,
}

impl QualityMode {
    pub const ALL: [QualityMode; 5] = [QualityMode::Auto, QualityMode::High, QualityMode::Medium, QualityMode::Low, QualityMode::Lossless];
    pub fn label(self) -> &'static str {
        match self {
            QualityMode::Auto => "Auto (adapt to connection)",
            QualityMode::High => "High",
            QualityMode::Medium => "Medium",
            QualityMode::Low => "Low (slow links)",
            QualityMode::Lossless => "Lossless",
        }
    }
    /// Tight quality level (0-9) to advertise, None = lossless.
    pub fn tight_level(self) -> Option<u8> {
        match self {
            QualityMode::Auto => Some(7),
            QualityMode::High => Some(8),
            QualityMode::Medium => Some(6),
            QualityMode::Low => Some(3),
            QualityMode::Lossless => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AudioMode {
    Off,
    Auto,
    Kbps(u32),
}

impl AudioMode {
    pub const PRESETS: [AudioMode; 6] = [AudioMode::Off, AudioMode::Auto, AudioMode::Kbps(32), AudioMode::Kbps(64), AudioMode::Kbps(96), AudioMode::Kbps(128)];
    pub fn label(self) -> String {
        match self {
            AudioMode::Off => "Off".into(),
            AudioMode::Auto => "Auto (adapt to connection)".into(),
            AudioMode::Kbps(k) => format!("{k} kbps"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct ServerConfig {
    pub enabled: bool,
    pub port: u16,
    /// Listen on all interfaces (LAN/WAN direct connections). When off, only
    /// connections arriving through the VPN are accepted.
    pub listen_direct: bool,
    /// Address for direct connections (0.0.0.0 = all networks).
    pub bind_address: String,
    pub accept_via_vpn: bool,
    /// Let VPN peers reach other TCP services on this computer (off: only PortlessVNC).
    pub vpn_expose_all: bool,
    pub auth: AuthMode,
    /// VNC password, obfuscated with the standard VNC fixed DES key.
    pub vnc_password: String,
    /// Accept the permanent password above.
    pub permanent_password: bool,
    /// Accept a random one-time password that changes after every successful login.
    pub one_time_password: bool,
    /// Offer plain "VNC Authentication" (needed by RealVNC/UltraVNC viewers).
    pub allow_classic_auth: bool,
    pub monitor: usize,
    pub max_fps: u32,
    pub share_audio: bool,
    /// Linux: PulseAudio/PipeWire source to stream (empty = default output's monitor)
    pub audio_source: String,
    pub share_clipboard: bool,
    pub allow_file_transfer: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            enabled: true,
            port: 5900,
            listen_direct: true,
            bind_address: "0.0.0.0".into(),
            accept_via_vpn: true,
            vpn_expose_all: false,
            auth: AuthMode::VncPassword,
            vnc_password: String::new(),
            permanent_password: true,
            one_time_password: true,
            allow_classic_auth: true,
            monitor: 0,
            max_fps: 30,
            share_audio: true,
            audio_source: String::new(),
            share_clipboard: true,
            allow_file_transfer: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct ViewerConfig {
    pub quality: QualityMode,
    pub audio: AudioMode,
    pub scale_to_fit: bool,
    pub share_clipboard: bool,
    pub capture_system_keys: bool,
    /// Android: tap where you touch (else the screen is a touchpad)
    pub touch_direct: bool,
    /// Android, while viewing: 0 auto (follow the phone), 1 landscape, 2 portrait
    pub orientation: u8,
    /// Android: show the left/right mouse-button bar
    pub mouse_bar: bool,
}

impl Default for ViewerConfig {
    fn default() -> Self {
        ViewerConfig { quality: QualityMode::Auto, audio: AudioMode::Auto, scale_to_fit: true, share_clipboard: true, capture_system_keys: true, touch_direct: false, orientation: 0, mouse_bar: true }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct VpnProfile {
    pub name: String,
    pub ovpn_path: String,
    pub username: String,
    /// DPAPI-protected (current Windows user only), base64.
    pub password_protected: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct VpnConfig {
    pub profiles: Vec<VpnProfile>,
    pub selected: usize,
    pub connect_on_start: bool,
    /// Reconnect forever (with backoff) once a profile has worked.
    pub keep_connected: bool,
    /// The VPN was up when the app last ran (and not disconnected by the user).
    pub resume: bool,
}

impl Default for VpnConfig {
    fn default() -> Self {
        VpnConfig { profiles: Vec::new(), selected: 0, connect_on_start: false, keep_connected: true, resume: false }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct BookEntry {
    pub name: String,
    pub address: String,
    pub username: String,
    /// DPAPI-protected, base64.
    pub password_protected: Option<String>,
    /// VPN profile (name) used to reach it; None = same network
    pub vpn_profile: Option<String>,
    /// this computer's own viewer settings (None = the app's defaults)
    pub audio: Option<AudioMode>,
    pub quality: Option<QualityMode>,
    pub touch_direct: Option<bool>,
    pub orientation: Option<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub viewer: ViewerConfig,
    pub download_dir: String,
    pub vpn: VpnConfig,
    pub address_book: Vec<BookEntry>,
    pub recent: Vec<String>,
    /// "host:port" -> SHA-256 certificate fingerprint (hex)
    pub known_hosts: BTreeMap<String, String>,
    pub start_with_windows: bool,
    pub public_ip_lookup: bool,
}

impl Default for Config {
    fn default() -> Self {
        let dl = dirs::download_dir().unwrap_or_else(|| PathBuf::from(".")).join("PortlessVNC");
        Config {
            server: ServerConfig::default(),
            viewer: ViewerConfig::default(),
            download_dir: dl.to_string_lossy().into_owned(),
            vpn: VpnConfig::default(),
            address_book: Vec::new(),
            recent: Vec::new(),
            known_hosts: BTreeMap::new(),
            start_with_windows: false,
            public_ip_lookup: true,
        }
    }
}

static MACHINE_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Use the machine-wide (service) settings folder instead of the user's.
pub fn set_machine_mode() {
    MACHINE_MODE.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub fn machine_mode() -> bool {
    MACHINE_MODE.load(std::sync::atomic::Ordering::SeqCst)
}

/// The current user's settings folder (ignores machine mode).
pub fn config_dir() -> PathBuf {
    if machine_mode() {
        return crate::servicectl::machine_dir();
    }
    user_config_dir()
}

/// The current user's settings folder (ignores machine mode).
pub fn user_config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("PORTLESS_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if dir.join("portable.txt").exists() {
                return dir.join("PortlessVNC-data");
            }
        }
    }
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("PortlessVNC")
}

impl Config {
    pub fn load(dir: &Path) -> Config {
        let path = dir.join("config.json");
        let mut cfg: Config = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        if cfg.server.vnc_password.is_empty() {
            // First run: generate a random 8-character password.
            let pw = crate::util::random_password(8);
            cfg.server.vnc_password = crate::rfb::vncauth::obfuscate(&pw);
        }
        cfg
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join("config.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap_or_default())?;
        std::fs::rename(tmp, dir.join("config.json"))
    }

    pub fn vnc_password(&self) -> String {
        crate::rfb::vncauth::deobfuscate(&self.server.vnc_password).unwrap_or_default()
    }

    pub fn set_vnc_password(&mut self, pw: &str) {
        self.server.vnc_password = crate::rfb::vncauth::obfuscate(pw);
    }

    pub fn add_recent(&mut self, addr: &str) {
        self.recent.retain(|a| a != addr);
        self.recent.insert(0, addr.to_string());
        self.recent.truncate(15);
    }
}
