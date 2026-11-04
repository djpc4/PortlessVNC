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

/// How the remote screen is sized in the viewer.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScaleMode {
    /// Fills the window; the picture may be stretched.
    Stretch,
    /// The whole screen fits, shape kept.
    KeepRatio,
    /// Window width filled, shape kept; scrolls up and down if taller.
    FitWidth,
    /// Window height filled, shape kept; scrolls sideways if wider.
    FitHeight,
    /// One remote pixel per screen pixel; scrolls both ways if larger.
    Full,
}

impl ScaleMode {
    pub const ALL: [ScaleMode; 5] = [ScaleMode::KeepRatio, ScaleMode::Stretch, ScaleMode::FitWidth, ScaleMode::FitHeight, ScaleMode::Full];

    pub fn label(self) -> &'static str {
        match self {
            ScaleMode::Stretch => "Fit to window (stretch)",
            ScaleMode::KeepRatio => "Fit to window (keep ratio)",
            ScaleMode::FitWidth => "Fit width (keep ratio)",
            ScaleMode::FitHeight => "Fit height (keep ratio)",
            ScaleMode::Full => "Full size (scroll)",
        }
    }

    /// Horizontal and vertical scale for a `fw` x `fh` remote screen shown in a
    /// `w` x `h` area. `ppp` is the display's physical pixels per UI point.
    pub fn scales(self, w: f32, h: f32, fw: f32, fh: f32, ppp: f32) -> (f32, f32) {
        if fw <= 0.0 || fh <= 0.0 {
            return (1.0, 1.0);
        }
        let (sx, sy) = (w / fw, h / fh);
        let (x, y) = match self {
            ScaleMode::Stretch => (sx, sy),
            ScaleMode::KeepRatio => (sx.min(sy), sx.min(sy)),
            ScaleMode::FitWidth => (sx, sx),
            ScaleMode::FitHeight => (sy, sy),
            ScaleMode::Full => (1.0 / ppp.max(0.1), 1.0 / ppp.max(0.1)),
        };
        (x.max(0.05), y.max(0.05))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct ViewerConfig {
    pub quality: QualityMode,
    pub audio: AudioMode,
    /// Older setting, still written so older versions keep working: see `scale_mode`.
    pub scale_to_fit: bool,
    /// None: not chosen yet, follow `scale_to_fit`.
    pub scale_mode: Option<ScaleMode>,
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
        ViewerConfig { quality: QualityMode::Auto, audio: AudioMode::Auto, scale_to_fit: true, scale_mode: None, share_clipboard: true, capture_system_keys: true, touch_direct: false, orientation: 0, mouse_bar: true }
    }
}

impl ViewerConfig {
    pub fn scale(&self) -> ScaleMode {
        self.scale_mode.unwrap_or(if self.scale_to_fit { ScaleMode::KeepRatio } else { ScaleMode::Full })
    }

    pub fn set_scale(&mut self, m: ScaleMode) {
        self.scale_mode = Some(m);
        self.scale_to_fit = m != ScaleMode::Full;
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
    /// The profile flagged as this computer's home VPN (name). The background
    /// service has its own profile setting and does not use this.
    pub home: Option<String>,
    pub connect_on_start: bool,
    /// Reconnect forever (with backoff) once a profile has worked.
    pub keep_connected: bool,
    /// The VPN was up when the app last ran (and not disconnected by the user).
    pub resume: bool,
}

impl Default for VpnConfig {
    fn default() -> Self {
        VpnConfig { profiles: Vec::new(), selected: 0, home: None, connect_on_start: false, keep_connected: true, resume: false }
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
    /// desktop: the VPN choice below was made (entries from older versions have none)
    pub vpn_assigned: bool,
    /// desktop: reached through the home VPN
    pub vpn_home: bool,
    /// this computer's own viewer settings (None = the app's defaults)
    pub audio: Option<AudioMode>,
    pub quality: Option<QualityMode>,
    pub touch_direct: Option<bool>,
    pub orientation: Option<u8>,
}

/// How a saved client is reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientVpn {
    /// Saved by an older version: decided by address, as it was then.
    Unset,
    /// Local, or needs no VPN: always connects directly.
    None,
    /// Uses the home VPN that is already up (the service's or this window's).
    Home,
    /// Uses this known VPN, connected only while one of its clients is open.
    Guest(String),
}

impl BookEntry {
    pub fn vpn(&self) -> ClientVpn {
        if !self.vpn_assigned {
            ClientVpn::Unset
        } else if self.vpn_home {
            ClientVpn::Home
        } else {
            match &self.vpn_profile {
                Some(n) => ClientVpn::Guest(n.clone()),
                None => ClientVpn::None,
            }
        }
    }

    pub fn set_vpn(&mut self, v: ClientVpn) {
        self.vpn_assigned = v != ClientVpn::Unset;
        self.vpn_home = v == ClientVpn::Home;
        self.vpn_profile = match v {
            ClientVpn::Guest(n) => Some(n),
            _ => None,
        };
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    /// Settings format; older files are copied aside before being changed.
    /// (0 when absent: not the struct's default, or old files would look current)
    #[serde(default)]
    pub config_version: u32,
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
            config_version: CONFIG_VERSION,
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

/// 1 = 0.3.0 (client VPN assignments)
const CONFIG_VERSION: u32 = 1;

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
        if cfg.config_version < CONFIG_VERSION {
            // keep the older settings, in case the older version is wanted back
            let backup = dir.join("config.pre-0.3.json");
            if path.exists() && !backup.exists() {
                if let Err(e) = std::fs::copy(&path, &backup) {
                    log::warn!("Could not back up the older settings: {e}");
                }
            }
            // the profile in use so far becomes the home VPN
            cfg.vpn.home = cfg.vpn.profiles.get(cfg.vpn.selected).map(|p| p.name.clone());
            cfg.config_version = CONFIG_VERSION;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_modes_size_the_picture() {
        // a 2000 x 1000 remote screen in a 1000 x 1000 area
        let s = |m: ScaleMode| m.scales(1000.0, 1000.0, 2000.0, 1000.0, 1.0);
        assert_eq!(s(ScaleMode::Stretch), (0.5, 1.0));
        assert_eq!(s(ScaleMode::KeepRatio), (0.5, 0.5));
        assert_eq!(s(ScaleMode::FitWidth), (0.5, 0.5));
        assert_eq!(s(ScaleMode::FitHeight), (1.0, 1.0));
        assert_eq!(s(ScaleMode::Full), (1.0, 1.0));
        // a small remote screen grows to fit
        assert_eq!(ScaleMode::KeepRatio.scales(1000.0, 1000.0, 500.0, 500.0, 1.0), (2.0, 2.0));
        // full size means real pixels on a scaled display
        assert_eq!(ScaleMode::Full.scales(1000.0, 1000.0, 500.0, 500.0, 2.0), (0.5, 0.5));
    }

    #[test]
    fn older_fit_setting_carries_over_and_stays_written() {
        let old: ViewerConfig = serde_json::from_str(r#"{"scale_to_fit":false}"#).unwrap();
        assert_eq!(old.scale(), ScaleMode::Full);
        let old: ViewerConfig = serde_json::from_str(r#"{"scale_to_fit":true}"#).unwrap();
        assert_eq!(old.scale(), ScaleMode::KeepRatio);
        let mut c = ViewerConfig::default();
        c.set_scale(ScaleMode::Full);
        assert!(!c.scale_to_fit);
        c.set_scale(ScaleMode::Stretch);
        assert!(c.scale_to_fit);
        assert_eq!(c.scale(), ScaleMode::Stretch);
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pvnc-config-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const OLD_SETTINGS: &str = r#"{
        "vpn": { "profiles": [
            { "name": "first", "ovpn_path": "a.ovpn", "username": "", "password_protected": null },
            { "name": "second", "ovpn_path": "b.ovpn", "username": "", "password_protected": null }
        ], "selected": 1 },
        "address_book": [ { "name": "Office", "address": "10.8.0.6", "username": "", "password_protected": null } ],
        "known_hosts": { "10.8.0.6:5900": "abc" }
    }"#;

    #[test]
    fn older_settings_are_backed_up_and_keep_working() {
        let d = temp_dir("old");
        std::fs::write(d.join("config.json"), OLD_SETTINGS).unwrap();
        let c = Config::load(&d);
        // a copy of the older file, byte for byte
        assert_eq!(std::fs::read_to_string(d.join("config.pre-0.3.json")).unwrap(), OLD_SETTINGS);
        // the profile in use becomes home
        assert_eq!(c.vpn.home.as_deref(), Some("second"));
        // older clients keep being decided by address, and their trust carries over
        assert_eq!(c.address_book[0].vpn(), ClientVpn::Unset);
        assert_eq!(c.known_hosts.get("10.8.0.6:5900").map(|s| s.as_str()), Some("abc"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn current_settings_are_not_migrated_again() {
        let d = temp_dir("new");
        let mut c = Config::default();
        c.vpn.profiles.push(VpnProfile { name: "guest".into(), ..Default::default() });
        c.vpn.home = None; // the flag was removed on purpose
        c.save(&d).unwrap();
        let again = Config::load(&d);
        assert_eq!(again.vpn.home, None);
        assert!(!d.join("config.pre-0.3.json").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn client_vpn_choices_survive_saving() {
        for v in [ClientVpn::None, ClientVpn::Home, ClientVpn::Guest("Dave".into())] {
            let mut e = BookEntry::default();
            e.set_vpn(v.clone());
            let s = serde_json::to_string(&e).unwrap();
            let back: BookEntry = serde_json::from_str(&s).unwrap();
            assert_eq!(back.vpn(), v);
        }
    }
}
