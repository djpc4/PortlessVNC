//! `PortlessVNC.exe --agent`: the headless host started by the service inside
//! the active session (as SYSTEM). It runs the VNC server and the VPN from the
//! machine-wide settings, publishes its status for the user's window, and
//! carries out requests from it (VPN profile / login / connect / disconnect,
//! new one-time password). Exits when its settings are changed from outside
//! (the service then starts a fresh one) or when the service asks it to stop.

use crate::app::Core;
use crate::servicectl::{self, Status, ViewerInfo, VpnImport, VpnLogin};
use crate::vpn::{ovpn::OvpnConfig, ConnectRequest, VpnState};
use base64::Engine as _;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime};

fn config_mtime() -> Option<SystemTime> {
    std::fs::metadata(crate::config::config_dir().join("config.json")).and_then(|m| m.modified()).ok()
}

struct Agent {
    core: std::sync::Arc<Core>,
    /// password typed without "remember": used until the agent restarts
    session_password: Option<String>,
    /// mtime of the config as last written by us (outside changes restart the agent)
    mtime: Option<SystemTime>,
    relay_port: u16,
}

impl Agent {
    fn save(&mut self) {
        self.core.save_config();
        self.mtime = config_mtime();
    }

    fn selected_profile(&self) -> Option<crate::config::VpnProfile> {
        let c = self.core.cfg.read();
        c.vpn.profiles.get(c.vpn.selected).cloned()
    }

    fn saved_password(p: &crate::config::VpnProfile) -> Option<String> {
        let raw = base64::engine::general_purpose::STANDARD.decode(p.password_protected.as_ref()?).ok()?;
        String::from_utf8(crate::platform::unprotect(&raw)?).ok()
    }

    /// Connect the selected profile. `password` overrides the stored one.
    fn connect(&mut self, password: Option<String>) {
        let Some(p) = self.selected_profile() else {
            log::info!("agent: no VPN profile configured");
            return;
        };
        let cfg = match OvpnConfig::load(std::path::Path::new(&p.ovpn_path)) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("agent: VPN profile '{}': {e:#}", p.name);
                return;
            }
        };
        let (user, pass) = match (&cfg.auth_file_creds, cfg.auth_user_pass) {
            (Some((u, pw)), _) => (Some(u.clone()), Some(pw.clone())),
            (None, true) => {
                let pw = password.or_else(|| self.session_password.clone()).or_else(|| Self::saved_password(&p));
                if pw.is_none() {
                    log::info!("agent: VPN profile '{}' needs a login - use Login... in PortlessVNC", p.name);
                }
                (Some(p.username.clone()), pw)
            }
            (None, false) => (None, None),
        };
        log::info!("agent: connecting VPN profile '{}'", p.name);
        self.core.vpn.connect(ConnectRequest { profile_name: p.name.clone(), config: cfg, username: user, password: pass });
    }

    fn set_off(&mut self, off: bool) {
        self.core.cfg.write().vpn.resume = !off;
        self.save();
    }

    fn handle(&mut self, name: &str, data: &[u8]) {
        match name {
            "new-otp" => self.core.server.rotate_otp(),
            "reconnect" | "vpn-connect" => {
                self.set_off(false);
                self.connect(None);
            }
            "vpn-disconnect" => {
                self.set_off(true);
                self.core.vpn.disconnect();
                log::info!("agent: VPN disconnected by the user (stays off until Connect)");
            }
            "vpn-select" => {
                let Ok(i) = std::str::from_utf8(data).unwrap_or("").trim().parse::<usize>() else { return };
                if i < self.core.cfg.read().vpn.profiles.len() {
                    self.core.cfg.write().vpn.selected = i;
                    self.session_password = None;
                    self.set_off(false);
                    self.connect(None);
                }
            }
            "vpn-import" => {
                let Ok(req) = serde_json::from_slice::<VpnImport>(data) else { return };
                let base = crate::util::sanitize_rel_path(&req.name).and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned())).unwrap_or_else(|| "profile".into());
                let path = self.core.dir.join(format!("{base}.ovpn"));
                if std::fs::write(&path, req.text.as_bytes()).is_err() {
                    return;
                }
                match OvpnConfig::load(&path) {
                    Ok(cfg) => {
                        {
                            let mut c = self.core.cfg.write();
                            let path_s = path.to_string_lossy().into_owned();
                            c.vpn.profiles.retain(|p| p.ovpn_path != path_s);
                            c.vpn.profiles.push(crate::config::VpnProfile { name: base.clone(), ovpn_path: path_s, username: cfg.auth_file_creds.map(|c| c.0).unwrap_or_default(), password_protected: None });
                            c.vpn.selected = c.vpn.profiles.len() - 1;
                            c.vpn.resume = true;
                        }
                        self.session_password = None;
                        self.save();
                        log::info!("agent: imported VPN profile '{base}'");
                        self.connect(None);
                    }
                    Err(e) => {
                        log::warn!("agent: cannot use imported profile '{base}': {e:#}");
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
            "vpn-login" => {
                let Ok(req) = serde_json::from_slice::<VpnLogin>(data) else { return };
                let static_challenge = self.selected_profile().and_then(|p| OvpnConfig::load(std::path::Path::new(&p.ovpn_path)).ok()).and_then(|c| c.static_challenge);
                {
                    let mut c = self.core.cfg.write();
                    let i = c.vpn.selected;
                    if let Some(p) = c.vpn.profiles.get_mut(i) {
                        p.username = req.user.clone();
                        p.password_protected = if req.remember { crate::platform::protect_for_config(req.pass.as_bytes()).map(|b| base64::engine::general_purpose::STANDARD.encode(b)) } else { None };
                    }
                    c.vpn.resume = true;
                }
                self.save();
                self.session_password = (!req.remember).then(|| req.pass.clone());
                // one-time codes are never stored: build the static-challenge password now
                let pass = match (&static_challenge, &req.otp) {
                    (Some(_), Some(otp)) => {
                        let e = &base64::engine::general_purpose::STANDARD;
                        format!("SCRV1:{}:{}", e.encode(&req.pass), e.encode(otp))
                    }
                    _ => req.pass.clone(),
                };
                log::info!("agent: VPN login updated for '{}' ({})", req.user, if req.remember { "password saved" } else { "password not saved" });
                self.connect(Some(pass));
            }
            // the signed-in user typed in Shared text: share it with our viewers
            "note-edit" => {
                self.core.hub.note_local_edit(String::from_utf8_lossy(data).into_owned());
            }
            "vpn-challenge" => {
                let resp = String::from_utf8_lossy(data).trim().to_string();
                self.core.vpn.answer_challenge(&resp);
            }
            _ => {}
        }
    }

    fn status(&self) -> Status {
        let core = &self.core;
        let vs = core.vpn.status();
        let (state, detail) = match &vs.state {
            VpnState::Connected => ("connected".to_string(), format!("{} - {}", vs.server.map(|s| s.to_string()).unwrap_or_default(), vs.cipher)),
            VpnState::Connecting(m) => ("connecting".into(), m.clone()),
            VpnState::Reconnecting(m) => ("reconnecting".into(), m.clone()),
            VpnState::Failed(m) => ("failed".into(), m.clone()),
            VpnState::AuthFailed(m) => ("auth-failed".into(), m.clone()),
            VpnState::Challenge { text, .. } => ("challenge".into(), text.clone()),
            VpnState::Disconnected => ("disconnected".into(), String::new()),
        };
        let cfg = core.cfg.read();
        let profile = cfg.vpn.profiles.get(cfg.vpn.selected).cloned();
        let ovpn = profile.as_ref().and_then(|p| OvpnConfig::load(std::path::Path::new(&p.ovpn_path)).ok());
        Status {
            vpn_state: state,
            vpn_ip: core.vpn.vpn_ip().map(|i| i.to_string()),
            vpn_profile: profile.as_ref().map(|p| p.name.clone()).unwrap_or_default(),
            vpn_detail: detail,
            direct_port: core.server.direct_port(),
            vpn_port: cfg.server.port,
            otp: core.server.current_otp(),
            permanent_password: cfg.server.permanent_password,
            fingerprint: core.server.identity.fingerprint.clone(),
            viewers: core.server.client_list().iter().map(|c| ViewerInfo { addr: c.addr.to_string(), via_vpn: c.via_vpn, native: c.native.load(Ordering::Relaxed) }).collect(),
            #[cfg(windows)]
            desktop: crate::platform::desktop::input_desktop_name(),
            #[cfg(not(windows))]
            desktop: std::env::var("PVNC_DESKTOP").unwrap_or_else(|_| "Default".into()),
            vpn_profiles: cfg.vpn.profiles.iter().map(|p| p.name.clone()).collect(),
            vpn_selected: cfg.vpn.selected,
            vpn_user: ovpn.as_ref().and_then(|o| o.auth_file_creds.clone().map(|c| c.0)).or_else(|| profile.as_ref().map(|p| p.username.clone())).unwrap_or_default(),
            vpn_remote: ovpn.as_ref().and_then(|o| o.remotes.first().map(|r| format!("{}:{} {:?}", r.host, r.port, r.proto))).unwrap_or_default(),
            vpn_password_saved: profile.as_ref().map(|p| p.password_protected.is_some()).unwrap_or(false) || self.session_password.is_some(),
            vpn_needs_login: ovpn.as_ref().map(|o| o.auth_user_pass && o.auth_file_creds.is_none()).unwrap_or(false),
            vpn_static_challenge: ovpn.and_then(|o| o.static_challenge),
            vpn_off: !cfg.vpn.resume,
            relay_port: self.relay_port,
            ..Default::default()
        }
    }
}

pub fn run() -> i32 {
    crate::config::set_machine_mode();
    let core = match Core::new() {
        Ok(c) => c,
        Err(e) => {
            log::error!("agent: {e:#}");
            return 1;
        }
    };
    #[cfg(windows)]
    crate::platform::clipboard::start(core.hub.clone());
    core.server.restart();
    log::info!("PortlessVNC agent {} running (service mode)", env!("CARGO_PKG_VERSION"));

    let relay_port = crate::vpn::relay::start(core.vpn.clone());
    let mut agent = Agent { core, session_password: None, mtime: config_mtime(), relay_port };
    // connect at start unless the user switched the VPN off
    if agent.core.cfg.read().vpn.resume {
        agent.connect(None);
    }

    let mut last_status = Instant::now() - Duration::from_secs(10);
    let mut note_published = 0u64;
    loop {
        #[cfg(windows)]
        if crate::platform::service::stop_requested() {
            break;
        }
        if config_mtime() != agent.mtime {
            log::info!("agent: settings changed from Service settings, restarting");
            break;
        }
        for (name, data) in servicectl::take_requests() {
            agent.handle(&name, &data);
            last_status = Instant::now() - Duration::from_secs(10); // publish right away
        }
        if last_status.elapsed() >= Duration::from_secs(1) {
            last_status = Instant::now();
            servicectl::write_status(agent.status());
        }
        // publish shared text for the signed-in user's window
        let (v, text) = agent.core.hub.note_snapshot();
        if v != note_published {
            note_published = v;
            servicectl::write_note(v, &text);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    agent.core.vpn.disconnect();
    agent.core.server.disconnect_all();
    std::thread::sleep(Duration::from_millis(400));
    0
}
