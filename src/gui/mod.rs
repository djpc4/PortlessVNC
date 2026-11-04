//! Main window: host panel (addresses, password, viewers) + connect panel.

mod session;
#[cfg(windows)]
pub mod soft;

use crate::app::Core;
use crate::config::{AudioMode, AuthMode, BookEntry, Config, QualityMode, VpnProfile};
use crate::hub::{Direction, XferState};
use crate::vpn::{ovpn::OvpnConfig, ConnectRequest, VpnState};
use eframe::egui::{self, Color32, RichText};
use parking_lot::Mutex;
use session::SessionView;
use std::sync::Arc;
use std::time::{Duration, Instant};

const ACCENT: Color32 = Color32::from_rgb(0x2f, 0x9e, 0x6b);

struct VpnPrompt {
    profile: usize,
    user: String,
    pass: String,
    otp: String,
    remember: bool,
    static_challenge: Option<(String, bool)>,
    message: String,
    /// dynamic CRV1 challenge (only the response is asked)
    challenge: Option<(String, bool)>,
    /// the login is for the background service (sent to it, not used here)
    for_service: bool,
}

pub struct App {
    core: Arc<Core>,
    host_only: bool,
    address: String,
    sessions: Vec<SessionView>,
    /// Some(new password being typed) while changing the permanent password
    pw_edit: Option<String>,
    addr_had_focus: bool,
    about_open: bool,
    settings: Option<Config>,
    settings_pw: String,
    vpn_prompt: Option<VpnPrompt>,
    local_ips: Vec<crate::netinfo::LocalAddr>,
    ips_at: Instant,
    public_ip: Arc<Mutex<Option<String>>>,
    toast: Option<(String, Instant)>,
    book_name: String,
    show_log: bool,
    minimize_once: bool,
    /// this window edits the background service's settings (--service-config)
    service_config: bool,
    /// status published by the background service, if it is running
    svc: Option<crate::servicectl::Status>,
    svc_at: Instant,
}

impl App {
    pub fn new(ctx: &egui::Context, core: Arc<Core>, host_only: bool, minimized: bool, service_config: bool) -> App {
        crate::util::set_repaint_ctx(ctx.clone());
        #[cfg(windows)]
        crate::platform::keyhook::install();
        #[cfg(windows)]
        if std::env::var_os("PVNC_TEST_INJECTED").is_some() {
            std::thread::spawn(|| loop {
                std::thread::sleep(Duration::from_secs(1));
                log::info!("hook calls so far: {}", crate::platform::keyhook::HOOK_CALLS.load(std::sync::atomic::Ordering::Relaxed));
            });
        }
        let public_ip = Arc::new(Mutex::new(None));
        if core.cfg.read().public_ip_lookup {
            crate::netinfo::lookup_public_ip(public_ip.clone());
        }
        let mut app = App {
            core,
            host_only,
            address: String::new(),
            sessions: Vec::new(),
            pw_edit: None,
            addr_had_focus: false,
            about_open: false,
            settings: None,
            settings_pw: String::new(),
            vpn_prompt: None,
            local_ips: crate::netinfo::local_addrs(),
            ips_at: Instant::now(),
            public_ip,
            toast: None,
            book_name: String::new(),
            show_log: false,
            minimize_once: minimized,
            service_config,
            svc: crate::servicectl::read_status(),
            svc_at: Instant::now(),
        };
        let auto = {
            let v = &app.core.cfg.read().vpn;
            v.connect_on_start || (v.keep_connected && v.resume)
        };
        // with the service running, the service keeps the VPN; this window's own VPN is for viewing only
        if auto && !app.service_config && app.svc.is_none() {
            app.vpn_connect(false);
        }
        if app.service_config {
            if std::env::args().any(|a| a == "--vpn-login") {
                app.vpn_connect(true); // straight to the login prompt
            } else {
                app.settings = Some(app.core.cfg.read().clone());
            }
        }
        app
    }

    fn spawn_self_args(&mut self, args: &[&str]) {
        match std::env::current_exe().and_then(|e| std::process::Command::new(e).args(args).spawn()) {
            Ok(_) => {}
            Err(e) => self.toast(format!("Could not start: {e}")),
        }
    }

    fn spawn_self(&mut self, arg: &str) {
        match std::env::current_exe().and_then(|e| std::process::Command::new(e).arg(arg).spawn()) {
            Ok(_) => {}
            Err(e) => self.toast(format!("Could not start: {e}")),
        }
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    fn copy(&mut self, ctx: &egui::Context, text: String) {
        ctx.output_mut(|o| o.copied_text = text.clone());
        self.toast(format!("Copied {text}"));
    }

    pub fn connect_to(&mut self, address: &str, user: &str, pass: &str) {
        let address = address.trim();
        if address.is_empty() {
            return;
        }
        if crate::viewer::parse_address(address).is_none() {
            self.toast("Invalid address");
            return;
        }
        let s = crate::viewer::Session::start(self.core.clone(), address, user, pass);
        self.core.sessions.lock().push(s.clone());
        self.sessions.push(SessionView::new(s));
    }

    // ---- VPN -------------------------------------------------------------------

    fn selected_profile(&self) -> Option<(usize, VpnProfile)> {
        let c = self.core.cfg.read();
        let i = c.vpn.selected;
        c.vpn.profiles.get(i).cloned().map(|p| (i, p))
    }

    fn vpn_connect(&mut self, force_prompt: bool) {
        let Some((idx, prof)) = self.selected_profile() else {
            self.toast("Import an .ovpn profile first");
            return;
        };
        let cfg = match OvpnConfig::load(std::path::Path::new(&prof.ovpn_path)) {
            Ok(c) => c,
            Err(e) => {
                self.toast(format!("Profile error: {e:#}"));
                log::warn!("VPN profile {}: {e:#}", prof.ovpn_path);
                return;
            }
        };
        for w in &cfg.warnings {
            log::debug!("ovpn: {w}");
        }
        if self.service_config && !cfg.auth_user_pass {
            self.toast("This profile needs no login - the service connects with it automatically");
            return;
        }
        let force_prompt = force_prompt || self.service_config;
        if !cfg.auth_user_pass {
            self.core.vpn.connect(ConnectRequest { profile_name: prof.name.clone(), config: cfg, username: None, password: None });
            return;
        }
        if let Some((u, p)) = cfg.auth_file_creds.clone() {
            if !force_prompt && cfg.static_challenge.is_none() {
                self.core.vpn.connect(ConnectRequest { profile_name: prof.name.clone(), config: cfg, username: Some(u), password: Some(p) });
                return;
            }
        }
        let saved = prof.password_protected.as_ref().and_then(|b| {
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD.decode(b).ok()?;
            String::from_utf8(crate::platform::unprotect(&raw)?).ok()
        });
        if let (false, Some(p), None) = (force_prompt, saved.clone(), cfg.static_challenge.as_ref()) {
            self.core.vpn.connect(ConnectRequest { profile_name: prof.name.clone(), config: cfg, username: Some(prof.username.clone()), password: Some(p) });
            return;
        }
        self.vpn_prompt = Some(VpnPrompt {
            profile: idx,
            user: prof.username.clone(),
            pass: saved.clone().unwrap_or_default(),
            otp: String::new(),
            remember: saved.is_some() || self.service_config, // the service needs the saved password
            static_challenge: cfg.static_challenge.clone(),
            message: String::new(),
            challenge: None,
            for_service: false,
        });
    }

    fn submit_vpn_prompt(&mut self) {
        let Some(p) = self.vpn_prompt.take() else { return };
        if p.for_service {
            // goes to the service's own (persistent) settings
            if p.challenge.is_some() {
                crate::servicectl::request_with("vpn-challenge", p.otp.as_bytes());
            } else {
                crate::servicectl::request_json("vpn-login", &crate::servicectl::VpnLogin { user: p.user, pass: p.pass, otp: p.static_challenge.is_some().then_some(p.otp), remember: p.remember });
                self.toast("Login sent to the service");
            }
            return;
        }
        if p.challenge.is_some() {
            self.core.vpn.answer_challenge(&p.otp);
            return;
        }
        let prof = self.core.cfg.read().vpn.profiles.get(p.profile).cloned();
        let Some(prof) = prof else { return };
        let cfg = match OvpnConfig::load(std::path::Path::new(&prof.ovpn_path)) {
            Ok(c) => c,
            Err(e) => {
                self.toast(format!("Profile error: {e:#}"));
                return;
            }
        };
        {
            let mut c = self.core.cfg.write();
            if let Some(pr) = c.vpn.profiles.get_mut(p.profile) {
                pr.username = p.user.clone();
                pr.password_protected = if p.remember {
                    use base64::Engine;
                    crate::platform::protect_for_config(p.pass.as_bytes()).map(|b| base64::engine::general_purpose::STANDARD.encode(b))
                } else {
                    None
                };
            }
        }
        self.core.save_config();
        if self.service_config {
            self.toast("VPN login saved - the service reconnects with it now");
            return;
        }
        let password = if p.static_challenge.is_some() {
            use base64::Engine;
            let e = &base64::engine::general_purpose::STANDARD;
            format!("SCRV1:{}:{}", e.encode(&p.pass), e.encode(&p.otp))
        } else {
            p.pass
        };
        self.core.vpn.connect(ConnectRequest { profile_name: prof.name, config: cfg, username: Some(p.user), password: Some(password) });
    }

    fn import_profile(&mut self) {
        let Some(mut path) = rfd::FileDialog::new().add_filter("OpenVPN profile", &["ovpn", "conf"]).pick_file() else { return };
        // the service reads its profile from its own (protected) folder
        if crate::config::machine_mode() {
            let dest = self.core.dir.join(path.file_name().unwrap_or_default());
            if let Err(e) = std::fs::copy(&path, &dest) {
                self.toast(format!("Could not copy the profile: {e}"));
                return;
            }
            path = dest;
        }
        match OvpnConfig::load(&path) {
            Ok(cfg) => {
                let name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "VPN".into());
                let mut c = self.core.cfg.write();
                c.vpn.profiles.retain(|p| p.ovpn_path != path.to_string_lossy());
                c.vpn.profiles.push(VpnProfile { name: name.clone(), ovpn_path: path.to_string_lossy().into_owned(), username: cfg.auth_file_creds.clone().map(|c| c.0).unwrap_or_default(), password_protected: None });
                c.vpn.selected = c.vpn.profiles.len() - 1;
                drop(c);
                self.core.save_config();
                let r = cfg.remotes.first().map(|r| format!("{}:{} {:?}", r.host, r.port, r.proto)).unwrap_or_default();
                log::info!("Imported VPN profile '{name}' ({r})");
                self.toast(format!("Imported profile '{name}'"));
            }
            Err(e) => {
                log::warn!("Cannot use {}: {e:#}", path.display());
                self.toast(format!("Cannot use this profile: {e:#}"));
            }
        }
    }

    // ---- panels ------------------------------------------------------------------

    /// VPN card of the service-settings window: shows the running service's
    /// tunnel and lets the admin pick the profile / enter its login.
    fn service_vpn_card(&mut self, ui: &mut egui::Ui) {
        let fill = if ui.visuals().dark_mode { Color32::from_rgb(0x12, 0x3b, 0x2b) } else { Color32::from_rgb(0xe3, 0xf6, 0xec) };
        let svc = self.svc.clone();
        egui::Frame::none().fill(fill).stroke(egui::Stroke::new(1.5, ACCENT)).rounding(10.0).inner_margin(12.0).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("SERVICE VPN").strong().color(ACCENT));
            match svc.as_ref() {
                Some(s) => match &s.vpn_ip {
                    Some(ip) => {
                        ui.label(RichText::new(ip).size(28.0).monospace().strong());
                        ui.label(RichText::new(format!("Connected to '{}' via {}", s.vpn_profile, s.vpn_detail)).small());
                    }
                    None => {
                        ui.label(RichText::new(format!("VPN {}", s.vpn_state)).size(18.0).weak());
                        ui.label(RichText::new(&s.vpn_detail).small());
                    }
                },
                None => {
                    ui.label(RichText::new("The service is not running.").weak());
                }
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let (names, mut sel) = {
                    let c = self.core.cfg.read();
                    (c.vpn.profiles.iter().map(|p| p.name.clone()).collect::<Vec<_>>(), c.vpn.selected)
                };
                let before = sel;
                egui::ComboBox::from_id_salt("svcprof").selected_text(names.get(sel).cloned().unwrap_or_else(|| "(no profile)".into())).width(150.0).show_ui(ui, |ui| {
                    for (i, n) in names.iter().enumerate() {
                        ui.selectable_value(&mut sel, i, n);
                    }
                });
                if sel != before {
                    self.core.cfg.write().vpn.selected = sel;
                    self.core.save_config();
                }
                if ui.button("Import .ovpn...").clicked() {
                    self.import_profile();
                }
            });
            if ui.add_enabled(!self.core.cfg.read().vpn.profiles.is_empty(), egui::Button::new("Enter VPN login...")).clicked() {
                self.vpn_connect(true);
            }
            ui.label(RichText::new("Saving a profile or login restarts the service's host, which then connects with it.").small().weak());
        });
    }

    fn vpn_card(&mut self, ui: &mut egui::Ui) {
        if self.service_config {
            self.service_vpn_card(ui);
            return;
        }
        let st = self.core.vpn.status();
        let port = self.core.server.port();
        let fill = if ui.visuals().dark_mode { Color32::from_rgb(0x12, 0x3b, 0x2b) } else { Color32::from_rgb(0xe3, 0xf6, 0xec) };
        egui::Frame::none().fill(fill).stroke(egui::Stroke::new(1.5, ACCENT)).rounding(10.0).inner_margin(12.0).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("VPN ADDRESS").strong().color(ACCENT));
                ui.label(RichText::new("no port forwarding needed").small().italics());
            });
            match (&st.state, st.info.as_ref().and_then(|i| i.ip)) {
                (VpnState::Connected, Some(ip)) => {
                    let text = if port == 5900 { ip.to_string() } else { format!("{ip}:{port}") };
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&text).size(28.0).monospace().strong());
                        if ui.button("Copy").clicked() {
                            let t = text.clone();
                            self.copy(ui.ctx(), t);
                        }
                    });
                    let since = st.since.map(|s| s.elapsed().as_secs()).unwrap_or(0);
                    ui.label(RichText::new(format!(
                        "Connected to '{}' via {} - {} - up {}:{:02}:{:02}",
                        st.profile,
                        st.server.map(|s| s.to_string()).unwrap_or_default(),
                        st.cipher,
                        since / 3600,
                        (since / 60) % 60,
                        since % 60
                    ))
                    .small());
                    let gw = st.info.as_ref().and_then(|i| i.gateway).map(|g| g.to_string()).unwrap_or_default();
                    match (st.gateway_checked, st.gateway_rtt) {
                        (true, Some(rtt)) => ui.label(RichText::new(format!("Tunnel OK: VPN gateway {gw} answered in {} ms", rtt.as_millis())).small().color(ACCENT)),
                        (true, None) => ui.label(RichText::new(format!("VPN gateway {gw} did not answer ping (may be normal if ICMP is filtered)")).small()),
                        _ => ui.label(RichText::new("Checking tunnel...").small()),
                    };
                    ui.label(RichText::new("Others on the same VPN connect to this address. The VPN server must allow client-to-client traffic.").small().weak());
                }
                (VpnState::Connecting(m), _) | (VpnState::Reconnecting(m), _) => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(m);
                    });
                }
                (VpnState::Failed(m), _) => {
                    ui.colored_label(Color32::from_rgb(0xd9, 0x48, 0x48), format!("Failed: {m}"));
                }
                (VpnState::AuthFailed(m), _) => {
                    ui.colored_label(Color32::from_rgb(0xd9, 0x48, 0x48), format!("Login rejected: {m}"));
                    if ui.button("Enter credentials again").clicked() {
                        self.vpn_connect(true);
                    }
                }
                (VpnState::Challenge { text, echo }, _) => {
                    ui.label(format!("The VPN server asks: {text}"));
                    if self.vpn_prompt.is_none() {
                        let idx = self.core.cfg.read().vpn.selected;
                        self.vpn_prompt = Some(VpnPrompt { profile: idx, user: String::new(), pass: String::new(), otp: String::new(), remember: false, static_challenge: None, message: text.clone(), challenge: Some((text.clone(), *echo)), for_service: false });
                    }
                }
                _ => {
                    ui.label(RichText::new("Not connected").size(20.0).weak());
                }
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let (names, mut sel) = {
                    let c = self.core.cfg.read();
                    (c.vpn.profiles.iter().map(|p| p.name.clone()).collect::<Vec<_>>(), c.vpn.selected)
                };
                let label = names.get(sel).cloned().unwrap_or_else(|| "(no profile)".into());
                let before = sel;
                egui::ComboBox::from_id_salt("vpnprof").selected_text(label).width(150.0).show_ui(ui, |ui| {
                    for (i, n) in names.iter().enumerate() {
                        ui.selectable_value(&mut sel, i, n);
                    }
                });
                if sel != before {
                    self.core.cfg.write().vpn.selected = sel;
                    self.core.save_config();
                }
                if ui.button("Import .ovpn...").clicked() {
                    self.import_profile();
                }
            });
            ui.horizontal(|ui| {
                let active = matches!(st.state, VpnState::Connected | VpnState::Connecting(_) | VpnState::Reconnecting(_));
                if active {
                    if ui.button("Disconnect VPN").clicked() {
                        self.core.vpn.disconnect();
                        self.core.cfg.write().vpn.resume = false; // the user wants it off
                        self.core.save_config();
                    }
                } else if ui.add_enabled(!self.core.cfg.read().vpn.profiles.is_empty(), egui::Button::new(RichText::new("Connect VPN").strong())).clicked() {
                    self.vpn_connect(false);
                }
                if !self.core.cfg.read().vpn.profiles.is_empty() && !active && ui.small_button("Remove profile").clicked() {
                    let mut c = self.core.cfg.write();
                    let i = c.vpn.selected;
                    if i < c.vpn.profiles.len() {
                        c.vpn.profiles.remove(i);
                    }
                    c.vpn.selected = 0;
                    drop(c);
                    self.core.save_config();
                }
            });
        });
    }

    fn direct_card(&mut self, ui: &mut egui::Ui) {
        if self.ips_at.elapsed() > Duration::from_secs(15) {
            self.local_ips = crate::netinfo::local_addrs();
            self.ips_at = Instant::now();
        }
        let direct = self.core.cfg.read().server.listen_direct;
        let st = self.core.server.status.lock().clone();
        let port = st.listening.map(|a| a.port()).unwrap_or_else(|| self.core.server.port());
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Direct addresses").strong());
            if !direct {
                ui.label(RichText::new("Direct connections are off (VPN only).").small().weak());
                return;
            }
            let fmt = |ip: &std::net::IpAddr| -> String {
                match (ip, port) {
                    (std::net::IpAddr::V6(v6), _) => format!("[{v6}]:{port}"),
                    (_, 5900) => ip.to_string(),
                    _ => format!("{ip}:{port}"),
                }
            };
            let ips = self.local_ips.clone();
            for a in ips.iter().filter(|a| a.ip.is_ipv4()) {
                ui.horizontal(|ui| {
                    let t = fmt(&a.ip);
                    ui.label(RichText::new(&t).monospace());
                    ui.label(RichText::new(format!("LAN - {}", a.iface)).small().weak());
                    if ui.small_button("Copy").clicked() {
                        self.copy(ui.ctx(), t);
                    }
                });
            }
            let pubip = self.public_ip.lock().clone();
            ui.horizontal(|ui| match pubip {
                Some(ip) => {
                    ui.label(RichText::new(&ip).monospace());
                    ui.label(RichText::new(format!("Internet - needs TCP {port} forwarded")).small().weak());
                }
                None if self.core.cfg.read().public_ip_lookup => {
                    ui.label(RichText::new("public IP: checking...").small().weak());
                }
                None => {
                    if ui.small_button("Show public IP").clicked() {
                        crate::netinfo::lookup_public_ip(self.public_ip.clone());
                    }
                }
            });
            ui.label(RichText::new("Direct connections may be blocked by Windows Firewall (allowing the app there needs admin). The VPN address is not affected.").small().weak());
        });
    }

    fn access_card(&mut self, ui: &mut egui::Ui) {
        let (auth, pw) = {
            let c = self.core.cfg.read();
            (c.server.auth, c.vnc_password())
        };
        let st = self.core.server.status.lock().clone();
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Access").strong());
                let enabled = self.core.cfg.read().server.enabled;
                match (enabled, &st.listening, &st.error) {
                    (false, _, _) => ui.label(RichText::new("hosting off").small().weak()),
                    (true, Some(a), _) => ui.label(RichText::new(format!("ready (direct port {})", a.port())).small().color(ACCENT)),
                    (true, None, Some(e)) => ui.colored_label(Color32::from_rgb(0xd9, 0x48, 0x48), format!("{e} - VPN still works")),
                    (true, None, None) => ui.label(RichText::new("ready (VPN only)").small().color(ACCENT)),
                };
            });
            let (mut perm_on, mut otp_on) = {
                let c = self.core.cfg.read();
                (c.server.permanent_password, c.server.one_time_password)
            };
            let (p0, o0) = (perm_on, otp_on);
            if auth != AuthMode::None {
                ui.horizontal(|ui| {
                    if auth == AuthMode::VncPassword {
                        ui.checkbox(&mut perm_on, "Permanent password");
                    }
                    ui.checkbox(&mut otp_on, "One-time password").on_hover_text("A random password that works for one login, then changes. Give it out for a single session.");
                });
            }
            if (perm_on, otp_on) != (p0, o0) {
                {
                    let mut c = self.core.cfg.write();
                    c.server.permanent_password = perm_on;
                    c.server.one_time_password = otp_on;
                }
                self.core.save_config();
            }
            // in the service-settings window the live one-time password is the service's
            let otp_now = if self.service_config { self.svc.as_ref().and_then(|s| s.otp.clone()) } else { self.core.server.current_otp() };
            if let Some(otp) = otp_now {
                ui.horizontal(|ui| {
                    ui.label("One-time:");
                    ui.label(RichText::new(&otp).monospace().size(18.0).strong().color(ACCENT));
                    if ui.small_button("Copy").clicked() {
                        self.copy(ui.ctx(), otp.clone());
                    }
                    if ui.small_button("New").clicked() {
                        if self.service_config {
                            crate::servicectl::request("new-otp");
                        } else {
                            self.core.server.rotate_otp();
                        }
                    }
                });
            }
            if auth == AuthMode::VncPassword && !perm_on && !otp_on {
                ui.colored_label(Color32::from_rgb(0xd9, 0x8a, 0x20), "Both passwords are off - nobody can log in.");
            }
            match auth {
                AuthMode::VncPassword if !perm_on => {}
                AuthMode::VncPassword => {
                    let mut save = None;
                    let mut cancel = false;
                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        match self.pw_edit.as_mut() {
                            None => {
                                ui.label(RichText::new("\u{2022}".repeat(pw.chars().count().max(1))).monospace().size(16.0));
                                if ui.small_button("Change").clicked() {
                                    self.pw_edit = Some(String::new());
                                }
                            }
                            Some(new) => {
                                let r = ui.add(egui::TextEdit::singleline(new).password(true).char_limit(8).desired_width(110.0).hint_text("new password"));
                                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                if (ui.small_button("Save").clicked() || enter) && !new.is_empty() {
                                    save = Some(new.clone());
                                }
                                if ui.small_button("Cancel").clicked() {
                                    cancel = true;
                                }
                            }
                        }
                    });
                    if let Some(n) = save {
                        self.core.cfg.write().set_vnc_password(&n);
                        self.core.save_config();
                        self.pw_edit = None;
                        self.toast("Password changed");
                    } else if cancel {
                        self.pw_edit = None;
                    }
                }
                AuthMode::SystemAccount => {
                    ui.label(format!("Viewers sign in with a Windows account (e.g. {}).", crate::platform::current_user()));
                }
                AuthMode::None => {
                    ui.colored_label(Color32::from_rgb(0xd9, 0x8a, 0x20), "No password required - anyone who can reach this computer can control it.");
                }
            }
            let fp = crate::util::short_fingerprint(&self.core.server.identity.fingerprint);
            ui.label(RichText::new(format!("Fingerprint: {fp}")).small().monospace().weak())
                .on_hover_text("Not an address: this is the fingerprint of this computer's encryption certificate. Viewers show it the first time they connect, so you can check you reached the right computer.");
        });
    }

    /// The window's menu bar: PortlessVNC / Service / View / Help.
    fn menu_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        use std::sync::atomic::Ordering;
        ui.menu_button(RichText::new("PortlessVNC").strong().color(ACCENT), |ui| {
            #[cfg(any(windows, target_os = "linux"))]
            {
                use crate::platform::appinstall;
                if appinstall::running_installed() {
                    if ui.button("Uninstall PortlessVNC...").clicked() {
                        self.spawn_self("--uninstall-app");
                        ui.close_menu();
                    }
                } else {
                    let label = if appinstall::is_installed() { "Update installed copy" } else { "Install on this computer..." };
                    if ui.button(label).on_hover_text("For your account: Start menu shortcut and Apps & features entry. No administrator rights needed.").clicked() {
                        self.spawn_self("--install-app");
                        ui.close_menu();
                    }
                    if appinstall::is_installed() && ui.button("Uninstall PortlessVNC...").clicked() {
                        let _ = std::process::Command::new(appinstall::installed_exe()).arg("--uninstall-app").spawn();
                        ui.close_menu();
                    }
                }
                ui.separator();
            }
            if ui.button("Settings...").clicked() {
                if self.settings.is_none() {
                    self.settings = Some(self.core.cfg.read().clone());
                }
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Exit").clicked() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
        ui.menu_button("Service", |ui| {
            let svc = self.svc.clone();
            match svc {
                None if !self.service_config => {
                    ui.label(RichText::new("Not installed").small().weak());
                    if ui.button("Install as a service...").on_hover_text("Starts with Windows, keeps the VPN connected, allows control of the sign-in screen. Asks for administrator rights.").clicked() {
                        self.spawn_self("--install-service");
                        self.toast("Approve the administrator prompt to install the service");
                        ui.close_menu();
                    }
                }
                _ => {
                    let v = self.svc.as_ref().map(|s| s.version.clone()).unwrap_or_default();
                    ui.label(RichText::new(format!("Running (version {v})")).small().weak());
                    let mine = env!("CARGO_PKG_VERSION");
                    if ui.button(if v != mine { format!("Update service to {mine}") } else { "Reinstall service".into() }).clicked() {
                        self.spawn_self("--install-service");
                        self.toast("Approve the administrator prompt to update the service");
                        ui.close_menu();
                    }
                    if !self.service_config && ui.button("Service settings...").clicked() {
                        self.spawn_self("--service-config");
                        ui.close_menu();
                    }
                    if ui.button("Remove service...").clicked() {
                        self.spawn_self("--uninstall-service");
                        ui.close_menu();
                    }
                }
            }
        });
        ui.menu_button("View", |ui| {
            if ui.checkbox(&mut self.show_log, "Log").clicked() {
                ui.close_menu();
            }
            let mut open = self.core.hub.note_window.load(Ordering::Relaxed);
            if ui.checkbox(&mut open, "Shared text").clicked() {
                self.core.hub.note_window.store(open, Ordering::Relaxed);
                ui.close_menu();
            }
        });
        ui.menu_button("Help", |ui| {
            if ui.button("About PortlessVNC").clicked() {
                self.about_open = true;
                ui.close_menu();
            }
            if ui.button("Open settings folder").clicked() {
                let _ = std::process::Command::new("explorer").arg(&self.core.dir).spawn();
                ui.close_menu();
            }
        });
        // quick access on the right, as before
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(env!("CARGO_PKG_VERSION")).small().weak());
            let open = self.core.hub.note_window.load(Ordering::Relaxed);
            if self.core.hub.note_unread() && ui.selectable_label(open, "Shared text \u{25CF}").clicked() {
                self.core.hub.note_window.store(!open, Ordering::Relaxed);
            }
        });
    }

    /// Host panel while the background service runs.
    fn service_card(&mut self, ui: &mut egui::Ui, st: &crate::servicectl::Status) {
        let fill = if ui.visuals().dark_mode { Color32::from_rgb(0x12, 0x3b, 0x2b) } else { Color32::from_rgb(0xe3, 0xf6, 0xec) };
        egui::Frame::none().fill(fill).stroke(egui::Stroke::new(1.5, ACCENT)).rounding(10.0).inner_margin(12.0).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("VPN ADDRESS").strong().color(ACCENT));
                ui.label(RichText::new("hosted by the background service").small().italics());
            });
            let red = Color32::from_rgb(0xd9, 0x48, 0x48);
            match (&st.vpn_ip, st.vpn_state.as_str()) {
                (Some(ip), _) => {
                    let text = if st.vpn_port == 5900 { ip.clone() } else { format!("{ip}:{}", st.vpn_port) };
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&text).size(28.0).monospace().strong());
                        if ui.button("Copy").clicked() {
                            self.copy(ui.ctx(), text.clone());
                        }
                    });
                    ui.label(RichText::new(format!("Connected via {}", st.vpn_detail)).small());
                }
                (None, "connecting") | (None, "reconnecting") => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(&st.vpn_detail);
                    });
                }
                (None, "auth-failed") => {
                    ui.colored_label(red, format!("Login rejected: {}", st.vpn_detail));
                }
                (None, "failed") => {
                    ui.colored_label(red, format!("Failed: {}", st.vpn_detail));
                }
                (None, "challenge") => {
                    ui.label(format!("The VPN server asks: {}", st.vpn_detail));
                    if self.vpn_prompt.is_none() {
                        self.vpn_prompt = Some(VpnPrompt { profile: st.vpn_selected, user: String::new(), pass: String::new(), otp: String::new(), remember: false, static_challenge: None, message: String::new(), challenge: Some((st.vpn_detail.clone(), false)), for_service: true });
                    }
                }
                _ => {
                    ui.label(RichText::new(if st.vpn_off { "Not connected (switched off)" } else { "Not connected" }).size(20.0).weak());
                }
            }
            ui.add_space(6.0);
            // the service's profile, like the normal window's VPN card
            ui.horizontal(|ui| {
                let names = st.vpn_profiles.clone();
                let mut sel = st.vpn_selected;
                egui::ComboBox::from_id_salt("svc-prof").selected_text(names.get(sel).cloned().unwrap_or_else(|| "(no profile)".into())).width(150.0).show_ui(ui, |ui| {
                    for (i, n) in names.iter().enumerate() {
                        ui.selectable_value(&mut sel, i, n);
                    }
                });
                if sel != st.vpn_selected {
                    crate::servicectl::request_with("vpn-select", sel.to_string().as_bytes());
                }
                if ui.button("Import .ovpn...").clicked() {
                    if let Some(path) = rfd::FileDialog::new().add_filter("OpenVPN profile", &["ovpn", "conf"]).pick_file() {
                        match (OvpnConfig::load(&path), std::fs::read_to_string(&path)) {
                            (Ok(_), Ok(text)) => {
                                let name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "VPN".into());
                                crate::servicectl::request_json("vpn-import", &crate::servicectl::VpnImport { name: name.clone(), text });
                                self.toast(format!("Profile '{name}' sent to the service"));
                            }
                            (Err(e), _) => self.toast(format!("Cannot use this profile: {e:#}")),
                            (_, Err(e)) => self.toast(format!("Cannot read the profile: {e}")),
                        }
                    }
                }
            });
            if !st.vpn_remote.is_empty() {
                let who = if st.vpn_needs_login {
                    format!(" - user '{}'{}", st.vpn_user, if st.vpn_password_saved { ", password saved" } else { ", no password saved" })
                } else {
                    String::new()
                };
                ui.label(RichText::new(format!("Server {}{who}", st.vpn_remote)).small().weak());
            }
            ui.horizontal(|ui| {
                let active = st.vpn_ip.is_some() || matches!(st.vpn_state.as_str(), "connecting" | "reconnecting");
                if active {
                    if ui.button("Disconnect VPN").on_hover_text("Stays off (also after restarts) until you press Connect").clicked() {
                        crate::servicectl::request("vpn-disconnect");
                    }
                } else if ui.add_enabled(!st.vpn_profiles.is_empty(), egui::Button::new(RichText::new("Connect VPN").strong())).clicked() {
                    crate::servicectl::request("vpn-connect");
                }
                if st.vpn_needs_login && ui.button("Login...").clicked() {
                    self.vpn_prompt = Some(VpnPrompt {
                        profile: st.vpn_selected,
                        user: st.vpn_user.clone(),
                        pass: String::new(),
                        otp: String::new(),
                        remember: true,
                        static_challenge: st.vpn_static_challenge.clone(),
                        message: String::new(),
                        challenge: None,
                        for_service: true,
                    });
                }
                if active && ui.small_button("Reconnect").clicked() {
                    crate::servicectl::request("reconnect");
                }
            });
            ui.label(RichText::new("Starts with Windows, keeps the VPN connected, and allows control of the sign-in screen and UAC prompts.").small().weak());
            if st.desktop.eq_ignore_ascii_case("winlogon") {
                ui.label(RichText::new("The sign-in / lock screen is showing right now.").small().color(ACCENT));
            }
        });
        ui.add_space(6.0);
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Access").strong());
            match &st.otp {
                Some(otp) => {
                    ui.horizontal(|ui| {
                        ui.label("One-time:");
                        ui.label(RichText::new(otp).monospace().size(18.0).strong().color(ACCENT));
                        if ui.small_button("Copy").clicked() {
                            self.copy(ui.ctx(), otp.clone());
                        }
                        if ui.small_button("New").clicked() {
                            crate::servicectl::request("new-otp");
                        }
                    });
                }
                None => {
                    ui.label(RichText::new("One-time password is off.").small().weak());
                }
            }
            // the service's password itself is not shared (admin-only settings): show it is set
            ui.horizontal(|ui| {
                ui.label("Password:");
                if st.permanent_password {
                    ui.label(RichText::new("\u{2022}".repeat(8)).monospace().size(16.0));
                } else {
                    ui.label(RichText::new("off").weak());
                }
                if ui.small_button("Change").on_hover_text("Opens Service settings (asks for administrator rights)").clicked() {
                    self.spawn_self("--service-config");
                }
            });
            if let Some(p) = st.direct_port {
                for a in self.local_ips.iter().filter(|a| a.ip.is_ipv4()) {
                    let t = if p == 5900 { a.ip.to_string() } else { format!("{}:{p}", a.ip) };
                    ui.label(RichText::new(format!("Direct: {t}")).small().monospace());
                }
            }
            ui.label(RichText::new(format!("Fingerprint: {}", crate::util::short_fingerprint(&st.fingerprint))).small().monospace().weak());
        });
        ui.add_space(6.0);
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(format!("Connected viewers ({})", st.viewers.len())).strong());
            for v in &st.viewers {
                ui.label(RichText::new(format!("{}{}{}", v.addr, if v.via_vpn { " [VPN]" } else { "" }, if v.native { " [PortlessVNC]" } else { "" })).monospace());
            }
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("Service settings...").on_hover_text("Asks for administrator rights").clicked() {
                self.spawn_self("--service-config");
            }
            let mine = env!("CARGO_PKG_VERSION");
            let outdated = st.version != mine;
            let label = if outdated { RichText::new(format!("Update service to {mine}")).strong().color(ACCENT) } else { RichText::new("Reinstall service") };
            if ui
                .button(label)
                .on_hover_text(format!("The service runs {}; this window is {mine}. Keeps the service's VPN login and settings. Asks for administrator rights.", st.version))
                .clicked()
            {
                self.spawn_self("--install-service");
                self.toast("Approve the administrator prompt to update the service");
            }
            if ui.button("Remove service...").on_hover_text("Stops and uninstalls the service, including its saved VPN login. Asks for administrator rights.").clicked() {
                self.spawn_self("--uninstall-service");
            }
        });
    }

    fn viewers_card(&mut self, ui: &mut egui::Ui) {
        let clients = self.core.server.client_list();
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(format!("Connected viewers ({})", clients.len())).strong());
            if clients.is_empty() {
                ui.label(RichText::new("Nobody is connected.").small().weak());
            }
            for c in clients {
                ui.horizontal(|ui| {
                    let tags = format!(
                        "{}{}",
                        if c.via_vpn { " [VPN]" } else { "" },
                        if c.native.load(std::sync::atomic::Ordering::Relaxed) { " [PortlessVNC]" } else { " [standard VNC]" }
                    );
                    ui.label(RichText::new(format!("{}{tags}", c.addr.ip())).monospace());
                    if c.native.load(std::sync::atomic::Ordering::Relaxed) && self.core.cfg.read().server.allow_file_transfer && ui.small_button("Send files...").clicked() {
                        if let Some(files) = rfd::FileDialog::new().pick_files() {
                            let peer: Arc<dyn crate::hub::Peer> = c.clone();
                            self.core.hub.send_paths(peer, files);
                        }
                    }
                    if ui.small_button("Disconnect").clicked() {
                        c.close();
                    }
                });
            }
        });
    }

    fn connect_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Connect to a remote computer");
        ui.add_space(4.0);
        let mut go = false;
        let suggestion = self.address_suggestion();
        let edit_id = egui::Id::new("connect-address");
        ui.horizontal(|ui| {
            // Tab accepts the grey completion (consumed before egui uses it to move focus)
            // (egui moves focus on Tab before we see it, so remember whether the
            // box had focus last frame and take the focus back)
            let had_focus = std::mem::replace(&mut self.addr_had_focus, ui.memory(|m| m.has_focus(edit_id)));
            if let (true, Some(s)) = (had_focus, suggestion.as_ref()) {
                if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Tab)) {
                    ui.memory_mut(|m| m.request_focus(edit_id));
                    self.address = s.clone();
                    if let Some(mut st) = egui::text_edit::TextEditState::load(ui.ctx(), edit_id) {
                        st.cursor.set_char_range(Some(egui::text::CCursorRange::one(egui::text::CCursor::new(self.address.chars().count()))));
                        st.store(ui.ctx(), edit_id);
                    }
                }
            }
            let r = ui.add(egui::TextEdit::singleline(&mut self.address).id(edit_id).lock_focus(suggestion.is_some()).hint_text("address, e.g. 10.8.0.6 or 192.168.1.20:5901").desired_width(ui.available_width() - 90.0).font(egui::TextStyle::Monospace));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                go = true;
            }
            // ghost text: the rest of the suggestion, drawn right after what was typed
            if let Some(s) = self.address_suggestion() {
                if r.has_focus() {
                    let font = egui::TextStyle::Monospace.resolve(ui.style());
                    let typed_w = ui.fonts(|f| f.layout_no_wrap(self.address.clone(), font.clone(), Color32::WHITE).size().x);
                    let mut rest: String = s.chars().skip(self.address.chars().count()).collect();
                    if s.ends_with('.') {
                        rest.push('x'); // network prefix: the last number is still to type
                    }
                    let pos = egui::pos2(r.rect.left() + 4.0 + typed_w, r.rect.center().y);
                    ui.painter().text(pos, egui::Align2::LEFT_CENTER, format!("{rest}   Tab"), font, ui.visuals().weak_text_color());
                }
            }
            if ui.add(egui::Button::new(RichText::new("Connect").strong()).min_size(egui::vec2(80.0, 0.0))).clicked() {
                go = true;
            }
        });
        if go {
            let a = self.address.clone();
            self.connect_to(&a, "", "");
        }
        ui.horizontal(|ui| {
            let mut c = self.core.cfg.write();
            let mut changed = false;
            ui.label("Quality:");
            egui::ComboBox::from_id_salt("defq").selected_text(c.viewer.quality.label()).show_ui(ui, |ui| {
                for q in QualityMode::ALL {
                    changed |= ui.selectable_value(&mut c.viewer.quality, q, q.label()).changed();
                }
            });
            ui.label("Audio:");
            egui::ComboBox::from_id_salt("defa").selected_text(c.viewer.audio.label()).show_ui(ui, |ui| {
                for a in AudioMode::PRESETS {
                    changed |= ui.selectable_value(&mut c.viewer.audio, a, a.label()).changed();
                }
            });
            drop(c);
            if changed {
                self.core.save_config();
            }
        });
        if let Some(ip) = self.core.vpn.vpn_ip() {
            ui.label(RichText::new(format!("Addresses in your VPN network (like {ip}) are reached through the tunnel automatically.")).small().weak());
        }
        ui.add_space(8.0);
        ui.columns(2, |cols| {
            // recent
            cols[0].label(RichText::new("Recent").strong());
            let recent = self.core.cfg.read().recent.clone();
            egui::ScrollArea::vertical().id_salt("recent").max_height(180.0).show(&mut cols[0], |ui| {
                if recent.is_empty() {
                    ui.label(RichText::new("No recent connections").small().weak());
                }
                for r in recent {
                    let resp = ui.selectable_label(self.address == r, RichText::new(&r).monospace());
                    if resp.clicked() {
                        self.address = r.clone();
                    }
                    if resp.double_clicked() {
                        self.connect_to(&r, "", "");
                    }
                }
            });
            // address book
            cols[1].label(RichText::new("Address book").strong());
            let book = self.core.cfg.read().address_book.clone();
            let mut remove = None;
            let mut connect = None;
            egui::ScrollArea::vertical().id_salt("book").max_height(150.0).show(&mut cols[1], |ui| {
                if book.is_empty() {
                    ui.label(RichText::new("Save addresses you use often").small().weak());
                }
                for (i, e) in book.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.link(&e.name).on_hover_text(&e.address).clicked() {
                            connect = Some(e.clone());
                        }
                        ui.label(RichText::new(&e.address).small().monospace().weak());
                        if ui.small_button("x").clicked() {
                            remove = Some(i);
                        }
                    });
                }
            });
            cols[1].horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.book_name).hint_text("name").desired_width(110.0));
                if ui.small_button("Save current address").clicked() && !self.address.trim().is_empty() {
                    let name = if self.book_name.trim().is_empty() { self.address.clone() } else { self.book_name.trim().to_string() };
                    self.core.cfg.write().address_book.push(BookEntry { name, address: self.address.trim().to_string(), ..Default::default() });
                    self.core.save_config();
                    self.book_name.clear();
                }
            });
            if let Some(i) = remove {
                self.core.cfg.write().address_book.remove(i);
                self.core.save_config();
            }
            if let Some(e) = connect {
                self.address = e.address.clone();
                self.connect_to(&e.address, &e.username, "");
            }
        });
        ui.add_space(8.0);
        self.transfers(ui);
    }

    /// Completion for the address box: a matching recent/address-book entry,
    /// else the VPN (then LAN) network prefix up to the last number.
    fn address_suggestion(&self) -> Option<String> {
        let typed = self.address.trim_start();
        if typed.is_empty() {
            return None;
        }
        let prefix_of = |ip: std::net::Ipv4Addr| {
            let o = ip.octets();
            format!("{}.{}.{}.", o[0], o[1], o[2])
        };
        let mut candidates: Vec<String> = Vec::new();
        // Once a dot is typed the user is probably entering a new address:
        // offer network prefixes (VPN first, then LAN) instead of recents.
        if !typed.contains('.') {
            let c = self.core.cfg.read();
            candidates.extend(c.recent.iter().cloned());
            candidates.extend(c.address_book.iter().map(|e| e.address.clone()));
        }
        if let Some(ip) = self.core.vpn.vpn_ip() {
            candidates.push(prefix_of(ip));
        }
        for a in &self.local_ips {
            if let std::net::IpAddr::V4(v4) = a.ip {
                candidates.push(prefix_of(v4));
            }
        }
        candidates.into_iter().find(|c| c.len() > typed.len() && c.starts_with(typed))
    }

    fn transfers(&mut self, ui: &mut egui::Ui) {
        let list = self.core.hub.transfers.lock().clone();
        if list.is_empty() {
            return;
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new("File transfers").strong());
            if ui.small_button("Clear finished").clicked() {
                self.core.hub.clear_finished();
            }
            if ui.small_button("Open download folder").clicked() {
                let d = self.core.cfg.read().download_dir.clone();
                let _ = std::fs::create_dir_all(&d);
                let _ = std::process::Command::new("explorer").arg(d).spawn();
            }
        });
        for t in list.iter().rev().take(8) {
            ui.horizontal(|ui| {
                let arrow = if t.direction == Direction::Upload { "\u{2191}" } else { "\u{2193}" };
                ui.label(format!("{arrow} {}", t.name));
                match &t.state {
                    XferState::Running => {
                        let f = if t.total > 0 { t.done as f32 / t.total as f32 } else { 0.0 };
                        let secs = t.started.elapsed().as_secs_f64().max(0.1);
                        ui.add(egui::ProgressBar::new(f).desired_width(160.0).text(format!("{} / {} ({}/s)", crate::util::human_bytes(t.done), crate::util::human_bytes(t.total), crate::util::human_bytes((t.done as f64 / secs) as u64))));
                        if ui.small_button("Cancel").clicked() {
                            self.core.hub.cancel_transfer(t.key);
                        }
                    }
                    XferState::Done => {
                        ui.colored_label(ACCENT, "done");
                    }
                    XferState::Failed(e) => {
                        ui.colored_label(Color32::from_rgb(0xd9, 0x48, 0x48), format!("failed: {e}"));
                    }
                }
            });
        }
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        let Some(mut draft) = self.settings.take() else { return };
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        let mut install_service = false;
        egui::Window::new("Settings").open(&mut open).resizable(true).default_width(460.0).show(ctx, |ui| {
            egui::ScrollArea::vertical().max_height(560.0).show(ui, |ui| {
                ui.heading("Hosting (this computer)");
                ui.checkbox(&mut draft.server.enabled, "Allow remote control of this computer");
                ui.horizontal(|ui| {
                    ui.label("Port:");
                    ui.add(egui::DragValue::new(&mut draft.server.port).range(1..=65535));
                });
                ui.checkbox(&mut draft.server.accept_via_vpn, "Accept connections through the VPN");
                ui.checkbox(&mut draft.server.vpn_expose_all, "Let VPN peers reach other services on this computer").on_hover_text("Off (recommended): on the VPN address only PortlessVNC answers.\nOn: TCP connections to any other port on the VPN address are passed to that port on this computer (e.g. Remote Desktop 3389, file shares 445). Those services then see the connection as coming from this computer itself, so only enable this if you trust everyone on the VPN.");
                if draft.server.vpn_expose_all {
                    ui.label(RichText::new("Everyone on the VPN can reach every TCP service on this computer.").small().color(Color32::from_rgb(0xd9, 0x8a, 0x20)));
                }
                ui.checkbox(&mut draft.server.listen_direct, "Accept direct (LAN / Internet) connections");
                ui.label("Authentication:");
                ui.radio_value(&mut draft.server.auth, AuthMode::VncPassword, "VNC password (standard, max 8 characters)");
                ui.radio_value(&mut draft.server.auth, AuthMode::SystemAccount, "Windows account (username + password, TLS only)");
                ui.radio_value(&mut draft.server.auth, AuthMode::None, "No authentication (not recommended)");
                if draft.server.auth == AuthMode::VncPassword {
                    let has_pw = !draft.vnc_password().is_empty();
                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        let hint = if has_pw { "set - type to change" } else { "not set" };
                        ui.add(egui::TextEdit::singleline(&mut self.settings_pw).password(true).desired_width(150.0).char_limit(8).hint_text(hint));
                        if has_pw {
                            ui.label(RichText::new("\u{2714} a password is set (leave empty to keep it)").small().color(ACCENT));
                        } else {
                            ui.colored_label(Color32::from_rgb(0xd9, 0x8a, 0x20), "no password yet");
                        }
                    });
                    ui.checkbox(&mut draft.server.allow_classic_auth, "Allow unencrypted classic VNC authentication (needed by RealVNC/UltraVNC/TightVNC viewers)");
                }
                let mons = crate::platform::capture::monitors();
                let label = |i: usize| -> String {
                    match mons.get(i) {
                        Some(m) => format!("{} {}x{}{}", m.name.trim_start_matches(r"\\.\"), m.width, m.height, if i == 0 { " (primary)" } else { "" }),
                        None => "All monitors".into(),
                    }
                };
                ui.horizontal(|ui| {
                    ui.label("Display:");
                    egui::ComboBox::from_id_salt("mon").selected_text(label(draft.server.monitor)).show_ui(ui, |ui| {
                        for i in 0..=mons.len() {
                            ui.selectable_value(&mut draft.server.monitor, i, label(i));
                        }
                    });
                });
                ui.horizontal(|ui| {
                    ui.label("Max frame rate:");
                    ui.add(egui::Slider::new(&mut draft.server.max_fps, 5..=60).suffix(" fps"));
                });
                ui.checkbox(&mut draft.server.share_audio, "Stream this computer's audio to PortlessVNC viewers");
                #[cfg(target_os = "linux")]
                ui.horizontal(|ui| {
                    ui.label("Audio capture source:");
                    ui.add(egui::TextEdit::singleline(&mut draft.server.audio_source).hint_text("default output's monitor").desired_width(260.0))
                        .on_hover_text("A PulseAudio/PipeWire source name, e.g. alsa_output.pci-0000_00_1f.3.analog-stereo.monitor (list them with: pactl list short sources). Empty = @DEFAULT_MONITOR@.");
                });
                ui.checkbox(&mut draft.server.share_clipboard, "Share clipboard with viewers");
                ui.checkbox(&mut draft.server.allow_file_transfer, "Allow file transfer");
                ui.separator();
                ui.heading("Viewing");
                ui.horizontal(|ui| {
                    ui.label("Default quality:");
                    egui::ComboBox::from_id_salt("q2").selected_text(draft.viewer.quality.label()).show_ui(ui, |ui| {
                        for q in QualityMode::ALL {
                            ui.selectable_value(&mut draft.viewer.quality, q, q.label());
                        }
                    });
                });
                ui.horizontal(|ui| {
                    ui.label("Default audio:");
                    egui::ComboBox::from_id_salt("a2").selected_text(draft.viewer.audio.label()).show_ui(ui, |ui| {
                        for a in AudioMode::PRESETS {
                            ui.selectable_value(&mut draft.viewer.audio, a, a.label());
                        }
                    });
                });
                ui.checkbox(&mut draft.viewer.scale_to_fit, "Scale remote screen to fit the window");
                ui.checkbox(&mut draft.viewer.share_clipboard, "Share clipboard with remote computers");
                ui.checkbox(&mut draft.viewer.capture_system_keys, "Send Windows key / Alt+Tab to the remote computer");
                ui.separator();
                ui.heading("Files");
                ui.horizontal(|ui| {
                    ui.label("Received files go to:");
                    ui.add(egui::TextEdit::singleline(&mut draft.download_dir).desired_width(220.0));
                    if ui.button("Browse...").clicked() {
                        if let Some(d) = rfd::FileDialog::new().set_directory(&draft.download_dir).pick_folder() {
                            draft.download_dir = d.to_string_lossy().into_owned();
                        }
                    }
                });
                ui.separator();
                ui.heading("Background service");
                if self.service_config {
                    ui.label(RichText::new("You are editing the service's own settings.").small().weak());
                } else if self.svc.is_some() {
                    ui.label(RichText::new("The PortlessVNC service is installed and running.").small());
                } else {
                    ui.label(RichText::new("Run PortlessVNC as a Windows service: it starts with the computer (before sign-in), keeps the VPN connected and can control the sign-in screen and UAC prompts. Needs administrator rights once; your current hosting settings and VPN profile are copied to it.").small().weak());
                    if ui.button("Install as a service...").clicked() {
                        install_service = true;
                    }
                }
                ui.separator();
                ui.heading("General");
                ui.checkbox(&mut draft.start_with_windows, "Start PortlessVNC when I sign in to Windows");
                ui.checkbox(&mut draft.vpn.connect_on_start, "Connect the selected VPN profile at startup");
                ui.checkbox(&mut draft.vpn.keep_connected, "Keep the VPN connected (reconnect automatically, resume after restart)");
                ui.checkbox(&mut draft.public_ip_lookup, "Look up my public IP (asks api.ipify.org)");
                ui.label(RichText::new(format!("Settings folder: {}", self.core.dir.display())).small().weak());
            });
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Save").strong()).clicked() {
                    save = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if install_service {
            self.spawn_self("--install-service");
            self.toast("Approve the administrator prompt to install the service");
        }
        if save {
            let new_password = !self.settings_pw.is_empty();
            if new_password {
                draft.set_vnc_password(&self.settings_pw);
                self.settings_pw.clear();
            }
            let autostart_changed = draft.start_with_windows != self.core.cfg.read().start_with_windows;
            #[cfg(windows)]
            crate::platform::keyhook::CAPTURE_SYSTEM_KEYS.store(draft.viewer.capture_system_keys, std::sync::atomic::Ordering::Relaxed);
            {
                // keep what the Settings window does not edit (and may have changed
                // while it was open): VPN profiles + saved logins, history, trust
                let cur = self.core.cfg.read();
                draft.vpn.resume = cur.vpn.resume;
                draft.vpn.profiles = cur.vpn.profiles.clone();
                draft.vpn.selected = cur.vpn.selected;
                draft.recent = cur.recent.clone();
                draft.address_book = cur.address_book.clone();
                draft.known_hosts = cur.known_hosts.clone();
                if !new_password {
                    draft.server.vnc_password = cur.server.vnc_password.clone();
                }
                draft.server.permanent_password = cur.server.permanent_password;
                draft.server.one_time_password = cur.server.one_time_password;
            }
            *self.core.cfg.write() = draft.clone();
            self.core.save_config();
            if autostart_changed {
                if let Err(e) = crate::platform::set_autostart(draft.start_with_windows) {
                    self.toast(format!("Autostart: {e}"));
                }
            }
            self.core.server.restart();
            self.toast("Settings saved");
        } else if open && !cancel {
            self.settings = Some(draft);
        }
    }

    /// Pop-out window with text shared between both sides.
    fn shared_text_window(&mut self, ctx: &egui::Context) {
        use std::sync::atomic::Ordering;
        let hub = self.core.hub.clone();
        if !hub.note_window.load(Ordering::Relaxed) {
            return;
        }
        let peers = self.core.server.client_list().iter().filter(|c| c.native.load(Ordering::Relaxed)).count()
            + self.core.sessions.lock().iter().filter(|s| s.native.load(Ordering::Relaxed) && !s.is_closed()).count()
            + self.svc.as_ref().map(|s| s.viewers.iter().filter(|v| v.native).count()).unwrap_or(0);
        let service_running = self.svc.is_some();
        // one window only: an ordinary floating panel
        if ctx.embed_viewports() {
            let mut open = true;
            let mut copied = None;
            egui::Window::new("Shared text").open(&mut open).default_size([420.0, 300.0]).show(ctx, |ui| {
                hub.note_mark_read();
                let mut text = hub.note_text();
                if ui.add(egui::TextEdit::multiline(&mut text).desired_width(f32::INFINITY).desired_rows(10).hint_text("Type or paste here - the other side sees it right away.").font(egui::TextStyle::Monospace)).changed() {
                    if service_running {
                        crate::servicectl::request_with("note-edit", text.as_bytes());
                    }
                    hub.note_local_edit(text.clone());
                }
                ui.horizontal(|ui| {
                    if ui.button("Copy all").clicked() {
                        copied = Some(text.clone());
                    }
                    if ui.button("Clear").clicked() {
                        if service_running {
                            crate::servicectl::request_with("note-edit", b"");
                        }
                        hub.note_local_edit(String::new());
                    }
                });
            });
            if !open {
                hub.note_window.store(false, Ordering::Relaxed);
            }
            if let Some(t) = copied {
                self.copy(ctx, t);
            }
            return;
        }
        let builder = egui::ViewportBuilder::default().with_title("Shared text - PortlessVNC").with_inner_size([460.0, 380.0]).with_min_inner_size([260.0, 180.0]);
        let mut copied = None;
        ctx.show_viewport_immediate(egui::ViewportId::from_hash_of("shared-text"), builder, |ctx, _| {
            if ctx.input(|i| i.viewport().close_requested()) {
                hub.note_window.store(false, Ordering::Relaxed);
                return;
            }
            hub.note_mark_read();
            egui::TopBottomPanel::bottom("st-bar").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Copy all").clicked() {
                        copied = Some(hub.note_text());
                    }
                    if ui.button("Clear").clicked() {
                        if service_running {
                            crate::servicectl::request_with("note-edit", b"");
                        }
                        hub.note_local_edit(String::new());
                    }
                    let who = match peers {
                        0 => "not connected to another PortlessVNC".to_string(),
                        1 => "shared with 1 computer".to_string(),
                        n => format!("shared with {n} computers"),
                    };
                    ui.label(RichText::new(who).small().weak());
                });
            });
            egui::CentralPanel::default().show(ctx, |ui| {
                let mut text = hub.note_text();
                let r = egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| ui.add_sized(ui.available_size(), egui::TextEdit::multiline(&mut text).hint_text("Type or paste here - the other side sees it right away.").font(egui::TextStyle::Monospace)))
                    .inner;
                if r.changed() {
                    // when the service hosts this computer, its viewers get the text from it
                    if service_running {
                        crate::servicectl::request_with("note-edit", text.as_bytes());
                    }
                    hub.note_local_edit(text);
                }
            });
        });
        if let Some(t) = copied {
            self.copy(ctx, t);
        }
    }

    fn vpn_prompt_window(&mut self, ctx: &egui::Context) {
        let Some(p) = self.vpn_prompt.as_mut() else { return };
        let mut submit = false;
        let mut cancel = false;
        egui::Window::new("VPN login").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
            if let Some((text, echo)) = &p.challenge {
                ui.label(text);
                let r = ui.add(egui::TextEdit::singleline(&mut p.otp).password(!echo));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    submit = true;
                }
            } else {
                egui::Grid::new("vpnlogin").num_columns(2).show(ui, |ui| {
                    ui.label("Username:");
                    ui.text_edit_singleline(&mut p.user);
                    ui.end_row();
                    ui.label("Password:");
                    let r = ui.add(egui::TextEdit::singleline(&mut p.pass).password(true));
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && p.static_challenge.is_none() {
                        submit = true;
                    }
                    ui.end_row();
                    if let Some((text, echo)) = &p.static_challenge {
                        ui.label(text);
                        let r = ui.add(egui::TextEdit::singleline(&mut p.otp).password(!echo));
                        if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            submit = true;
                        }
                        ui.end_row();
                    }
                });
                if p.for_service {
                    ui.checkbox(&mut p.remember, "Remember password for the service (encrypted, survives restarts)");
                } else if !self.service_config {
                    ui.checkbox(&mut p.remember, "Remember password (encrypted for your Windows account)");
                } else {
                    ui.label(RichText::new("Saved for the service (encrypted, readable only by SYSTEM and administrators).").small().weak());
                }
            }
            if !p.message.is_empty() && p.challenge.is_none() {
                ui.label(&p.message);
            }
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Connect").strong()).clicked() {
                    submit = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if submit {
            self.submit_vpn_prompt();
        } else if cancel {
            self.vpn_prompt = None;
        }
    }
}

impl App {
    /// One frame of the whole program (any renderer).
    pub fn frame(&mut self, ctx: &egui::Context) {
        if self.minimize_once {
            self.minimize_once = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
        ctx.request_repaint_after(Duration::from_millis(500));
        // another launch handed over to this window
        for msg in crate::instance::take() {
            if let Some(addr) = msg.strip_prefix("connect ") {
                self.connect_to(addr, "", "");
            }
        }
        // follow the background service: when it runs, it hosts and this window only views
        if self.svc_at.elapsed() > Duration::from_secs(1) {
            self.svc_at = Instant::now();
            self.svc = crate::servicectl::read_status();
            // shared text of the service's viewers
            if self.svc.is_some() {
                if let Some((v, text)) = crate::servicectl::read_note() {
                    self.core.hub.note_from_service(v, text);
                }
            }
            let running = self.svc.is_some() || self.service_config;
            if running != self.core.server.suppressed() {
                self.core.server.set_suppressed(running);
                self.core.server.restart();
                log::info!("{}", if running { "The PortlessVNC service is hosting this computer" } else { "The PortlessVNC service stopped; this window hosts again" });
            }
        }
        // remember that the VPN is up, so it resumes after a restart
        if self.core.vpn.status().state == VpnState::Connected && !self.core.cfg.read().vpn.resume {
            self.core.cfg.write().vpn.resume = true;
            self.core.save_config();
        }

        // one window only (software rendering): an open session fills it
        if ctx.embed_viewports() && !self.sessions.is_empty() {
            self.vpn_prompt_window(ctx);
            self.shared_text_window(ctx);
            let core = self.core.clone();
            let mut last = self.sessions.pop().unwrap();
            if last.show(ctx, &core) {
                self.sessions.push(last);
            }
            let live: Vec<u64> = self.sessions.iter().map(|s| s.session.id).collect();
            self.core.sessions.lock().retain(|s| live.contains(&s.id));
            return;
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                self.menu_bar(ui, ctx);
            });
        });
        if self.about_open {
            let mut open = true;
            egui::Window::new("About PortlessVNC").open(&mut open).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
                ui.label(RichText::new(format!("PortlessVNC {}", env!("CARGO_PKG_VERSION"))).strong().size(18.0).color(ACCENT));
                ui.label("VNC server + viewer with a built-in OpenVPN client:");
                ui.label("remote access over your own VPN, without port forwarding.");
                ui.add_space(4.0);
                ui.label(RichText::new(format!("Running from: {}", std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default())).small().weak());
                ui.label(RichText::new(format!("Settings: {}", self.core.dir.display())).small().weak());
            });
            self.about_open = open;
        }

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let last = crate::util::with_log(|l| l.back().map(|x| x.text.clone()));
                ui.label(RichText::new(last.unwrap_or_default()).small().weak());
                if let Some((t, at)) = &self.toast {
                    if at.elapsed() < Duration::from_secs(4) {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(RichText::new(t).small().color(ACCENT));
                        });
                    }
                }
            });
        });

        if self.show_log {
            egui::TopBottomPanel::bottom("log").resizable(true).default_height(160.0).show(ctx, |ui| {
                egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
                    crate::util::with_log(|l| {
                        for line in l.iter() {
                            let c = match line.level {
                                log::Level::Error => Color32::from_rgb(0xd9, 0x48, 0x48),
                                log::Level::Warn => Color32::from_rgb(0xd9, 0x8a, 0x20),
                                _ => ui.visuals().text_color(),
                            };
                            ui.label(RichText::new(&line.text).small().monospace().color(c));
                        }
                    });
                });
            });
        }

        let panel = egui::SidePanel::left("host").resizable(true).default_width(380.0).min_width(320.0);
        let host_ui = |me: &mut App, ui: &mut egui::Ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(6.0);
                ui.label(RichText::new(if me.service_config { "Background service settings" } else { "This computer" }).heading());
                ui.add_space(4.0);
                if let (false, Some(st)) = (me.service_config, me.svc.clone()) {
                    me.service_card(ui, &st);
                    return;
                }
                if me.service_config {
                    ui.label(RichText::new("These settings belong to the PortlessVNC service, which hosts this computer from startup. Changes apply when you save (the service restarts its host in a few seconds).").small().weak());

                    ui.add_space(4.0);
                }
                me.vpn_card(ui);
                ui.add_space(6.0);
                if !me.service_config {
                    me.direct_card(ui);
                    ui.add_space(6.0);
                }
                me.access_card(ui);
                ui.add_space(6.0);
                if !me.service_config {
                    me.viewers_card(ui);
                    ui.add_space(6.0);
                    ui.group(|ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new("Background service").strong());
                        ui.label(RichText::new("Start with Windows (before sign-in), keep the VPN connected and allow control of the sign-in screen and UAC prompts.").small().weak());
                        if ui.button("Install as a service...").on_hover_text("Asks for administrator rights once").clicked() {
                            me.spawn_self("--install-service");
                            me.toast("Approve the administrator prompt to install the service");
                        }
                    });
                } else if ui.button("Settings...").clicked() && me.settings.is_none() {
                    me.settings = Some(me.core.cfg.read().clone());
                }
            });
        };
        if self.host_only {
            egui::CentralPanel::default().show(ctx, |ui| host_ui(self, ui));
        } else {
            panel.show(ctx, |ui| host_ui(self, ui));
            egui::CentralPanel::default().show(ctx, |ui| self.connect_panel(ui));
        }

        self.settings_window(ctx);
        self.vpn_prompt_window(ctx);
        self.shared_text_window(ctx);

        // session windows
        let core = self.core.clone();
        self.sessions.retain_mut(|s| s.show(ctx, &core));
        let live: Vec<u64> = self.sessions.iter().map(|s| s.session.id).collect();
        self.core.sessions.lock().retain(|s| live.contains(&s.id));
    }

    /// The window is closing: end sessions and connections.
    pub fn shutdown(&mut self) {
        for s in &self.sessions {
            s.session.close();
        }
        self.core.vpn.disconnect();
        self.core.server.disconnect_all();
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.frame(ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.shutdown();
    }
}

/// No window could be opened: say so, instead of exiting silently.
pub fn show_startup_error(detail: &str) {
    eprintln!("Could not open a window: {detail}");
    #[cfg(windows)]
    unsafe {
        use windows::core::{w, PCWSTR};
        use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
        let text = format!("PortlessVNC could not open its window.\n\n{detail}\n\nTry starting it with --software-render, which needs no 3D graphics.\0");
        let wide: Vec<u16> = text.encode_utf16().collect();
        MessageBoxW(None, PCWSTR(wide.as_ptr()), w!("PortlessVNC"), MB_OK | MB_ICONERROR);
    }
}
