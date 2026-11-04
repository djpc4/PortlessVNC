//! Android client UI. The app opens to "My computers": tap one and it brings
//! up that computer's VPN (if any) and connects. "New connection" opens the
//! setup page, which is also each saved computer's own options page.

pub mod crash;
mod view;

use crate::app::Core;
use crate::config::{AudioMode, BookEntry, QualityMode, VpnProfile};
use crate::hub::{ClipCmd, Direction, XferState};
use crate::platform::java::{self, Event};
use crate::vpn::{ovpn::OvpnConfig, ConnectRequest, VpnState};
use base64::Engine as _;
use eframe::egui::{self, vec2, Color32, RichText};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use view::{Outcome, RemoteView};

/// Android API level (insets report the keyboard from 30 on).
fn android_api() -> i32 {
    static API: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    *API.get_or_init(|| {
        std::process::Command::new("getprop").arg("ro.build.version.sdk").output().ok().and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok()).unwrap_or(0)
    })
}

const ACCENT: Color32 = Color32::from_rgb(0x2f, 0x9e, 0x6b);
const ORIENTATIONS: [&str; 3] = ["Follow the phone", "Landscape (wide)", "Portrait (tall)"];

/// While a text field is being typed in, keep it on screen above the keyboard.
fn keep_visible(r: &egui::Response) {
    if r.has_focus() {
        r.scroll_to_me(Some(egui::Align::Center));
    }
}

fn b64() -> &'static base64::engine::GeneralPurpose {
    &base64::engine::general_purpose::STANDARD
}

fn decode_saved(b: &Option<String>) -> Option<String> {
    let raw = b64().decode(b.as_ref()?).ok()?;
    String::from_utf8(crate::platform::unprotect(&raw)?).ok()
}

fn encode_secret(s: &str) -> Option<String> {
    crate::platform::protect_for_config(s.as_bytes()).map(|b| b64().encode(b))
}

/// What the selected VPN profile needs (read from its .ovpn once).
struct ProfileInfo {
    needs_login: bool,
    static_challenge: Option<(String, bool)>,
    remote: String,
}

/// The setup page: a new / temporary connection, or a saved computer's options.
struct Form {
    /// index in the saved list when editing one
    edit: Option<usize>,
    nickname: String,
    address: String,
    password: String,
    remember_password: bool,
    vpn: Option<String>,
    audio: AudioMode,
    quality: QualityMode,
    touch_direct: bool,
    orientation: u8,
    confirm_delete: bool,
    confirm_remove_profile: bool,
}

impl Form {
    fn new(core: &Core, address: &str) -> Form {
        let c = core.cfg.read();
        let vpn = c.vpn.profiles.get(c.vpn.selected).map(|p| p.name.clone());
        Form {
            edit: None,
            nickname: String::new(),
            address: address.to_string(),
            password: String::new(),
            remember_password: true,
            vpn,
            audio: c.viewer.audio,
            quality: c.viewer.quality,
            touch_direct: c.viewer.touch_direct,
            orientation: c.viewer.orientation,
            confirm_delete: false,
            confirm_remove_profile: false,
        }
    }

    fn from_entry(core: &Core, i: usize, e: &BookEntry) -> Form {
        let c = core.cfg.read();
        Form {
            edit: Some(i),
            nickname: e.name.clone(),
            address: e.address.clone(),
            password: decode_saved(&e.password_protected).unwrap_or_default(),
            remember_password: true,
            vpn: e.vpn_profile.clone(),
            audio: e.audio.unwrap_or(c.viewer.audio),
            quality: e.quality.unwrap_or(c.viewer.quality),
            touch_direct: e.touch_direct.unwrap_or(c.viewer.touch_direct),
            orientation: e.orientation.unwrap_or(c.viewer.orientation),
            confirm_delete: false,
            confirm_remove_profile: false,
        }
    }

    fn target(&self) -> Target {
        Target {
            label: if self.nickname.trim().is_empty() { self.address.trim().to_string() } else { self.nickname.trim().to_string() },
            address: self.address.trim().to_string(),
            password: self.password.clone(),
            vpn: self.vpn.clone(),
            audio: self.audio,
            quality: self.quality,
            touch_direct: self.touch_direct,
            orientation: self.orientation,
        }
    }

    fn entry(&self) -> BookEntry {
        BookEntry {
            name: self.nickname.trim().to_string(),
            address: self.address.trim().to_string(),
            username: String::new(),
            password_protected: if self.remember_password && !self.password.is_empty() { encode_secret(&self.password) } else { None },
            vpn_profile: self.vpn.clone(),
            audio: Some(self.audio),
            quality: Some(self.quality),
            touch_direct: Some(self.touch_direct),
            orientation: Some(self.orientation),
        }
    }
}

/// Everything needed to open one connection.
#[derive(Clone)]
struct Target {
    label: String,
    address: String,
    password: String,
    vpn: Option<String>,
    audio: AudioMode,
    quality: QualityMode,
    touch_direct: bool,
    orientation: u8,
}

/// Waiting for the VPN before connecting.
struct Pending {
    target: Target,
    since: Instant,
}

enum Page {
    Home,
    Setup(Box<Form>),
    Settings,
}

pub struct MobileApp {
    core: Arc<Core>,
    view: Option<RemoteView>,
    page: Page,
    pending: Option<Pending>,
    // login of the selected VPN profile
    vpn_user: String,
    vpn_pass: String,
    vpn_otp: String,
    remember: bool,
    challenge: String,
    profile: Option<ProfileInfo>,
    keyboard_up: bool,
    /// the user closed the keyboard: keep it down until focus moves
    keyboard_dismissed: bool,
    /// keyboard events for the remote computer (taken before egui runs)
    remote_events: Vec<Event>,
    exported: HashSet<(u64, u32)>,
    /// system bars / cutout / keyboard (pixels: top, bottom, left, right, keyboard)
    insets: [i32; 5],
    insets_at: Instant,
    /// when the keyboard was last asked for (to notice the user closing it)
    keyboard_since: Instant,
    /// a closed session, dropped a few frames later (its textures may still be in flight)
    retired: Option<(RemoteView, u8)>,
    last_back: Instant,
    /// VPN profile -> its server's host (read from the .ovpn once)
    vpn_hosts: std::collections::HashMap<String, String>,
}

impl MobileApp {
    pub fn new(cc: &eframe::CreationContext<'_>, core: Arc<Core>) -> MobileApp {
        crate::util::set_repaint_ctx(cc.egui_ctx.clone());
        cc.egui_ctx.style_mut(|s| {
            s.spacing.interact_size = egui::vec2(48.0, 38.0);
            s.spacing.button_padding = egui::vec2(14.0, 9.0);
            s.spacing.item_spacing = egui::vec2(10.0, 10.0);
            for f in s.text_styles.values_mut() {
                f.size *= 1.2;
            }
        });
        core.hub.set_clipboard_backend(Box::new(|c| {
            if let ClipCmd::SetText(t) = c {
                java::set_clipboard(&t);
            }
        }));
        let mut app = MobileApp {
            core,
            view: None,
            page: Page::Home,
            pending: None,
            vpn_user: String::new(),
            vpn_pass: String::new(),
            vpn_otp: String::new(),
            remember: true,
            challenge: String::new(),
            profile: None,
            keyboard_up: false,
            keyboard_dismissed: false,
            remote_events: Vec::new(),
            exported: HashSet::new(),
            insets: [0; 5],
            insets_at: Instant::now() - Duration::from_secs(1),
            keyboard_since: Instant::now(),
            vpn_hosts: Default::default(),
            retired: None,
            last_back: Instant::now() - Duration::from_secs(1),
        };
        // start fresh: no VPN until a computer (or a VPN's Connect) is tapped
        app.load_profile();
        app
    }

    // ---- VPN profiles ---------------------------------------------------------

    /// The VPN server a profile connects to (for "address @ server").
    fn vpn_host(&mut self, name: &str) -> String {
        if let Some(h) = self.vpn_hosts.get(name) {
            return h.clone();
        }
        let path = self.core.cfg.read().vpn.profiles.iter().find(|p| p.name == name).map(|p| p.ovpn_path.clone());
        let host = path.and_then(|p| OvpnConfig::load(std::path::Path::new(&p)).ok()).and_then(|c| c.remotes.first().map(|r| r.host.clone())).unwrap_or_else(|| name.to_string());
        self.vpn_hosts.insert(name.to_string(), host.clone());
        host
    }

    fn profile_index(&self, name: &str) -> Option<usize> {
        self.core.cfg.read().vpn.profiles.iter().position(|p| p.name == name)
    }

    fn selected(&self) -> Option<(usize, VpnProfile)> {
        let c = self.core.cfg.read();
        c.vpn.profiles.get(c.vpn.selected).cloned().map(|p| (c.vpn.selected, p))
    }

    /// Make `name` the active VPN profile and fill in its saved login.
    fn select_profile(&mut self, name: &str) {
        if let Some(i) = self.profile_index(name) {
            if self.core.cfg.read().vpn.selected != i {
                self.core.cfg.write().vpn.selected = i;
                self.core.save_config();
            }
        }
        self.load_profile();
    }

    fn load_profile(&mut self) {
        self.profile = None;
        let Some((_, p)) = self.selected() else { return };
        let cfg = OvpnConfig::load(std::path::Path::new(&p.ovpn_path)).ok();
        self.vpn_user = p.username.clone();
        self.vpn_pass = decode_saved(&p.password_protected).unwrap_or_default();
        self.remember = p.password_protected.is_some() || self.vpn_pass.is_empty();
        self.profile = Some(ProfileInfo {
            needs_login: cfg.as_ref().map(|c| c.auth_user_pass && c.auth_file_creds.is_none()).unwrap_or(false),
            static_challenge: cfg.as_ref().and_then(|c| c.static_challenge.clone()),
            remote: cfg.as_ref().and_then(|c| c.remotes.first().map(|r| format!("{}:{} {:?}", r.host, r.port, r.proto))).unwrap_or_else(|| "profile cannot be read".into()),
        });
    }

    fn import_profile(&mut self, name: &str, data: &[u8]) {
        let dir = self.core.dir.join("profiles");
        let _ = std::fs::create_dir_all(&dir);
        let base = crate::util::sanitize_rel_path(name).and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned())).unwrap_or_else(|| "VPN".into());
        let path = dir.join(format!("{base}.ovpn"));
        if let Err(e) = std::fs::write(&path, data) {
            java::toast(&format!("Could not save the profile: {e}"));
            return;
        }
        match OvpnConfig::load(&path) {
            Ok(cfg) => {
                let path_s = path.to_string_lossy().into_owned();
                {
                    let mut c = self.core.cfg.write();
                    c.vpn.profiles.retain(|p| p.ovpn_path != path_s);
                    c.vpn.profiles.push(VpnProfile { name: base.clone(), ovpn_path: path_s, username: cfg.auth_file_creds.clone().map(|c| c.0).unwrap_or_default(), password_protected: None });
                    c.vpn.selected = c.vpn.profiles.len() - 1;
                }
                self.core.save_config();
                self.load_profile();
                self.vpn_hosts.remove(&base);
                if let Page::Setup(f) = &mut self.page {
                    f.vpn = Some(base.clone());
                }
                java::toast(&format!("Imported VPN profile '{base}'"));
            }
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                log::warn!("import of '{name}' failed: {e:#}");
                java::toast(&format!("Not a usable .ovpn profile: {e:#}"));
            }
        }
    }

    /// Connect the selected profile with the login typed / saved for it.
    /// False when a password is still needed.
    fn vpn_connect(&mut self) -> bool {
        let Some((index, prof)) = self.selected() else {
            java::toast("Import an .ovpn profile first");
            return false;
        };
        let cfg = match OvpnConfig::load(std::path::Path::new(&prof.ovpn_path)) {
            Ok(c) => c,
            Err(e) => {
                java::toast(&format!("Profile error: {e:#}"));
                return false;
            }
        };
        let (user, pass) = match (&cfg.auth_file_creds, cfg.auth_user_pass) {
            (Some((u, p)), _) => (Some(u.clone()), Some(p.clone())),
            (None, true) => {
                if self.vpn_pass.is_empty() {
                    return false;
                }
                {
                    let mut c = self.core.cfg.write();
                    if let Some(p) = c.vpn.profiles.get_mut(index) {
                        p.username = self.vpn_user.trim().to_string();
                        p.password_protected = if self.remember { encode_secret(&self.vpn_pass) } else { None };
                    }
                }
                let pass = match &cfg.static_challenge {
                    Some(_) => format!("SCRV1:{}:{}", b64().encode(&self.vpn_pass), b64().encode(std::mem::take(&mut self.vpn_otp))),
                    None => self.vpn_pass.clone(),
                };
                (Some(self.vpn_user.trim().to_string()), Some(pass))
            }
            (None, false) => (None, None),
        };
        self.core.cfg.write().vpn.resume = true;
        self.core.save_config();
        self.core.vpn.connect(ConnectRequest { profile_name: prof.name.clone(), config: cfg, username: user, password: pass });
        true
    }

    fn vpn_disconnect(&mut self) {
        self.core.vpn.disconnect();
        self.core.cfg.write().vpn.resume = false;
        self.core.save_config();
    }

    fn vpn_up_with(&self, name: &str) -> bool {
        let st = self.core.vpn.status();
        matches!(st.state, VpnState::Connected) && st.profile == name && self.core.vpn.vpn_ip().is_some()
    }

    // ---- connecting -------------------------------------------------------------

    /// Bring up the computer's VPN if it has one, then connect.
    fn start(&mut self, t: Target) {
        if crate::viewer::parse_address(&t.address).is_none() {
            java::toast("Enter an address like 10.8.0.6 or 192.168.1.20:5901");
            return;
        }
        let Some(name) = t.vpn.clone() else {
            self.open_session(t);
            return;
        };
        if self.vpn_up_with(&name) {
            self.open_session(t);
            return;
        }
        if self.profile_index(&name).is_none() {
            java::toast(&format!("The VPN profile '{name}' is gone - pick another in this computer's options"));
            return;
        }
        let busy = !matches!(self.core.vpn.status().state, VpnState::Disconnected | VpnState::Failed(_) | VpnState::AuthFailed(_));
        if busy && self.core.vpn.status().profile != name {
            self.core.vpn.disconnect();
        }
        self.select_profile(&name);
        if !busy || self.core.vpn.status().profile != name {
            if !self.vpn_connect() {
                java::toast("Enter the VPN password for this profile");
                return;
            }
        }
        self.pending = Some(Pending { target: t, since: Instant::now() });
    }

    fn open_session(&mut self, t: Target) {
        self.pending = None;
        let s = crate::viewer::Session::start_with(self.core.clone(), &t.address, "", &t.password, t.quality, t.audio);
        self.core.sessions.lock().push(s.clone());
        self.view = Some(RemoteView::new(s, t.touch_direct, t.orientation));
        java::set_viewing(true);
    }

    fn check_pending(&mut self, ctx: &egui::Context) {
        let Some(p) = &self.pending else { return };
        let name = p.target.vpn.clone().unwrap_or_default();
        let st = self.core.vpn.status();
        if self.vpn_up_with(&name) {
            let t = self.pending.take().unwrap().target;
            self.open_session(t);
            return;
        }
        let failed = match &st.state {
            VpnState::Failed(m) => Some(format!("VPN failed: {m}")),
            VpnState::AuthFailed(m) => Some(format!("VPN login rejected: {m}")),
            _ if p.since.elapsed() > Duration::from_secs(45) => Some("The VPN did not connect in time".to_string()),
            _ => None,
        };
        if let Some(m) = failed {
            java::toast(&m);
            self.pending = None;
            return;
        }
        let label = p.target.label.clone();
        let mut cancel = false;
        view::dialog(ctx, &format!("Connecting to {label}"), |ui| {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(match &st.state {
                    VpnState::Connecting(m) | VpnState::Reconnecting(m) => format!("VPN: {m}"),
                    VpnState::Challenge { text, .. } => format!("VPN asks: {text}"),
                    _ => "Starting the VPN...".to_string(),
                });
            });
            if let VpnState::Challenge { echo, .. } = &st.state {
                ui.add(egui::TextEdit::singleline(&mut self.challenge).password(!*echo).hint_text("Response").desired_width(f32::INFINITY));
                if ui.button("Send").clicked() {
                    self.core.vpn.answer_challenge(&std::mem::take(&mut self.challenge));
                }
            }
            if ui.button("Cancel").clicked() {
                cancel = true;
            }
        });
        if cancel {
            self.pending = None;
        }
        ctx.request_repaint_after(Duration::from_millis(200));
    }

    /// Received files go to the phone's Downloads/PortlessVNC.
    fn export_downloads(&mut self) {
        let dir = self.core.hub.download_dir.read().clone();
        let done: Vec<(u64, u32, String)> = self
            .core
            .hub
            .transfers
            .lock()
            .iter()
            .filter(|t| matches!(t.direction, Direction::Download) && t.state == XferState::Done && !self.exported.contains(&t.key))
            .map(|t| (t.key.0, t.key.1, t.name.clone()))
            .collect();
        for (a, b, name) in done {
            self.exported.insert((a, b));
            let path = dir.join(&name);
            if path.is_file() {
                let file = std::path::Path::new(&name).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or(name.clone());
                match java::save_to_downloads(&path, &file) {
                    Some(at) => java::toast(&format!("Saved {at}")),
                    None => java::toast(&format!("Received {file} (could not copy it to Downloads)")),
                }
            }
        }
    }

    // ---- pages --------------------------------------------------------------------

    fn card(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
        egui::Frame::group(ui.style()).rounding(10.0).inner_margin(12.0).show(ui, |ui| {
            ui.set_width(ui.available_width());
            if !title.is_empty() {
                ui.label(RichText::new(title).strong().color(ACCENT));
            }
            add(ui);
        });
    }

    fn page_frame(ctx: &egui::Context, add: impl FnOnce(&mut egui::Ui)) {
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add_space(6.0);
                add(ui);
                ui.add_space(40.0);
            });
        });
    }

    /// Heading of a group on the home page: the VPN, its state and this
    /// phone's address on it (for firewall rules), or "Same network".
    fn group_header(&mut self, ui: &mut egui::Ui, vpn: Option<&str>) {
        let Some(name) = vpn else {
            ui.label(RichText::new("SAME NETWORK").strong().color(ACCENT));
            return;
        };
        let st = self.core.vpn.status();
        let mine = st.profile == name;
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("VPN  {name}")).strong().color(ACCENT));
            match (&st.state, self.core.vpn.vpn_ip()) {
                (VpnState::Connected, Some(ip)) if mine => {
                    ui.label(RichText::new(ip.to_string()).monospace().strong());
                    if ui.small_button("Disconnect").clicked() {
                        self.vpn_disconnect();
                    }
                }
                (VpnState::Connecting(_) | VpnState::Reconnecting(_), _) if mine => {
                    ui.spinner();
                }
                (VpnState::AuthFailed(_), _) if mine => {
                    ui.colored_label(Color32::from_rgb(0xe0, 0x60, 0x50), "login rejected");
                }
                (VpnState::Failed(_), _) if mine => {
                    ui.colored_label(Color32::from_rgb(0xe0, 0x60, 0x50), "failed");
                }
                _ => {
                    ui.label(RichText::new("off").weak());
                    if ui.small_button("Connect").clicked() {
                        if matches!(st.state, VpnState::Connected | VpnState::Connecting(_) | VpnState::Reconnecting(_)) {
                            self.core.vpn.disconnect();
                        }
                        self.select_profile(name);
                        if !self.vpn_connect() {
                            java::toast("Enter its VPN password once: Edit a computer of this VPN (or New connection)");
                        }
                    }
                }
            }
        });
    }

    fn home(&mut self, ctx: &egui::Context) {
        let book = self.core.cfg.read().address_book.clone();
        let recent: Vec<String> = self.core.cfg.read().recent.iter().filter(|a| !book.iter().any(|e| e.address == **a)).take(5).cloned().collect();
        let mut connect = None;
        let mut edit = None;
        let mut new_with = None;
        let mut settings = false;
        Self::page_frame(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("PortlessVNC").size(26.0).strong().color(ACCENT));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Settings").clicked() {
                        settings = true;
                    }
                });
            });
            ui.add_space(4.0);
            if book.is_empty() {
                ui.label(RichText::new("No computers saved yet. Tap New connection, set it up, then Save to my computers.").weak());
            }
            // one group per VPN (its computers under it), then the ones on the same network
            let profiles: Vec<String> = self.core.cfg.read().vpn.profiles.iter().map(|p| p.name.clone()).collect();
            let mut groups: Vec<Option<String>> = profiles.iter().cloned().map(Some).collect();
            groups.push(None);
            for g in groups {
                let members: Vec<usize> = book.iter().enumerate().filter(|(_, e)| e.vpn_profile.as_ref().filter(|v| profiles.contains(v)) == g.as_ref()).map(|(i, _)| i).collect();
                if members.is_empty() {
                    if let Some(name) = g.as_deref() {
                        ui.add_space(6.0);
                        self.group_header(ui, Some(name));
                        ui.label(RichText::new("No computers on this VPN yet.").small().weak());
                    }
                    continue;
                }
                // a VPN shared by several computers is a group; a computer alone on
                // its VPN is a card of its own that names the VPN
                let alone = g.is_some() && members.len() == 1;
                ui.add_space(6.0);
                if !alone {
                    self.group_header(ui, g.as_deref());
                }
                for i in members {
                    let e = &book[i];
                    if alone {
                        let name = g.as_deref().unwrap_or_default();
                        let st = self.core.vpn.status();
                        let state = match (&st.state, self.core.vpn.vpn_ip()) {
                            (VpnState::Connected, Some(ip)) if st.profile == name => format!("VPN {name} - this phone {ip}"),
                            (VpnState::Connecting(_) | VpnState::Reconnecting(_), _) if st.profile == name => format!("VPN {name} - connecting"),
                            _ => format!("VPN {name}"),
                        };
                        ui.label(RichText::new(state).small().color(ACCENT));
                    }
                    let w = ui.available_width();
                    let (rect, resp) = ui.allocate_exact_size(vec2(w, 66.0), egui::Sense::click());
                    let fill = if resp.is_pointer_button_down_on() { Color32::from_gray(60) } else { ui.visuals().faint_bg_color };
                    ui.painter().rect_filled(rect, 10.0, fill);
                    let title = if e.name.is_empty() { e.address.clone() } else { e.name.clone() };
                    ui.painter().text(rect.left_top() + vec2(14.0, 10.0), egui::Align2::LEFT_TOP, title, egui::FontId::proportional(21.0), ui.visuals().strong_text_color());
                    let desc = match g.as_deref() {
                        Some(v) => format!("{} @ {}", e.address, self.vpn_host(v)),
                        None => e.address.clone(),
                    };
                    ui.painter().text(rect.left_top() + vec2(14.0, 40.0), egui::Align2::LEFT_TOP, desc, egui::FontId::proportional(14.0), ui.visuals().weak_text_color());
                    let edit_rect = egui::Rect::from_min_size(egui::pos2(rect.right() - 90.0, rect.top() + 13.0), vec2(80.0, 40.0));
                    if ui.put(edit_rect, egui::Button::new("Edit")).clicked() {
                        edit = Some(i);
                    } else if resp.clicked() {
                        connect = Some(i);
                    }
                }
            }
            ui.add_space(10.0);
            if ui.add(egui::Button::new(RichText::new("+  New connection").size(19.0).strong()).min_size(vec2(ui.available_width(), 52.0))).clicked() {
                new_with = Some(String::new());
            }
            if !recent.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("Recent (not saved)").small().weak());
                ui.horizontal_wrapped(|ui| {
                    for a in &recent {
                        if ui.button(a.as_str()).clicked() {
                            new_with = Some(a.clone());
                        }
                    }
                });
            }
        });
        if settings {
            self.page = Page::Settings;
        }
        if let Some(a) = new_with {
            self.page = Page::Setup(Box::new(Form::new(&self.core, &a)));
        }
        if let Some(i) = edit {
            self.page = Page::Setup(Box::new(Form::from_entry(&self.core, i, &book[i])));
        }
        if let Some(i) = connect {
            let f = Form::from_entry(&self.core, i, &book[i]);
            let t = f.target();
            // no saved VPN password yet: ask on the options page
            if let Some(name) = &t.vpn {
                if !self.vpn_up_with(name) {
                    self.select_profile(name);
                    if self.profile.as_ref().map(|p| p.needs_login).unwrap_or(false) && self.vpn_pass.is_empty() {
                        java::toast("Enter the VPN password once, then Connect");
                        self.page = Page::Setup(Box::new(f));
                        return;
                    }
                }
            }
            self.start(t);
        }
    }

    fn setup(&mut self, ctx: &egui::Context) {
        let Page::Setup(mut f) = std::mem::replace(&mut self.page, Page::Home) else { return };
        let mut stay = true;
        let mut go = false;
        let names: Vec<String> = self.core.cfg.read().vpn.profiles.iter().map(|p| p.name.clone()).collect();
        Self::page_frame(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("<  Back").clicked() {
                    stay = false;
                }
                let title = match f.edit {
                    Some(_) => format!("{}", if f.nickname.is_empty() { &f.address } else { &f.nickname }),
                    None => "New connection".to_string(),
                };
                ui.label(RichText::new(title).size(22.0).strong());
            });
            ui.add_space(4.0);

            Self::card(ui, "COMPUTER", |ui| {
                keep_visible(&ui.add(egui::TextEdit::singleline(&mut f.address).hint_text("Address, e.g. 10.8.0.6").desired_width(f32::INFINITY)));
                keep_visible(&ui.add(egui::TextEdit::singleline(&mut f.password).password(true).hint_text("Password or one-time password (optional)").desired_width(f32::INFINITY)));
                ui.checkbox(&mut f.remember_password, "Remember this password (saved with the computer)");
            });
            ui.add_space(8.0);

            Self::card(ui, "VPN", |ui| {
                let label = f.vpn.clone().unwrap_or_else(|| "None - same network".into());
                let before = f.vpn.clone();
                ui.horizontal_wrapped(|ui| {
                    egui::ComboBox::from_id_salt("form-vpn").selected_text(label).show_ui(ui, |ui| {
                        ui.selectable_value(&mut f.vpn, None, "None - same network");
                        for n in &names {
                            ui.selectable_value(&mut f.vpn, Some(n.clone()), n);
                        }
                    });
                    if ui.button("Import .ovpn").clicked() {
                        java::pick_file();
                    }
                });
                if f.vpn != before {
                    if let Some(n) = f.vpn.clone() {
                        self.select_profile(&n);
                    }
                }
                let Some(name) = f.vpn.clone() else {
                    ui.label(RichText::new("Connects directly (home or office network).").small().weak());
                    return;
                };
                if self.core.cfg.read().vpn.profiles.get(self.core.cfg.read().vpn.selected).map(|p| p.name != name).unwrap_or(true) {
                    self.select_profile(&name);
                }
                if let Some(p) = &self.profile {
                    ui.label(RichText::new(&p.remote).small().weak());
                }
                let st = self.core.vpn.status();
                let up = self.vpn_up_with(&name);
                if up {
                    if let Some(ip) = self.core.vpn.vpn_ip() {
                        ui.label(RichText::new("This phone's VPN address").small());
                        ui.label(RichText::new(ip.to_string()).size(26.0).monospace().strong());
                    }
                } else if let VpnState::AuthFailed(m) = &st.state {
                    ui.colored_label(Color32::from_rgb(0xe0, 0x60, 0x50), format!("Login rejected: {m}"));
                }
                let (needs_login, challenge) = self.profile.as_ref().map(|p| (p.needs_login, p.static_challenge.clone())).unwrap_or((false, None));
                let busy = matches!(st.state, VpnState::Connected | VpnState::Connecting(_) | VpnState::Reconnecting(_)) && st.profile == name;
                if needs_login {
                    keep_visible(&ui.add_enabled(!busy, egui::TextEdit::singleline(&mut self.vpn_user).hint_text("VPN username").desired_width(f32::INFINITY)));
                    keep_visible(&ui.add_enabled(!busy, egui::TextEdit::singleline(&mut self.vpn_pass).password(true).hint_text("VPN password").desired_width(f32::INFINITY)));
                    if let Some((text, echo)) = &challenge {
                        keep_visible(&ui.add_enabled(!busy, egui::TextEdit::singleline(&mut self.vpn_otp).password(!*echo).hint_text(text.as_str()).desired_width(f32::INFINITY)));
                    }
                    ui.add_enabled(!busy, egui::Checkbox::new(&mut self.remember, "Remember the VPN password"));
                }
                ui.horizontal_wrapped(|ui| {
                    if busy {
                        if ui.button("Disconnect VPN").clicked() {
                            self.vpn_disconnect();
                        }
                    } else if ui.button("Connect VPN only").clicked() && !self.vpn_connect() {
                        java::toast("Enter the VPN password");
                    }
                    if f.confirm_remove_profile {
                        if ui.button(RichText::new("Remove profile").color(Color32::from_rgb(0xf0, 0x70, 0x60))).clicked() {
                            if busy {
                                self.vpn_disconnect();
                            }
                            let mut c = self.core.cfg.write();
                            if let Some(i) = c.vpn.profiles.iter().position(|p| p.name == name) {
                                let p = c.vpn.profiles.remove(i);
                                if p.ovpn_path.starts_with(&*self.core.dir.to_string_lossy()) {
                                    let _ = std::fs::remove_file(&p.ovpn_path);
                                }
                            }
                            c.vpn.selected = 0;
                            drop(c);
                            self.core.save_config();
                            self.load_profile();
                            f.vpn = None;
                            f.confirm_remove_profile = false;
                        }
                        if ui.button("Keep").clicked() {
                            f.confirm_remove_profile = false;
                        }
                    } else if ui.small_button("Remove profile...").clicked() {
                        f.confirm_remove_profile = true;
                    }
                });
            });
            ui.add_space(8.0);

            Self::card(ui, "SETTINGS FOR THIS COMPUTER", |ui| {
                ui.label("Sound (uses data):");
                egui::ComboBox::from_id_salt("form-audio").selected_text(f.audio.label()).show_ui(ui, |ui| {
                    for m in AudioMode::PRESETS {
                        ui.selectable_value(&mut f.audio, m, m.label());
                    }
                });
                ui.label("Picture quality:");
                egui::ComboBox::from_id_salt("form-quality").selected_text(f.quality.label()).show_ui(ui, |ui| {
                    for m in QualityMode::ALL {
                        ui.selectable_value(&mut f.quality, m, m.label());
                    }
                });
                ui.label("Touch:");
                ui.radio_value(&mut f.touch_direct, false, "Touchpad - drag moves the pointer");
                ui.radio_value(&mut f.touch_direct, true, "Direct - tap where you click");
                ui.label("Screen:");
                egui::ComboBox::from_id_salt("form-orient").selected_text(ORIENTATIONS[f.orientation.min(2) as usize]).show_ui(ui, |ui| {
                    for (i, l) in ORIENTATIONS.iter().enumerate() {
                        ui.selectable_value(&mut f.orientation, i as u8, *l);
                    }
                });
            });
            ui.add_space(8.0);

            Self::card(ui, if f.edit.is_some() { "SAVED COMPUTER" } else { "SAVE TO MY COMPUTERS" }, |ui| {
                keep_visible(&ui.add(egui::TextEdit::singleline(&mut f.nickname).hint_text("Nickname, e.g. Office PC").desired_width(f32::INFINITY)));
                ui.horizontal_wrapped(|ui| {
                    let label = if f.edit.is_some() { "Save changes" } else { "Save to my computers" };
                    if ui.button(RichText::new(label).strong()).clicked() {
                        if f.address.trim().is_empty() {
                            java::toast("Enter the computer's address first");
                        } else {
                            let e = f.entry();
                            let mut c = self.core.cfg.write();
                            match f.edit {
                                Some(i) if i < c.address_book.len() => c.address_book[i] = e,
                                _ => {
                                    c.address_book.push(e);
                                    f.edit = Some(c.address_book.len() - 1);
                                }
                            }
                            drop(c);
                            self.core.save_config();
                            java::toast("Saved");
                        }
                    }
                    if let Some(i) = f.edit {
                        if f.confirm_delete {
                            if ui.button(RichText::new("Delete it").color(Color32::from_rgb(0xf0, 0x70, 0x60))).clicked() {
                                let mut c = self.core.cfg.write();
                                if i < c.address_book.len() {
                                    c.address_book.remove(i);
                                }
                                drop(c);
                                self.core.save_config();
                                stay = false;
                            }
                            if ui.button("Keep").clicked() {
                                f.confirm_delete = false;
                            }
                        } else if ui.button("Delete...").clicked() {
                            f.confirm_delete = true;
                        }
                    }
                });
            });
            ui.add_space(12.0);
            if ui.add(egui::Button::new(RichText::new("Connect").size(20.0).strong()).fill(ACCENT).min_size(vec2(ui.available_width(), 54.0))).clicked() {
                go = true;
            }
        });
        if go {
            let t = f.target();
            self.page = Page::Setup(f);
            self.start(t);
            return;
        }
        if stay {
            self.page = Page::Setup(f);
        }
    }

    fn settings(&mut self, ctx: &egui::Context) {
        let mut back = false;
        Self::page_frame(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("<  Back").clicked() {
                    back = true;
                }
                ui.label(RichText::new("Settings").size(22.0).strong());
            });
            Self::card(ui, "DEFAULTS FOR NEW CONNECTIONS", |ui| {
                let mut c = self.core.cfg.read().viewer.clone();
                let before = (c.audio, c.quality, c.touch_direct, c.orientation, c.share_clipboard);
                ui.label("Sound (uses data):");
                egui::ComboBox::from_id_salt("set-audio").selected_text(c.audio.label()).show_ui(ui, |ui| {
                    for m in AudioMode::PRESETS {
                        ui.selectable_value(&mut c.audio, m, m.label());
                    }
                });
                ui.label("Picture quality:");
                egui::ComboBox::from_id_salt("set-quality").selected_text(c.quality.label()).show_ui(ui, |ui| {
                    for m in QualityMode::ALL {
                        ui.selectable_value(&mut c.quality, m, m.label());
                    }
                });
                ui.label("Touch:");
                ui.radio_value(&mut c.touch_direct, false, "Touchpad - drag moves the pointer");
                ui.radio_value(&mut c.touch_direct, true, "Direct - tap where you click");
                ui.label("Screen:");
                egui::ComboBox::from_id_salt("set-orient").selected_text(ORIENTATIONS[c.orientation.min(2) as usize]).show_ui(ui, |ui| {
                    for (i, l) in ORIENTATIONS.iter().enumerate() {
                        ui.selectable_value(&mut c.orientation, i as u8, *l);
                    }
                });
                ui.checkbox(&mut c.share_clipboard, "Share the clipboard (text)");
                if (c.audio, c.quality, c.touch_direct, c.orientation, c.share_clipboard) != before {
                    self.core.cfg.write().viewer = c;
                    self.core.save_config();
                }
            });
            ui.add_space(8.0);
            Self::card(ui, "VPN", |ui| {
                ui.label(RichText::new("VPNs connect when you tap one of their computers (or Connect on the VPN). Profiles are added and logged in from a computer's options (Import .ovpn).").small().weak());
            });
            ui.add_space(8.0);
            Self::card(ui, "HELP", |ui| {
                ui.label(RichText::new("In a session, pull down the tab at the top: Rotate, Mouse / Keyboard / View, Mute and More. Gestures: pinch to zoom, two fingers to scroll, long-press or two-finger tap to right-click, three-finger tap for the keyboard. Received files go to Downloads/PortlessVNC.").small());
                ui.label(RichText::new(format!("PortlessVNC {}", env!("CARGO_PKG_VERSION"))).small().weak());
            });
        });
        if back {
            self.page = Page::Home;
        }
    }

    // ---- insets / keyboard -------------------------------------------------------

    /// Keep the UI clear of the status/navigation bars, the camera cutout and the keyboard.
    fn inset_panels(&mut self, ctx: &egui::Context) {
        if self.insets_at.elapsed() > Duration::from_millis(250) {
            self.insets_at = Instant::now();
            self.insets = java::insets();
        }
        let ppp = ctx.pixels_per_point();
        let [top, bottom, left, right, kb] = self.insets.map(|v| v.max(0) as f32 / ppp);
        let bottom = bottom.max(kb);
        let none = egui::Frame::none();
        for (id, h, is_top) in [("inset-top", top, true), ("inset-bottom", bottom, false)] {
            if h > 0.5 {
                let p = if is_top { egui::TopBottomPanel::top(id) } else { egui::TopBottomPanel::bottom(id) };
                p.exact_height(h).frame(none).show_separator_line(false).resizable(false).show(ctx, |_| {});
            }
        }
        for (id, w, is_left) in [("inset-left", left, true), ("inset-right", right, false)] {
            if w > 0.5 {
                let p = if is_left { egui::SidePanel::left(id) } else { egui::SidePanel::right(id) };
                p.exact_width(w).frame(none).show_separator_line(false).resizable(false).show(ctx, |_| {});
            }
        }
    }

    fn wants_remote_keys(&self, ctx: &egui::Context) -> bool {
        !ctx.wants_keyboard_input() && self.view.as_ref().map(|v| v.keyboard_on() && v.connected()).unwrap_or(false)
    }

    fn update_keyboard(&mut self, ctx: &egui::Context) {
        let egui_wants = ctx.wants_keyboard_input();
        if !egui_wants {
            self.keyboard_dismissed = false;
        }
        let want = (egui_wants && !self.keyboard_dismissed) || self.view.as_ref().map(|v| v.keyboard_on() && v.connected()).unwrap_or(false);
        if want != self.keyboard_up {
            self.keyboard_up = want;
            self.keyboard_since = Instant::now();
            java::show_keyboard(want);
        } else if want && self.insets[4] == 0 && self.keyboard_since.elapsed() > Duration::from_millis(1500) && android_api() >= 30 {
            // closed with the keyboard's own button: follow it
            self.keyboard_up = false;
            self.keyboard_dismissed = true;
            if let Some(v) = self.view.as_mut() {
                v.set_keyboard(false);
            }
        } else if want && self.insets[4] > 0 {
            self.keyboard_since = Instant::now();
        }
    }
}

impl eframe::App for MobileApp {
    /// Events from the Java side: typing goes to the focused text field, or
    /// to the remote computer while its keyboard is open.
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        let to_remote = self.wants_remote_keys(ctx);
        for ev in java::take_events() {
            match ev {
                Event::Text(t) if !to_remote => raw.events.push(egui::Event::Text(t)),
                Event::Key { code, down, .. } if !to_remote => {
                    let key = match code {
                        67 => egui::Key::Backspace,
                        66 | 160 => egui::Key::Enter,
                        112 => egui::Key::Delete,
                        21 => egui::Key::ArrowLeft,
                        22 => egui::Key::ArrowRight,
                        _ => continue,
                    };
                    raw.events.push(egui::Event::Key { key, physical_key: None, pressed: down, repeat: false, modifiers: egui::Modifiers::NONE });
                }
                Event::File { name, data } => self.import_profile(&name, &data),
                Event::Clipboard(t) => {
                    if self.core.cfg.read().viewer.share_clipboard {
                        self.core.hub.local_text_changed(t);
                    }
                }
                Event::Back => {
                    // one press may come both ways: count it once
                    if self.last_back.elapsed() < Duration::from_millis(700) {
                        continue;
                    }
                    self.last_back = Instant::now();
                    log::info!("Back pressed");
                    if let Some(v) = self.view.as_mut() {
                        v.back();
                    } else if self.pending.is_some() {
                        self.pending = None;
                    } else if matches!(self.page, Page::Home) {
                        java::move_to_back();
                    } else {
                        self.page = Page::Home;
                    }
                }
                Event::KeyboardHidden => {
                    self.keyboard_up = false;
                    self.keyboard_dismissed = true;
                    if let Some(v) = self.view.as_mut() {
                        v.set_keyboard(false);
                    }
                }
                other => self.remote_events.push(other),
            }
        }
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(500));
        let events = std::mem::take(&mut self.remote_events);
        if let Some(v) = self.view.as_mut() {
            for ev in events {
                match ev {
                    Event::Text(t) => v.type_text(&t),
                    Event::Key { code, down, ch } => v.android_key(code, down, ch),
                    _ => {}
                }
            }
        }
        self.inset_panels(ctx);
        let closed = match self.view.as_mut() {
            Some(v) => matches!(v.show(ctx, &self.core), Outcome::Close),
            None => {
                match self.page {
                    Page::Home => self.home(ctx),
                    Page::Setup(_) => self.setup(ctx),
                    Page::Settings => self.settings(ctx),
                }
                self.check_pending(ctx);
                false
            }
        };
        if let Some((_, n)) = self.retired.as_mut() {
            *n += 1;
            if *n > 3 {
                self.retired = None;
            }
        }
        if closed {
            if let Some(v) = self.view.take() {
                self.core.sessions.lock().retain(|s| s.id != v.session.id);
                self.retired = Some((v, 0));
            }
            java::set_viewing(false);
            java::set_orientation(0);
            self.page = Page::Home;
        }
        self.export_downloads();
        self.update_keyboard(ctx);
    }
}
