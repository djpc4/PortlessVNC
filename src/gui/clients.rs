//! Saved computers and the known VPNs they use.
//!
//! Each client is assigned no VPN (connects directly), the home VPN (uses what
//! is already up) or a guest VPN (connected for it, closed after its last
//! session). The assignment alone decides the route, because guest VPNs may
//! use the same addresses as each other or as the local network.

use super::session::SessionView;
use super::{App, VpnPrompt, ACCENT};
use crate::config::{AudioMode, BookEntry, ClientVpn, QualityMode, VpnProfile};
use crate::viewer::{Route, Session};
use crate::vpn::{ovpn::OvpnConfig, VpnState};
use eframe::egui::{self, Color32, RichText};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const WARN: Color32 = Color32::from_rgb(0xd9, 0x8a, 0x20);
/// Give up on a VPN that has not come up by then (time at a login prompt doesn't count).
const VPN_WAIT: Duration = Duration::from_secs(60);

pub(super) struct ClientForm {
    /// index in the address book; None = a new client
    edit: Option<usize>,
    name: String,
    address: String,
    user: String,
    pass: String,
    save_pass: bool,
    has_saved_pass: bool,
    vpn: ClientVpn,
    quality: Option<QualityMode>,
    audio: Option<AudioMode>,
    error: String,
}

impl ClientForm {
    fn new_client() -> ClientForm {
        ClientForm { edit: None, name: String::new(), address: String::new(), user: String::new(), pass: String::new(), save_pass: false, has_saved_pass: false, vpn: ClientVpn::None, quality: None, audio: None, error: String::new() }
    }

    fn for_entry(i: usize, e: &BookEntry) -> ClientForm {
        ClientForm { edit: Some(i), name: e.name.clone(), address: e.address.clone(), user: e.username.clone(), pass: String::new(), save_pass: e.password_protected.is_some(), has_saved_pass: e.password_protected.is_some(), vpn: e.vpn(), quality: e.quality, audio: e.audio, error: String::new() }
    }
}

enum Wait {
    Guest(String),
    Home,
}

struct PendingClient {
    entry: BookEntry,
    pass: String,
    wait: Wait,
    since: Instant,
}

enum Step {
    Go(Route, Option<String>),
    Wait,
    Drop(String),
}

#[derive(Clone)]
struct VpnInfo {
    server: String,
    login: &'static str,
}

#[derive(Default)]
struct VpnsPage {
    open: bool,
    sel: Option<String>,
    rename: String,
    user: String,
    pass: String,
    confirm_remove: bool,
}

#[derive(Default)]
pub(super) struct ClientsUi {
    form: Option<ClientForm>,
    pending: Vec<PendingClient>,
    home_prompt: Option<(BookEntry, String)>,
    confirm_delete: Option<usize>,
    vpns: VpnsPage,
    vpn_info: HashMap<String, VpnInfo>,
}

fn decode_saved(b: &Option<String>) -> Option<String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(b.as_ref()?).ok()?;
    String::from_utf8(crate::platform::unprotect(&raw)?).ok()
}

fn encode_saved(pass: &str) -> Option<String> {
    use base64::Engine;
    crate::platform::protect_for_config(pass.as_bytes()).map(|b| base64::engine::general_purpose::STANDARD.encode(b))
}

/// The text, shortened with "..." if it's wider than `width`.
fn fit_text(ui: &egui::Ui, text: &str, font: &egui::FontId, width: f32) -> String {
    let wide = |s: &str| ui.fonts(|f| f.layout_no_wrap(s.to_string(), font.clone(), Color32::WHITE).size().x) > width;
    if !wide(text) {
        return text.to_string();
    }
    let mut kept: Vec<char> = text.chars().collect();
    while !kept.is_empty() {
        kept.pop();
        let s: String = kept.iter().collect::<String>() + "...";
        if !wide(&s) {
            return s;
        }
    }
    "...".into()
}

fn vpn_label(v: &ClientVpn, known: bool) -> String {
    match v {
        ClientVpn::Unset => "Decide by address (older entry)".into(),
        ClientVpn::None => "No VPN (local network)".into(),
        ClientVpn::Home => "Home VPN".into(),
        ClientVpn::Guest(n) if known => n.clone(),
        ClientVpn::Guest(n) => format!("{n} (VPN missing)"),
    }
}

impl App {
    fn profile_named(&self, name: &str) -> Option<(usize, VpnProfile)> {
        let c = self.core.cfg.read();
        c.vpn.profiles.iter().position(|p| p.name == name).map(|i| (i, c.vpn.profiles[i].clone()))
    }

    fn guest_active(&self, name: &str) -> bool {
        self.core.guests.lock().get(name).is_some_and(|v| matches!(v.status().state, VpnState::Connected | VpnState::Connecting(_) | VpnState::Reconnecting(_)))
    }

    /// The window's own VPN is up on this profile.
    fn window_vpn_is(&self, name: &str) -> bool {
        let st = self.core.vpn.status();
        st.state == VpnState::Connected && st.profile == name && self.core.vpn.vpn_ip().is_some()
    }

    fn service_vpn_is(&self, name: Option<&str>) -> bool {
        self.svc.as_ref().is_some_and(|s| s.vpn_state == "connected" && name.is_none_or(|n| s.vpn_profile == n))
    }

    /// How to reach the home VPN right now, if it is up.
    fn home_route(&self) -> Option<Route> {
        if self.service_vpn_is(None) {
            return Some(Route::ServiceRelay);
        }
        let home = self.core.cfg.read().vpn.home.clone()?;
        self.window_vpn_is(&home).then(|| Route::Tunnel(self.core.vpn.clone()))
    }

    // ---- connecting ---------------------------------------------------------

    /// Connect a client the way it is assigned, bringing up its VPN if needed.
    fn open_client(&mut self, e: BookEntry, pass: String) {
        if crate::viewer::parse_address(&e.address).is_none() {
            self.toast("Invalid address");
            return;
        }
        match e.vpn() {
            ClientVpn::Unset => self.start_client(&e, &pass, Route::Auto, None),
            ClientVpn::None => self.start_client(&e, &pass, Route::Direct, None),
            ClientVpn::Home => {
                if let Some(route) = self.home_route() {
                    self.start_client(&e, &pass, route, None);
                } else if self.svc.is_some() || self.core.cfg.read().vpn.home.is_some() {
                    self.clients.home_prompt = Some((e, pass));
                } else {
                    self.toast("No VPN is flagged as home yet");
                    self.clients.vpns.open = true;
                }
            }
            ClientVpn::Guest(name) => self.open_guest_client(e, pass, name),
        }
    }

    fn open_guest_client(&mut self, e: BookEntry, pass: String, name: String) {
        let Some((idx, prof)) = self.profile_named(&name) else {
            // never fall back to a direct connection: that could be the wrong network
            self.toast(format!("The VPN '{name}' is gone: choose another for {}", e.name));
            let i = self.core.cfg.read().address_book.iter().position(|b| b.name == e.name && b.address == e.address);
            if let Some(i) = i {
                self.clients.form = Some(ClientForm::for_entry(i, &e));
            }
            return;
        };
        // already up here or in the service: a second login could drop that one
        if self.service_vpn_is(Some(&name)) {
            self.start_client(&e, &pass, Route::ServiceRelay, Some(name));
            return;
        }
        if self.window_vpn_is(&name) {
            let vpn = self.core.vpn.clone();
            self.start_client(&e, &pass, Route::Tunnel(vpn), Some(name));
            return;
        }
        let vpn = self.core.guest_vpn(&name);
        if vpn.status().state == VpnState::Connected && vpn.vpn_ip().is_some() {
            self.start_client(&e, &pass, Route::Tunnel(vpn), Some(name));
            return;
        }
        let waiting = self.clients.pending.iter().any(|p| matches!(&p.wait, Wait::Guest(n) if *n == name));
        if !waiting && !self.guest_active(&name) {
            log::info!("Connecting guest VPN '{name}' for {}", e.name);
            self.vpn_start(vpn, Some(name.clone()), idx, prof, false);
        }
        self.clients.pending.push(PendingClient { entry: e, pass, wait: Wait::Guest(name), since: Instant::now() });
    }

    fn start_client(&mut self, e: &BookEntry, pass: &str, route: Route, guest: Option<String>) {
        let (q, a) = {
            let c = self.core.cfg.read();
            (e.quality.unwrap_or(c.viewer.quality), e.audio.unwrap_or(c.viewer.audio))
        };
        let s = Session::start_routed(self.core.clone(), e.address.trim(), &e.username, pass, q, a, route, guest);
        self.core.sessions.lock().push(s.clone());
        self.sessions.push(SessionView::new(s));
    }

    fn guest_prompting(&self, name: &str) -> bool {
        self.vpn_prompt.as_ref().is_some_and(|p| p.guest.as_deref() == Some(name))
    }

    fn check_pending(&mut self, p: &mut PendingClient) -> Step {
        let name = match &p.wait {
            Wait::Home => {
                if let Some(route) = self.home_route() {
                    return Step::Go(route, None);
                }
                if self.svc.is_none() {
                    match self.core.vpn.status().state {
                        VpnState::Failed(m) => return Step::Drop(format!("Home VPN: {m}")),
                        VpnState::AuthFailed(m) => return Step::Drop(format!("Home VPN login rejected: {m}")),
                        _ => {}
                    }
                }
                return if p.since.elapsed() > VPN_WAIT { Step::Drop("The home VPN did not connect in time".into()) } else { Step::Wait };
            }
            Wait::Guest(n) => n.clone(),
        };
        if self.guest_prompting(&name) {
            p.since = Instant::now();
            return Step::Wait;
        }
        let vpn = self.core.guest_vpn(&name);
        match vpn.status().state {
            VpnState::Connected if vpn.vpn_ip().is_some() => Step::Go(Route::Tunnel(vpn), Some(name)),
            VpnState::Failed(m) => Step::Drop(format!("{name}: {m}")),
            VpnState::Disconnected => Step::Drop(format!("{name} was disconnected")),
            VpnState::AuthFailed(m) => {
                let Some((idx, prof)) = self.profile_named(&name) else { return Step::Drop(format!("{name} is gone")) };
                self.vpn_start(vpn, Some(name.clone()), idx, prof, true);
                match self.vpn_prompt.as_mut() {
                    Some(pr) => {
                        pr.message = format!("Login rejected: {m}");
                        Step::Wait
                    }
                    None => Step::Drop(format!("{name}: login rejected")),
                }
            }
            VpnState::Challenge { text, echo } => {
                if self.vpn_prompt.is_none() {
                    let profile = self.profile_named(&name).map(|x| x.0).unwrap_or(0);
                    self.vpn_prompt = Some(VpnPrompt { profile, user: String::new(), pass: String::new(), otp: String::new(), remember: false, static_challenge: None, message: text.clone(), challenge: Some((text, echo)), for_service: false, guest: Some(name) });
                }
                Step::Wait
            }
            _ if p.since.elapsed() > VPN_WAIT => Step::Drop(format!("{name} did not connect in time")),
            _ => Step::Wait,
        }
    }

    /// Every frame: start clients whose VPN came up; close guest VPNs nobody uses.
    pub(super) fn tick_clients(&mut self) {
        for mut p in std::mem::take(&mut self.clients.pending) {
            match self.check_pending(&mut p) {
                Step::Go(route, guest) => self.start_client(&p.entry, &p.pass, route, guest),
                Step::Wait => self.clients.pending.push(p),
                Step::Drop(msg) => {
                    log::warn!("{msg}");
                    self.toast(msg);
                }
            }
        }
        let guests: Vec<_> = self.core.guests.lock().iter().map(|(n, v)| (n.clone(), v.clone())).collect();
        for (name, vpn) in guests {
            if !self.guest_active(&name) || self.guest_prompting(&name) {
                continue;
            }
            let waiting = self.clients.pending.iter().any(|p| matches!(&p.wait, Wait::Guest(n) if *n == name));
            let in_use = self.core.sessions.lock().iter().any(|s| s.guest.as_deref() == Some(name.as_str()) && !s.is_closed());
            if !waiting && !in_use {
                log::info!("Guest VPN '{name}': last client closed, disconnecting");
                vpn.disconnect();
            }
        }
    }

    pub(super) fn cancel_guest_wait(&mut self, name: &str) {
        self.clients.pending.retain(|p| !matches!(&p.wait, Wait::Guest(n) if n == name));
    }

    pub(super) fn close_guests(&mut self) {
        for v in self.core.guests.lock().values() {
            v.disconnect();
        }
    }

    // ---- address list -------------------------------------------------------

    fn vpn_info(&mut self, p: &VpnProfile) -> VpnInfo {
        if let Some(i) = self.clients.vpn_info.get(&p.name) {
            return i.clone();
        }
        let info = match OvpnConfig::load(std::path::Path::new(&p.ovpn_path)) {
            Ok(c) => VpnInfo {
                server: c.remotes.first().map(|r| r.host.clone()).unwrap_or_default(),
                login: if !c.auth_user_pass {
                    "not needed"
                } else if c.auth_file_creds.is_some() {
                    "in the file"
                } else if p.password_protected.is_some() {
                    "saved"
                } else {
                    "asks"
                },
            },
            Err(_) => VpnInfo { server: "(file missing or unusable)".into(), login: "-" },
        };
        self.clients.vpn_info.insert(p.name.clone(), info.clone());
        info
    }

    /// "address @ VPN server"
    fn client_at(&mut self, e: &BookEntry) -> String {
        let at = match e.vpn() {
            ClientVpn::Unset => "decided by address".to_string(),
            ClientVpn::None => "no VPN".to_string(),
            ClientVpn::Home => "home VPN".to_string(),
            ClientVpn::Guest(n) => match self.profile_named(&n) {
                Some((_, p)) => self.vpn_info(&p).server,
                None => format!("{n} (VPN missing)"),
            },
        };
        format!("{} @ {at}", e.address)
    }

    fn group_title(&self, g: &ClientVpn) -> String {
        match g {
            ClientVpn::Home => {
                let state = if let Some(s) = &self.svc {
                    format!("service: {}", s.vpn_state)
                } else {
                    let home = self.core.cfg.read().vpn.home.clone();
                    match home {
                        Some(h) if self.window_vpn_is(&h) => format!("{h}: connected"),
                        Some(h) => format!("{h}: not connected"),
                        None => "none flagged".into(),
                    }
                };
                format!("Home VPN  ({state})")
            }
            ClientVpn::Guest(n) => {
                let known = self.profile_named(n).is_some();
                if !known {
                    format!("{n}  (VPN missing)")
                } else if self.guest_active(n) {
                    format!("{n}  (connected for now)")
                } else {
                    n.clone()
                }
            }
            ClientVpn::None => "No VPN (local network)".into(),
            ClientVpn::Unset => "Not sorted yet (right-click to choose a VPN)".into(),
        }
    }

    pub(super) fn clients_section(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Computers").strong());
            if ui.small_button("+ Add client").clicked() {
                self.clients.form = Some(ClientForm::new_client());
            }
            if ui.small_button("Known VPNs...").clicked() {
                self.clients.vpns.open = true;
            }
        });

        let mut cancel = None;
        for (i, p) in self.clients.pending.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.spinner();
                let what = match &p.wait {
                    Wait::Guest(n) => n.as_str(),
                    Wait::Home => "the home VPN",
                };
                ui.label(RichText::new(format!("Connecting {what} for {}...", p.entry.name)).small());
                if ui.small_button("Cancel").clicked() {
                    cancel = Some(i);
                }
            });
        }
        if let Some(i) = cancel {
            self.clients.pending.remove(i);
        }

        let book = self.core.cfg.read().address_book.clone();
        let profile_names: Vec<String> = self.core.cfg.read().vpn.profiles.iter().map(|p| p.name.clone()).collect();
        if book.is_empty() {
            ui.label(RichText::new("No saved computers yet. \"+ Add client\" adds one.").small().weak());
        }

        // the tree: home, then one group per guest VPN, then no VPN
        let mut groups = vec![ClientVpn::Home];
        for n in &profile_names {
            groups.push(ClientVpn::Guest(n.clone()));
        }
        for e in &book {
            let v = e.vpn();
            if !groups.contains(&v) && matches!(v, ClientVpn::Guest(_)) {
                groups.push(v);
            }
        }
        groups.push(ClientVpn::None);
        groups.push(ClientVpn::Unset);
        let details: Vec<String> = book.iter().map(|e| self.client_at(e)).collect();
        let titles: Vec<String> = groups.iter().map(|g| self.group_title(g)).collect();

        let mut connect = None;
        let mut edit = None;
        let mut delete = None;
        let mut moved = None;
        // room below for Recent, and for file transfers when there are any
        let reserve = if self.core.hub.transfers.lock().is_empty() { 50.0 } else { 220.0 };
        let height = (ui.available_height() - reserve).max(120.0);
        egui::ScrollArea::vertical().id_salt("computers").max_height(height).auto_shrink([false, true]).show(ui, |ui| {
            for (g, title) in groups.iter().zip(&titles) {
                if !book.iter().any(|e| e.vpn() == *g) {
                    continue;
                }
                egui::CollapsingHeader::new(RichText::new(title).small().strong()).id_salt(("group", vpn_label(g, true))).default_open(true).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for (i, e) in book.iter().enumerate() {
                            if e.vpn() != *g {
                                continue;
                            }
                            // guest clients also show which VPN they're on
                            let r = if matches!(e.vpn(), ClientVpn::Guest(_)) {
                                let r = ui.add_sized([150.0, 48.0], egui::Button::new(""));
                                let name_font = egui::TextStyle::Button.resolve(ui.style());
                                let small_font = egui::TextStyle::Small.resolve(ui.style());
                                let width = r.rect.width() - 10.0;
                                let c = r.rect.center();
                                let painter = ui.painter();
                                let text = ui.style().interact(&r).text_color();
                                painter.text(c - egui::vec2(0.0, 9.0), egui::Align2::CENTER_CENTER, fit_text(ui, &e.name, &name_font, width), name_font, text);
                                painter.text(c + egui::vec2(0.0, 10.0), egui::Align2::CENTER_CENTER, fit_text(ui, &details[i], &small_font, width), small_font, ui.visuals().weak_text_color());
                                r
                            } else {
                                ui.add_sized([150.0, 48.0], egui::Button::new(RichText::new(&e.name).strong()).wrap())
                            };
                            let r = r.on_hover_text(format!("{}\nDouble-click to connect, right-click for settings", details[i]));
                            if r.double_clicked() {
                                connect = Some(i);
                            }
                            r.context_menu(|ui| {
                                if ui.button("Connect").clicked() {
                                    connect = Some(i);
                                    ui.close_menu();
                                }
                                if ui.button("Settings...").clicked() {
                                    edit = Some(i);
                                    ui.close_menu();
                                }
                                ui.menu_button("Move to", |ui| {
                                    let mut targets = vec![ClientVpn::None, ClientVpn::Home];
                                    targets.extend(profile_names.iter().map(|n| ClientVpn::Guest(n.clone())));
                                    for t in targets {
                                        if ui.add_enabled(t != e.vpn(), egui::Button::new(vpn_label(&t, true))).clicked() {
                                            moved = Some((i, t));
                                            ui.close_menu();
                                        }
                                    }
                                });
                                ui.separator();
                                if ui.button("Delete...").clicked() {
                                    delete = Some(i);
                                    ui.close_menu();
                                }
                            });
                        }
                    });
                });
            }
        });

        if let Some(i) = connect {
            let e = book[i].clone();
            let pass = decode_saved(&e.password_protected).unwrap_or_default();
            self.open_client(e, pass);
        }
        if let Some(i) = edit {
            self.clients.form = Some(ClientForm::for_entry(i, &book[i]));
        }
        if let Some(i) = delete {
            self.clients.confirm_delete = Some(i);
        }
        if let Some((i, t)) = moved {
            if let Some(e) = self.core.cfg.write().address_book.get_mut(i) {
                e.set_vpn(t);
            }
            self.core.save_config();
        }
    }

    // ---- windows ------------------------------------------------------------

    pub(super) fn clients_windows(&mut self, ctx: &egui::Context) {
        self.client_form_window(ctx);
        self.confirm_delete_window(ctx);
        self.home_prompt_window(ctx);
        self.known_vpns_window(ctx);
    }

    fn confirm_delete_window(&mut self, ctx: &egui::Context) {
        let Some(i) = self.clients.confirm_delete else { return };
        let Some(e) = self.core.cfg.read().address_book.get(i).cloned() else {
            self.clients.confirm_delete = None;
            return;
        };
        egui::Window::new("Delete client").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
            ui.label(format!("Delete '{}' ({}) and its saved password?", e.name, e.address));
            ui.horizontal(|ui| {
                if ui.button("Delete").clicked() {
                    self.core.cfg.write().address_book.remove(i);
                    self.core.save_config();
                    self.clients.confirm_delete = None;
                    self.clients.form = None;
                }
                if ui.button("Cancel").clicked() {
                    self.clients.confirm_delete = None;
                }
            });
        });
    }

    fn home_prompt_window(&mut self, ctx: &egui::Context) {
        let Some((entry, pass)) = self.clients.home_prompt.clone() else { return };
        let home = self.core.cfg.read().vpn.home.clone();
        egui::Window::new("Home VPN isn't connected").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
            ui.label(format!("{} uses the home VPN, which isn't up right now.", entry.name));
            if self.svc.is_some() {
                ui.label(RichText::new("The background service holds this computer's home VPN.").small().weak());
            } else {
                ui.label(RichText::new(format!("Connecting '{}' also makes this computer's VNC server reachable on that VPN.", home.clone().unwrap_or_default())).small().weak());
            }
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Connect").strong()).clicked() {
                    if self.svc.is_some() {
                        crate::servicectl::request("vpn-connect");
                    } else if let Some((i, _)) = home.as_deref().and_then(|h| self.profile_named(h)) {
                        self.core.cfg.write().vpn.selected = i;
                        self.vpn_connect(false);
                    }
                    self.clients.pending.push(PendingClient { entry: entry.clone(), pass: pass.clone(), wait: Wait::Home, since: Instant::now() });
                    self.clients.home_prompt = None;
                }
                if ui.button("Cancel").clicked() {
                    self.clients.home_prompt = None;
                }
            });
        });
    }

    /// The entry the form describes, or the reason it can't be used yet.
    fn form_entry(&mut self, f: &ClientForm) -> Result<BookEntry, String> {
        let address = f.address.trim().to_string();
        if crate::viewer::parse_address(&address).is_none() {
            return Err("Enter an address, like 10.8.0.6 or 192.168.1.20:5901".into());
        }
        if let ClientVpn::Guest(n) = &f.vpn {
            if self.profile_named(n).is_none() {
                return Err(format!("The VPN '{n}' is gone: choose another"));
            }
        }
        let mut e = f.edit.and_then(|i| self.core.cfg.read().address_book.get(i).cloned()).unwrap_or_default();
        e.name = if f.name.trim().is_empty() { address.clone() } else { f.name.trim().to_string() };
        e.address = address;
        e.username = f.user.trim().to_string();
        e.quality = f.quality;
        e.audio = f.audio;
        e.set_vpn(f.vpn.clone());
        if !f.save_pass {
            e.password_protected = None;
        } else if !f.pass.is_empty() {
            e.password_protected = Some(encode_saved(&f.pass).ok_or("The password could not be encrypted, so it was not saved")?);
        }
        Ok(e)
    }

    fn client_form_window(&mut self, ctx: &egui::Context) {
        let Some(mut f) = self.clients.form.take() else { return };
        let profiles: Vec<String> = self.core.cfg.read().vpn.profiles.iter().map(|p| p.name.clone()).collect();
        let home = self.core.cfg.read().vpn.home.clone();
        let mut keep = true;
        let (mut connect_once, mut save, mut save_connect, mut delete, mut import) = (false, false, false, false, false);
        let title = if f.edit.is_some() { "Client settings" } else { "Add client" };
        egui::Window::new(title).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
            egui::Grid::new("client-form").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label("Nickname:");
                ui.add(egui::TextEdit::singleline(&mut f.name).hint_text("the name on its shortcut").desired_width(240.0));
                ui.end_row();
                ui.label("Address:");
                ui.add(egui::TextEdit::singleline(&mut f.address).hint_text("10.8.0.6 or 192.168.1.20:5901").font(egui::TextStyle::Monospace).desired_width(240.0));
                ui.end_row();
                ui.label("VPN:");
                ui.horizontal(|ui| {
                    let known = match &f.vpn {
                        ClientVpn::Guest(n) => profiles.contains(n),
                        _ => true,
                    };
                    egui::ComboBox::from_id_salt("client-vpn").selected_text(vpn_label(&f.vpn, known)).width(170.0).show_ui(ui, |ui| {
                        if f.vpn == ClientVpn::Unset {
                            ui.selectable_value(&mut f.vpn, ClientVpn::Unset, vpn_label(&ClientVpn::Unset, true));
                        }
                        ui.selectable_value(&mut f.vpn, ClientVpn::None, vpn_label(&ClientVpn::None, true));
                        ui.selectable_value(&mut f.vpn, ClientVpn::Home, vpn_label(&ClientVpn::Home, true));
                        // the flagged home VPN is "Home VPN" above, not a guest
                        for n in profiles.iter().filter(|n| Some(*n) != home.as_ref()) {
                            ui.selectable_value(&mut f.vpn, ClientVpn::Guest(n.clone()), n);
                        }
                    });
                    if ui.small_button("Import .ovpn...").clicked() {
                        import = true;
                    }
                });
                ui.end_row();
                ui.label("");
                let hint = match &f.vpn {
                    ClientVpn::Unset => "The VPN is used only if this address is in its range.",
                    ClientVpn::None => "Connects directly. Never uses a VPN.",
                    ClientVpn::Home => "Uses the home VPN that's already up.",
                    ClientVpn::Guest(_) => "Connects this VPN when needed and closes it afterwards. This computer can't be reached through it.",
                };
                ui.add(egui::Label::new(RichText::new(hint).small().weak()).wrap());
                ui.end_row();
                ui.label("Username:");
                ui.add(egui::TextEdit::singleline(&mut f.user).hint_text("only if the server asks").desired_width(240.0));
                ui.end_row();
                ui.label("Password:");
                let hint = if f.has_saved_pass { "saved (type to change)" } else { "asked when connecting if empty" };
                ui.add(egui::TextEdit::singleline(&mut f.pass).password(true).hint_text(hint).desired_width(240.0));
                ui.end_row();
                ui.label("");
                ui.checkbox(&mut f.save_pass, "Save password (encrypted for your account)");
                ui.end_row();
                ui.label("Quality:");
                egui::ComboBox::from_id_salt("client-q").selected_text(f.quality.map(|q| q.label()).unwrap_or("App default")).show_ui(ui, |ui| {
                    ui.selectable_value(&mut f.quality, None, "App default");
                    for q in QualityMode::ALL {
                        ui.selectable_value(&mut f.quality, Some(q), q.label());
                    }
                });
                ui.end_row();
                ui.label("Audio:");
                egui::ComboBox::from_id_salt("client-a").selected_text(f.audio.map(|a| a.label()).unwrap_or_else(|| "App default".into())).show_ui(ui, |ui| {
                    ui.selectable_value(&mut f.audio, None, "App default");
                    for a in AudioMode::PRESETS {
                        ui.selectable_value(&mut f.audio, Some(a), a.label());
                    }
                });
                ui.end_row();
            });
            if !f.error.is_empty() {
                ui.colored_label(WARN, &f.error);
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if f.edit.is_none() {
                    connect_once = ui.button("Connect").on_hover_text("Connect once. Nothing is saved.").clicked();
                }
                save = ui.button("Save").clicked();
                save_connect = ui.button(RichText::new("Save & Connect").strong()).clicked();
                if f.edit.is_some() {
                    delete = ui.button("Delete...").clicked();
                }
                if ui.button("Cancel").clicked() {
                    keep = false;
                }
            });
        });
        if import {
            if let Some(name) = self.import_guest_dialog() {
                f.vpn = ClientVpn::Guest(name);
            }
        }
        if delete {
            self.clients.confirm_delete = f.edit;
        }
        if connect_once || save || save_connect {
            match self.form_entry(&f) {
                Err(m) => f.error = m,
                Ok(mut e) => {
                    let pass = if f.pass.is_empty() { decode_saved(&e.password_protected).unwrap_or_default() } else { f.pass.clone() };
                    if connect_once {
                        e.password_protected = None; // nothing of a one-time client is kept
                    } else {
                        {
                            let mut c = self.core.cfg.write();
                            match f.edit.filter(|i| *i < c.address_book.len()) {
                                Some(i) => c.address_book[i] = e.clone(),
                                None => c.address_book.push(e.clone()),
                            }
                        }
                        self.core.save_config();
                    }
                    keep = false;
                    if connect_once || save_connect {
                        self.open_client(e, pass);
                    }
                }
            }
        }
        if keep && self.clients.form.is_none() {
            self.clients.form = Some(f);
        }
    }

    // ---- known VPNs -----------------------------------------------------------

    /// Pick an .ovpn and add it to the known VPNs (not home, not connected).
    fn import_guest_dialog(&mut self) -> Option<String> {
        let path = rfd::FileDialog::new().add_filter("OpenVPN profile", &["ovpn", "conf"]).pick_file()?;
        let cfg = match OvpnConfig::load(&path) {
            Ok(c) => c,
            Err(e) => {
                self.toast(format!("Cannot use this profile: {e:#}"));
                return None;
            }
        };
        let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "VPN".into());
        let mut name = stem.clone();
        let mut n = 2;
        while self.profile_named(&name).is_some() {
            name = format!("{stem} {n}");
            n += 1;
        }
        let ovpn_path = self.keep_private_copy(&path, &name);
        let username = cfg.auth_file_creds.map(|c| c.0).unwrap_or_default();
        self.core.cfg.write().vpn.profiles.push(VpnProfile { name: name.clone(), ovpn_path, username, password_protected: None });
        self.core.save_config();
        log::info!("Added known VPN '{name}'");
        self.toast(format!("Added VPN '{name}'"));
        Some(name)
    }

    fn private_vpn_dir(&self) -> std::path::PathBuf {
        self.core.dir.join("vpns")
    }

    /// Copy the profile into our own folder, so moving the original doesn't
    /// break it. A profile that needs files beside it keeps its original path.
    fn keep_private_copy(&mut self, path: &std::path::Path, name: &str) -> String {
        let original = path.to_string_lossy().into_owned();
        let dir = self.private_vpn_dir();
        let Some(file) = crate::util::sanitize_rel_path(name).and_then(|p| p.file_name().map(|f| f.to_owned())) else { return original };
        if std::fs::create_dir_all(&dir).is_err() {
            return original;
        }
        // these files can hold private keys
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let mut dest = dir.join(file);
        dest.set_extension("ovpn");
        if std::fs::copy(path, &dest).is_err() {
            return original;
        }
        if OvpnConfig::load(&dest).is_err() {
            let _ = std::fs::remove_file(&dest);
            self.toast("This profile uses files beside it, so it stays in its original folder");
            return original;
        }
        dest.to_string_lossy().into_owned()
    }

    fn select_vpn(page: &mut VpnsPage, p: &VpnProfile) {
        page.sel = Some(p.name.clone());
        page.rename = p.name.clone();
        page.user = p.username.clone();
        page.pass.clear();
        page.confirm_remove = false;
    }

    fn rename_vpn(&mut self, old: &str, new: &str) -> Result<(), String> {
        let new = new.trim();
        if new.is_empty() {
            return Err("Enter a name".into());
        }
        if self.profile_named(new).is_some() {
            return Err(format!("There is already a VPN named '{new}'"));
        }
        if self.guest_active(old) || self.core.vpn.status().profile == old && self.core.vpn.vpn_ip().is_some() {
            return Err("Disconnect this VPN first".into());
        }
        {
            let mut c = self.core.cfg.write();
            if let Some(p) = c.vpn.profiles.iter_mut().find(|p| p.name == old) {
                p.name = new.to_string();
            }
            if c.vpn.home.as_deref() == Some(old) {
                c.vpn.home = Some(new.to_string());
            }
            for e in c.address_book.iter_mut() {
                if e.vpn_profile.as_deref() == Some(old) {
                    e.vpn_profile = Some(new.to_string());
                }
            }
            // remembered server identities belong to this VPN's clients
            let prefix = format!("guest/{old}/");
            let moved: Vec<(String, String)> = c.known_hosts.iter().filter(|(k, _)| k.starts_with(&prefix)).map(|(k, v)| (k.clone(), v.clone())).collect();
            for (k, v) in moved {
                c.known_hosts.remove(&k);
                c.known_hosts.insert(format!("guest/{new}/{}", &k[prefix.len()..]), v);
            }
        }
        self.core.guests.lock().remove(old);
        self.clients.vpn_info.remove(old);
        self.core.save_config();
        Ok(())
    }

    fn remove_vpn(&mut self, name: &str) -> Result<(), String> {
        if self.core.vpn.status().profile == name && matches!(self.core.vpn.status().state, VpnState::Connected | VpnState::Connecting(_) | VpnState::Reconnecting(_)) {
            return Err("Disconnect this VPN first".into());
        }
        if let Some(v) = self.core.guests.lock().remove(name) {
            v.disconnect();
        }
        let Some((i, prof)) = self.profile_named(name) else { return Ok(()) };
        {
            let mut c = self.core.cfg.write();
            c.vpn.profiles.remove(i);
            if c.vpn.selected > i {
                c.vpn.selected -= 1;
            } else if c.vpn.selected == i {
                c.vpn.selected = 0;
            }
            if c.vpn.home.as_deref() == Some(name) {
                c.vpn.home = None;
            }
            let prefix = format!("guest/{name}/");
            c.known_hosts.retain(|k, _| !k.starts_with(&prefix));
        }
        // only our own copy, never the file the user imported from
        let path = std::path::Path::new(&prof.ovpn_path);
        if path.starts_with(self.private_vpn_dir()) {
            let _ = std::fs::remove_file(path);
        }
        self.clients.vpn_info.remove(name);
        self.cancel_guest_wait(name);
        self.core.save_config();
        Ok(())
    }

    fn known_vpns_window(&mut self, ctx: &egui::Context) {
        if !self.clients.vpns.open {
            return;
        }
        let mut page = std::mem::take(&mut self.clients.vpns);
        let (profiles, home, book) = {
            let c = self.core.cfg.read();
            (c.vpn.profiles.clone(), c.vpn.home.clone(), c.address_book.clone())
        };
        let infos: Vec<VpnInfo> = profiles.iter().map(|p| self.vpn_info(p)).collect();
        let window_vpn_up = matches!(self.core.vpn.status().state, VpnState::Connected | VpnState::Connecting(_) | VpnState::Reconnecting(_));
        let mut open = true;
        let mut message = None;
        let mut import = false;
        egui::Window::new("Known VPNs").open(&mut open).collapsible(false).default_width(520.0).show(ctx, |ui| {
            if ui.button("Import .ovpn...").clicked() {
                import = true;
            }
            ui.add_space(4.0);
            if profiles.is_empty() {
                ui.label(RichText::new("No VPNs yet. Import an .ovpn file to use it with your clients.").small().weak());
            }
            egui::Grid::new("known-vpns").num_columns(4).striped(true).spacing([14.0, 4.0]).show(ui, |ui| {
                if !profiles.is_empty() {
                    for h in ["Name", "Server", "Login", "Used by"] {
                        ui.label(RichText::new(h).small().strong());
                    }
                    ui.end_row();
                }
                for (p, info) in profiles.iter().zip(&infos) {
                    let is_home = home.as_ref() == Some(&p.name);
                    let label = if is_home { format!("{}  (home)", p.name) } else { p.name.clone() };
                    if ui.selectable_label(page.sel.as_ref() == Some(&p.name), label).clicked() {
                        Self::select_vpn(&mut page, p);
                    }
                    ui.label(RichText::new(&info.server).small());
                    ui.label(RichText::new(info.login).small());
                    let used = book.iter().filter(|e| e.vpn() == ClientVpn::Guest(p.name.clone())).count() + if is_home { book.iter().filter(|e| e.vpn() == ClientVpn::Home).count() } else { 0 };
                    ui.label(RichText::new(if used == 0 { "unused".to_string() } else { format!("{used} client{}", if used == 1 { "" } else { "s" }) }).small());
                    ui.end_row();
                }
            });
            if let Some(s) = &self.svc {
                ui.add_space(4.0);
                ui.label(RichText::new(format!("The background service runs this computer's home VPN ('{}'), from its own settings. While it runs, Home clients use that one.", s.vpn_profile)).small().weak());
            }

            let Some(sel) = page.sel.clone() else { return };
            let Some(p) = profiles.iter().find(|p| p.name == sel).cloned() else {
                page.sel = None;
                return;
            };
            ui.separator();
            ui.label(RichText::new(&p.name).strong());
            ui.label(RichText::new(&p.ovpn_path).small().monospace().weak());

            let is_home = home.as_ref() == Some(&p.name);
            ui.horizontal(|ui| {
                if is_home {
                    ui.label(RichText::new("This is the home VPN").small().color(ACCENT));
                    if ui.add_enabled(!window_vpn_up, egui::Button::new("Remove home flag").small()).clicked() {
                        self.core.cfg.write().vpn.home = None;
                        self.core.save_config();
                    }
                } else if ui.add_enabled(!window_vpn_up, egui::Button::new("Set as home").small()).on_hover_text("Home clients use this VPN, and the VPN card selects it. It can be changed at any time.").clicked() {
                    let i = profiles.iter().position(|x| x.name == p.name).unwrap_or(0);
                    {
                        let mut c = self.core.cfg.write();
                        c.vpn.home = Some(p.name.clone());
                        c.vpn.selected = i;
                        // clients of this VPN are now Home clients
                        for e in c.address_book.iter_mut() {
                            if e.vpn() == ClientVpn::Guest(p.name.clone()) {
                                e.set_vpn(ClientVpn::Home);
                            }
                        }
                    }
                    self.core.save_config();
                }
                if window_vpn_up {
                    ui.label(RichText::new("(disconnect the VPN card to change this)").small().weak());
                }
            });

            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut page.rename).desired_width(180.0));
                if ui.small_button("Rename").clicked() && page.rename.trim() != p.name {
                    match self.rename_vpn(&p.name, &page.rename) {
                        Ok(()) => page.sel = Some(page.rename.trim().to_string()),
                        Err(m) => message = Some(m),
                    }
                }
                if ui.small_button("Replace file...").clicked() {
                    if let Some(path) = rfd::FileDialog::new().add_filter("OpenVPN profile", &["ovpn", "conf"]).pick_file() {
                        match OvpnConfig::load(&path) {
                            Ok(_) => {
                                let new_path = self.keep_private_copy(&path, &p.name);
                                if let Some(x) = self.core.cfg.write().vpn.profiles.iter_mut().find(|x| x.name == p.name) {
                                    x.ovpn_path = new_path;
                                }
                                self.clients.vpn_info.remove(&p.name);
                                self.core.save_config();
                            }
                            Err(e) => message = Some(format!("Cannot use this profile: {e:#}")),
                        }
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut page.user).hint_text("username").desired_width(120.0));
                ui.add(egui::TextEdit::singleline(&mut page.pass).password(true).hint_text(if p.password_protected.is_some() { "saved (type to change)" } else { "password" }).desired_width(120.0));
                if ui.small_button("Save login").clicked() {
                    let saved = if page.pass.is_empty() { Ok(p.password_protected.clone()) } else { encode_saved(&page.pass).map(Some).ok_or(()) };
                    match saved {
                        Ok(saved) => {
                            if let Some(x) = self.core.cfg.write().vpn.profiles.iter_mut().find(|x| x.name == p.name) {
                                x.username = page.user.trim().to_string();
                                x.password_protected = saved;
                            }
                            page.pass.clear();
                            self.clients.vpn_info.remove(&p.name);
                            self.core.save_config();
                        }
                        Err(()) => message = Some("The password could not be encrypted, so it was not saved".into()),
                    }
                }
                if p.password_protected.is_some() && ui.small_button("Forget password").clicked() {
                    if let Some(x) = self.core.cfg.write().vpn.profiles.iter_mut().find(|x| x.name == p.name) {
                        x.password_protected = None;
                    }
                    self.clients.vpn_info.remove(&p.name);
                    self.core.save_config();
                }
            });

            ui.add_space(4.0);
            if page.confirm_remove {
                let clients: Vec<&str> = book.iter().filter(|e| e.vpn() == ClientVpn::Guest(p.name.clone())).map(|e| e.name.as_str()).collect();
                if clients.is_empty() {
                    ui.label(format!("Remove '{}' and its saved login?", p.name));
                } else {
                    ui.colored_label(WARN, format!("{} will show \"VPN missing\" and won't connect until you choose another VPN for them.", clients.join(", ")));
                    ui.label(format!("Remove '{}' and its saved login?", p.name));
                }
                ui.horizontal(|ui| {
                    if ui.button("Remove").clicked() {
                        match self.remove_vpn(&p.name) {
                            Ok(()) => page.sel = None,
                            Err(m) => message = Some(m),
                        }
                        page.confirm_remove = false;
                    }
                    if ui.button("Keep it").clicked() {
                        page.confirm_remove = false;
                    }
                });
            } else if ui.small_button("Remove...").clicked() {
                page.confirm_remove = true;
            }
        });
        if import {
            if let Some(name) = self.import_guest_dialog() {
                if let Some((_, p)) = self.profile_named(&name) {
                    Self::select_vpn(&mut page, &p);
                }
            }
        }
        if let Some(m) = message {
            self.toast(m);
        }
        page.open = open;
        self.clients.vpns = page;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::servicectl::Status;

    fn entry(name: &str, address: &str, v: ClientVpn) -> BookEntry {
        let mut e = BookEntry { name: name.into(), address: address.into(), ..Default::default() };
        e.set_vpn(v);
        e
    }

    fn profile(dir: &std::path::Path, name: &str) -> VpnProfile {
        let path = dir.join(format!("{name}.ovpn"));
        // nothing listens on this address: the connection never leaves this computer
        std::fs::write(&path, "client\nproto udp\nremote 127.0.0.1 1\nauth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n").unwrap();
        VpnProfile { name: name.into(), ovpn_path: path.to_string_lossy().into_owned(), ..Default::default() }
    }

    fn last_route(app: &App) -> (Route, Option<String>) {
        let s = &app.sessions.last().unwrap().session;
        (s.route.clone(), s.guest.clone())
    }

    /// One test: these share the process-wide settings folder.
    #[test]
    fn clients_connect_the_way_they_are_assigned() {
        let dir = std::env::temp_dir().join(format!("pvnc-clients-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("PORTLESS_CONFIG_DIR", dir.join("config"));
        std::env::set_var("PVNC_MACHINE_DIR", dir.join("machine"));
        let core = crate::app::Core::new().unwrap();
        {
            let mut c = core.cfg.write();
            c.public_ip_lookup = false;
            c.vpn.profiles = vec![profile(&dir, "Home"), profile(&dir, "Dave")];
            c.vpn.home = Some("Home".into());
        }
        let ctx = egui::Context::default();
        let mut app = App::new(&ctx, core.clone(), false, false, false);
        app.svc = None;

        // no VPN: directly, even though other VPNs exist
        app.open_client(entry("Nas", "127.0.0.1::1", ClientVpn::None), String::new());
        assert!(matches!(last_route(&app).0, Route::Direct));
        // older entries keep deciding by address
        app.open_client(entry("Old", "127.0.0.1::1", ClientVpn::Unset), String::new());
        assert!(matches!(last_route(&app).0, Route::Auto));
        let started = app.sessions.len();

        // a removed VPN must not turn into a direct connection
        core.cfg.write().address_book.push(entry("Lost", "127.0.0.1::1", ClientVpn::Guest("Gone".into())));
        app.open_client(entry("Lost", "127.0.0.1::1", ClientVpn::Guest("Gone".into())), String::new());
        assert_eq!(app.sessions.len(), started);
        assert!(app.clients.form.is_some(), "its settings open instead");
        app.clients.form = None;

        // home VPN down: asks, doesn't connect anything by itself
        app.open_client(entry("Office", "127.0.0.1::1", ClientVpn::Home), String::new());
        assert_eq!(app.sessions.len(), started);
        assert!(app.clients.home_prompt.is_some());
        assert!(!matches!(core.vpn.status().state, VpnState::Connecting(_)));
        app.clients.home_prompt = None;

        // no home VPN at all: points at Known VPNs
        core.cfg.write().vpn.home = None;
        app.open_client(entry("Office", "127.0.0.1::1", ClientVpn::Home), String::new());
        assert!(app.clients.home_prompt.is_none());
        assert!(app.clients.vpns.open);
        core.cfg.write().vpn.home = Some("Home".into());

        // the service holds the VPN: uses it, without a second login
        app.svc = Some(Status { vpn_state: "connected".into(), vpn_profile: "Home".into(), ..Default::default() });
        app.open_client(entry("Office", "127.0.0.1::1", ClientVpn::Home), String::new());
        assert!(matches!(last_route(&app).0, Route::ServiceRelay));
        app.svc = Some(Status { vpn_state: "connected".into(), vpn_profile: "Dave".into(), ..Default::default() });
        app.open_client(entry("Dave PC", "127.0.0.1::1", ClientVpn::Guest("Dave".into())), String::new());
        let (route, guest) = last_route(&app);
        assert!(matches!(route, Route::ServiceRelay));
        assert_eq!(guest.as_deref(), Some("Dave"));
        app.svc = None;
        let started = app.sessions.len();

        // guest VPN: asks for its login, waits, and starts no session yet
        app.open_client(entry("Dave PC", "127.0.0.1::1", ClientVpn::Guest("Dave".into())), String::new());
        assert_eq!(app.sessions.len(), started);
        assert_eq!(app.clients.pending.len(), 1);
        let prompt = app.vpn_prompt.as_ref().expect("a login prompt");
        assert_eq!(prompt.guest.as_deref(), Some("Dave"));
        app.tick_clients();
        assert_eq!(app.clients.pending.len(), 1, "still waiting at the prompt");

        // the login goes to the guest connection, not the home one
        {
            let p = app.vpn_prompt.as_mut().unwrap();
            p.user = "me".into();
            p.pass = "secret".into();
            p.remember = false;
        }
        app.submit_vpn_prompt();
        assert!(app.guest_active("Dave"));
        assert_eq!(core.vpn.status().state, VpnState::Disconnected);
        assert!(core.cfg.read().vpn.profiles.iter().find(|p| p.name == "Dave").unwrap().password_protected.is_none());
        app.tick_clients();
        assert!(app.guest_active("Dave"), "stays up while its client waits");

        // nobody needs it any more: it closes
        app.clients.pending.clear();
        for s in &app.sessions {
            s.session.close();
        }
        app.tick_clients();
        assert!(!app.guest_active("Dave"));

        // renaming carries everything along; different VPNs keep separate identities
        {
            let mut c = core.cfg.write();
            c.address_book.push(entry("Dave PC", "10.0.0.5", ClientVpn::Guest("Dave".into())));
            c.known_hosts.insert("guest/Dave/10.0.0.5:5900".into(), "fp".into());
            c.known_hosts.insert("10.0.0.5:5900".into(), "other".into());
        }
        app.rename_vpn("Dave", "David").unwrap();
        {
            let c = core.cfg.read();
            assert!(c.address_book.iter().any(|e| e.vpn() == ClientVpn::Guest("David".into())));
            assert_eq!(c.known_hosts.get("guest/David/10.0.0.5:5900").map(|s| s.as_str()), Some("fp"));
            assert_eq!(c.known_hosts.get("10.0.0.5:5900").map(|s| s.as_str()), Some("other"));
        }
        assert!(app.rename_vpn("David", "Home").is_err(), "names stay unique");

        // removing it leaves its clients "missing", and removes only our own copy
        let original = core.cfg.read().vpn.profiles.iter().find(|p| p.name == "David").unwrap().ovpn_path.clone();
        app.remove_vpn("David").unwrap();
        assert!(std::path::Path::new(&original).exists());
        {
            let c = core.cfg.read();
            assert!(c.address_book.iter().any(|e| e.vpn() == ClientVpn::Guest("David".into())));
            assert!(!c.known_hosts.contains_key("guest/David/10.0.0.5:5900"));
        }
        app.remove_vpn("Home").unwrap();
        assert_eq!(core.cfg.read().vpn.home, None);

        // a one-time client saves nothing
        let before = core.cfg.read().address_book.len();
        let mut f = ClientForm::new_client();
        f.address = "127.0.0.1::1".into();
        f.pass = "secret".into();
        f.save_pass = false;
        let e = app.form_entry(&f).unwrap();
        assert!(e.password_protected.is_none());
        assert_eq!(core.cfg.read().address_book.len(), before);
        // a bad address is refused
        f.address = String::new();
        assert!(app.form_entry(&f).is_err());
        app.shutdown();
    }
}
