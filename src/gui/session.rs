//! One viewer session window (a native OS window via an egui viewport).

use crate::app::Core;
use crate::config::{AudioMode, QualityMode, ScaleMode};
use crate::viewer::{Answer, Session, State};
use crate::keys::{egui_keysym, to_color_image, KEY_COMBOS};
use eframe::egui::{self, Color32, RichText, TextureHandle, TextureOptions};
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub struct SessionView {
    pub session: Arc<Session>,
    tex: Option<TextureHandle>,
    tex_gen: u64,
    cursor_tex: Option<(TextureHandle, u64, (usize, usize))>,
    buttons: u8,
    last_pos: (u16, u16),
    scroll_acc: egui::Vec2,
    /// keys currently held on the remote side (released when focus is lost)
    held: Arc<parking_lot::Mutex<Vec<(u32, u32)>>>,
    user: String,
    pass: String,
    /// This window's size mode (starts from the setting)
    scale_mode: Option<ScaleMode>,
    registered: bool,
    egui_mods: u8,
    fallback_logged: bool,
    /// the low-level hook delivers keys for this session: ignore egui key events
    hook_used: Arc<std::sync::atomic::AtomicBool>,
    fullscreen: bool,
    overlay_open: bool,
    /// area covered by the full-screen overlay (clicks there stay local)
    overlay_rect: Option<egui::Rect>,
    /// audio mode to restore when unmuting
    unmuted_audio: Option<AudioMode>,
    /// a menu was open this frame / the last one
    menu_open: bool,
    menu_prev: bool,
    /// a menu or dropdown is open: keys stay here
    input_paused: Arc<std::sync::atomic::AtomicBool>,
    /// this mouse press began off the remote screen (or closed a menu): the remote
    /// computer never sees it
    swallow_press: bool,
}


impl SessionView {
    pub fn new(session: Arc<Session>) -> SessionView {
        #[cfg(windows)]
        let (tx, rx) = crossbeam_channel::unbounded();
        #[cfg(windows)]
        crate::platform::keyhook::register(&session.title, tx);
        let held: Arc<parking_lot::Mutex<Vec<(u32, u32)>>> = Arc::default();
        let hook_used: Arc<std::sync::atomic::AtomicBool> = Arc::default();
        let input_paused: Arc<std::sync::atomic::AtomicBool> = Arc::default();
        // Forward hooked keys straight to the network (no GUI frame needed).
        // The loop ends when the session is unregistered from the hook.
        #[cfg(windows)]
        {
            let (s, held, used, paused) = (session.clone(), held.clone(), hook_used.clone(), input_paused.clone());
            std::thread::Builder::new()
                .name("key-forward".into())
                .spawn(move || {
                    for k in rx {
                        if !used.swap(true, Ordering::Relaxed) {
                            log::info!("Keyboard: capturing keys for {} (low-level hook)", s.address);
                        }
                        // (releases still go through, so no key is left held down)
                        if k.down && paused.load(Ordering::Relaxed) {
                            continue;
                        }
                        {
                            let mut h = held.lock();
                            if k.down {
                                if !h.contains(&(k.keysym, k.xt)) {
                                    h.push((k.keysym, k.xt));
                                }
                            } else {
                                h.retain(|x| *x != (k.keysym, k.xt));
                            }
                        }
                        s.key(k.down, k.keysym, k.xt);
                    }
                })
                .ok();
        }
        SessionView {
            session,
            tex: None,
            tex_gen: u64::MAX,
            cursor_tex: None,
            menu_open: false,
            menu_prev: false,
            input_paused,
            swallow_press: false,
            buttons: 0,
            last_pos: (0, 0),
            scroll_acc: egui::Vec2::ZERO,
            held,
            user: String::new(),
            pass: String::new(),
            scale_mode: None,
            registered: true,
            egui_mods: 0,
            fallback_logged: false,
            hook_used,
            fullscreen: false,
            overlay_open: false,
            overlay_rect: None,
            unmuted_audio: None,
        }
    }

    fn release_keys(&mut self) {
        let keys: Vec<(u32, u32)> = self.held.lock().drain(..).collect();
        for (k, x) in keys {
            self.session.key(false, k, x);
        }
    }

    fn upload(&mut self, ctx: &egui::Context) {
        let Some(mut fb) = self.session.fb.try_lock() else { return };
        if fb.width == 0 || fb.height == 0 {
            return;
        }
        if self.tex.is_none() || self.tex_gen != fb.generation {
            let img = to_color_image(&fb, 0, 0, fb.width, fb.height);
            self.tex = Some(ctx.load_texture(format!("remote-{}", self.session.id), img, TextureOptions::LINEAR));
            self.tex_gen = fb.generation;
            fb.dirty = None;
            return;
        }
        if let Some((x0, y0, x1, y1)) = fb.dirty.take() {
            if x1 > x0 && y1 > y0 {
                let img = to_color_image(&fb, x0, y0, x1, y1);
                if let Some(t) = self.tex.as_mut() {
                    t.set_partial([x0, y0], img, TextureOptions::LINEAR);
                }
            }
        }
    }

    /// The window's size menu (the toolbar and the full-screen bar).
    fn scale_menu(&mut self, ui: &mut egui::Ui, id: u64) {
        let cur = self.scale_mode.unwrap_or(ScaleMode::KeepRatio);
        egui::ComboBox::from_id_salt(("scale", id)).selected_text(cur.label()).width(180.0).show_ui(ui, |ui| {
            for m in ScaleMode::ALL {
                if ui.selectable_label(cur == m, m.label()).clicked() {
                    self.scale_mode = Some(m);
                }
            }
        });
    }

    /// Returns false when the window has been closed.
    pub fn show(&mut self, ctx: &egui::Context, core: &Arc<Core>) -> bool {
        if self.scale_mode.is_none() {
            self.scale_mode = Some(core.cfg.read().viewer.scale());
        }
        // (the full-screen bar is drawn after the picture, so last frame's answer counts)
        self.menu_prev = std::mem::take(&mut self.menu_open);
        let s = self.session.clone();
        let vid = egui::ViewportId::from_hash_of(("session", s.id));
        let builder = egui::ViewportBuilder::default().with_title(&s.title).with_inner_size([1280.0, 800.0]).with_min_inner_size([480.0, 320.0]);
        let mut keep = true;
        ctx.show_viewport_immediate(vid, builder, |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested()) {
                keep = false;
                return;
            }
            self.upload(ctx);
            let state = s.state.lock().clone();
            if !self.fullscreen {
            egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    // first, so a narrow window can't cut it off
                    self.scale_menu(ui, s.id);
                    let name = s.desktop_name.lock().clone();
                    let route = if s.via_vpn.load(Ordering::Relaxed) { "via VPN" } else { "direct" };
                    let kind = if s.native.load(Ordering::Relaxed) { "PortlessVNC" } else { "standard VNC" };
                    ui.label(RichText::new(if name.is_empty() { s.address.clone() } else { name }).strong());
                    ui.label(RichText::new(format!("{route} - {kind}")).small().weak());
                    ui.separator();
                    let mut q = *s.quality.lock();
                    let before = q;
                    egui::ComboBox::from_id_salt(("q", s.id)).selected_text(q.label()).width(170.0).show_ui(ui, |ui| {
                        for m in QualityMode::ALL {
                            ui.selectable_value(&mut q, m, m.label());
                        }
                    });
                    if q != before {
                        s.set_quality(q);
                    }
                    if s.native.load(Ordering::Relaxed) {
                        let mut a = *s.audio.lock();
                        let before = a;
                        ui.label("Audio:");
                        egui::ComboBox::from_id_salt(("a", s.id)).selected_text(a.label()).width(150.0).show_ui(ui, |ui| {
                            for m in AudioMode::PRESETS {
                                ui.selectable_value(&mut a, m, m.label());
                            }
                        });
                        if a != before {
                            s.set_audio(a);
                        }
                        if ui.button("Send files...").clicked() {
                            if let Some(files) = rfd::FileDialog::new().pick_files() {
                                s.send_files(files);
                            }
                        }
                    }
                    let kb = if self.hook_used.load(Ordering::Relaxed) { "hook" } else if self.fallback_logged { "window" } else { "none yet" };
                    ui.label(RichText::new(format!("keys: {kb}")).small().weak()).on_hover_text("How keystrokes are captured: 'hook' = all keys incl. Win/Alt+Tab, 'window' = normal keys via the window");
                    let keys_menu = ui.menu_button("Keys", |ui| {
                        for (label, combo, hint) in KEY_COMBOS {
                            let b = ui.button(*label);
                            let b = if hint.is_empty() { b } else { b.on_hover_text(*hint) };
                            if b.clicked() {
                                s.key_combo(combo);
                                ui.close_menu();
                            }
                        }
                    });
                    self.menu_open |= keys_menu.inner.is_some();
                    let note_unread = core.hub.note_unread();
                    if s.native.load(Ordering::Relaxed) {
                        let open = core.hub.note_window.load(Ordering::Relaxed);
                        if ui.selectable_label(open, if note_unread { "Shared text \u{25CF}" } else { "Shared text" }).on_hover_text("A text window shared with the other side (paste or chat)").clicked() {
                            core.hub.note_window.store(!open, Ordering::Relaxed);
                        }
                    }
                    if ui.button("Full screen").clicked() {
                        self.fullscreen = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Disconnect").clicked() {
                            keep = false;
                        }
                        let rtt = s.rtt_ms.load(Ordering::Relaxed);
                        let secs = s.started.elapsed().as_secs_f64().max(1.0);
                        let kbps = s.bytes_in.load(Ordering::Relaxed) as f64 * 8.0 / 1000.0 / secs;
                        let mut info = format!("{:.0} kbit/s avg", kbps);
                        if rtt > 0 {
                            info.push_str(&format!(" - {rtt} ms"));
                        }
                        ui.label(RichText::new(info).small().weak());
                    });
                });
            });
            }
            egui::CentralPanel::default().frame(egui::Frame::none().fill(Color32::from_gray(20))).show(ctx, |ui| match &state {
                State::Connected => self.remote_view(ui, ctx),
                State::Connecting(msg) => {
                    ui.centered_and_justified(|ui| {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(RichText::new(msg).color(Color32::LIGHT_GRAY));
                        });
                    });
                }
                State::VerifyFingerprint { fingerprint, previous } => {
                    let fingerprint = fingerprint.clone();
                    let previous = previous.clone();
                    egui::Window::new("Verify the remote computer").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
                        if previous.is_some() {
                            ui.colored_label(Color32::from_rgb(0xe0, 0x50, 0x50), "WARNING: this computer's fingerprint has CHANGED since your last connection. This can mean someone is intercepting the connection - or the remote PortlessVNC was reinstalled.");
                        } else {
                            ui.label("First connection to this computer. Make sure this fingerprint matches the one the remote computer shows under 'Fingerprint':");
                        }
                        ui.add_space(6.0);
                        ui.label(RichText::new(crate::util::short_fingerprint(&fingerprint)).monospace().size(18.0).strong());
                        ui.label(RichText::new(&fingerprint).monospace().small().weak());
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button(RichText::new("Trust and connect").strong()).clicked() {
                                s.answer(Answer::Fingerprint(true));
                            }
                            if ui.button("Cancel").clicked() {
                                s.answer(Answer::Fingerprint(false));
                            }
                        });
                    });
                }
                State::NeedCredentials { username, message } => {
                    let need_user = *username;
                    let message = message.clone();
                    egui::Window::new("Sign in").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
                        ui.label(message);
                        let mut submit = false;
                        egui::Grid::new(("cred", s.id)).num_columns(2).show(ui, |ui| {
                            if need_user {
                                ui.label("Username:");
                                ui.text_edit_singleline(&mut self.user);
                                ui.end_row();
                            }
                            ui.label("Password:");
                            let r = ui.add(egui::TextEdit::singleline(&mut self.pass).password(true));
                            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                submit = true;
                            }
                            r.request_focus();
                            ui.end_row();
                        });
                        ui.horizontal(|ui| {
                            if ui.button(RichText::new("Connect").strong()).clicked() {
                                submit = true;
                            }
                            if ui.button("Cancel").clicked() {
                                s.answer(Answer::Cancel);
                            }
                        });
                        if submit {
                            s.answer(Answer::Credentials(self.user.clone(), std::mem::take(&mut self.pass)));
                        }
                    });
                }
                State::Closed(msg) => {
                    let msg = msg.clone();
                    ui.centered_and_justified(|ui| {
                        ui.vertical_centered(|ui| {
                            ui.add_space(ui.available_height() / 3.0);
                            ui.label(RichText::new("Connection closed").size(20.0).color(Color32::LIGHT_GRAY));
                            ui.label(RichText::new(msg).color(Color32::GRAY));
                            ui.add_space(8.0);
                            if ui.button("Close window").clicked() {
                                keep = false;
                            }
                        });
                    });
                }
            });
            if self.fullscreen {
                self.fullscreen_overlay(ctx, core, &mut keep);
            } else {
                self.overlay_rect = None;
            }
        });
        if !keep {
            self.release_keys();
            self.session.close();
            #[cfg(windows)]
            if self.registered {
                crate::platform::keyhook::unregister(&self.session.title);
                self.registered = false;
            }
        }
        keep
    }

    /// Full-screen mode: a small tab at the top centre that drops down a bar
    /// with the essentials. Clicks on it stay local.
    fn fullscreen_overlay(&mut self, ctx: &egui::Context, core: &Arc<Core>, keep: &mut bool) {
        let s = self.session.clone();
        let screen = ctx.screen_rect();
        let pointer = ctx.input(|i| i.pointer.hover_pos());
        // open when the mouse reaches the top edge near the tab, close when it leaves
        let hot_zone = egui::Rect::from_center_size(egui::pos2(screen.center().x, screen.top() + 4.0), egui::vec2(260.0, 8.0));
        if pointer.map(|p| hot_zone.contains(p)).unwrap_or(false) {
            self.overlay_open = true;
        }
        let area = egui::Area::new(egui::Id::new(("fs-overlay", s.id))).order(egui::Order::Foreground).anchor(egui::Align2::CENTER_TOP, [0.0, 0.0]);
        let resp = area.show(ctx, |ui| {
            egui::Frame::none().fill(Color32::from_rgba_unmultiplied(30, 30, 30, 235)).rounding(egui::Rounding { nw: 0.0, ne: 0.0, sw: 8.0, se: 8.0 }).inner_margin(egui::Margin::symmetric(10.0, 4.0)).show(ui, |ui| {
                if !self.overlay_open {
                    let t = ui.add(egui::Label::new(RichText::new("\u{25BE} PortlessVNC").small().color(Color32::LIGHT_GRAY)).sense(egui::Sense::click()));
                    if t.clicked() || t.hovered() {
                        self.overlay_open = true;
                    }
                    return;
                }
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&s.address).small().strong().color(Color32::LIGHT_GRAY));
                    ui.separator();
                    if ui.button("Exit full screen").clicked() {
                        self.fullscreen = false;
                        self.overlay_open = false;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                    }
                    self.scale_menu(ui, s.id);
                    if s.native.load(Ordering::Relaxed) {
                        let muted = *s.audio.lock() == AudioMode::Off;
                        if ui.button(if muted { "Unmute" } else { "Mute" }).clicked() {
                            if muted {
                                s.set_audio(self.unmuted_audio.take().unwrap_or(AudioMode::Auto));
                            } else {
                                self.unmuted_audio = Some(*s.audio.lock());
                                s.set_audio(AudioMode::Off);
                            }
                        }
                    }
                    let keys_menu = ui.menu_button("Keys", |ui| {
                        for (label, combo, hint) in KEY_COMBOS {
                            let b = ui.button(*label);
                            let b = if hint.is_empty() { b } else { b.on_hover_text(*hint) };
                            if b.clicked() {
                                s.key_combo(combo);
                                ui.close_menu();
                            }
                        }
                    });
                    self.menu_open |= keys_menu.inner.is_some();
                    if s.native.load(Ordering::Relaxed) {
                        let open = core.hub.note_window.load(Ordering::Relaxed);
                        let label = if core.hub.note_unread() { "Shared text \u{25CF}" } else { "Shared text" };
                        if ui.selectable_label(open, label).clicked() {
                            core.hub.note_window.store(!open, Ordering::Relaxed);
                        }
                    }
                    if ui.button("Disconnect").clicked() {
                        *keep = false;
                    }
                    if ui.small_button("\u{25B4}").on_hover_text("Hide this bar").clicked() {
                        self.overlay_open = false;
                    }
                });
            });
        });
        let rect = resp.response.rect;
        self.overlay_rect = Some(rect.expand(4.0));
        // auto-hide once the mouse moves away (but not while a menu is open)
        if self.overlay_open {
            let near = pointer.map(|p| rect.expand(40.0).contains(p)).unwrap_or(false);
            // (the Keys sub-menu pops up outside the bar: hovering it counts as near)
            let over_ui = ctx.is_pointer_over_area();
            if !near && !over_ui && !ctx.memory(|m| m.any_popup_open()) {
                self.overlay_open = false;
            }
        }
    }

    fn remote_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let s = self.session.clone();
        let Some(tex) = self.tex.clone() else { return };
        let (fw, fh) = {
            let sz = tex.size();
            (sz[0] as f32, sz[1] as f32)
        };
        let avail = ui.available_rect_before_wrap();
        let mode = self.scale_mode.unwrap_or(ScaleMode::KeepRatio);
        let ppp = ctx.pixels_per_point();
        // scroll bars here take up room rather than float over the picture, so a
        // click on one can never reach the remote computer
        ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
        let bar = ui.spacing().scroll.allocated_width();
        let (sx, sy) = match mode {
            // leave room for the one scroll bar if this mode will need it
            ScaleMode::FitWidth if fh * avail.width() / fw > avail.height() => mode.scales(avail.width() - bar, avail.height(), fw, fh, ppp),
            ScaleMode::FitHeight if fw * avail.height() / fh > avail.width() => mode.scales(avail.width(), avail.height() - bar, fw, fh, ppp),
            _ => mode.scales(avail.width(), avail.height(), fw, fh, ppp),
        };
        let size = egui::vec2(fw * sx, fh * sy);

        let draw = |ui: &mut egui::Ui| -> (egui::Response, egui::Rect) {
            // centred on any side where the picture is smaller than the window
            let outer = size.max(ui.available_size());
            let (area, resp) = ui.allocate_exact_size(outer, egui::Sense::click_and_drag());
            let rect = egui::Rect::from_center_size(area.center(), size);
            ui.painter().image(tex.id(), rect, egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)), Color32::WHITE);
            (resp, rect)
        };
        // the wheel belongs to the remote computer: the bars move the view here
        if matches!(mode, ScaleMode::FitWidth | ScaleMode::FitHeight | ScaleMode::Full) {
            let over = ctx.input(|i| i.pointer.hover_pos()).is_some_and(|p| avail.contains(p));
            let over_ui = ctx.memory(|m| m.any_popup_open());
            if over && !over_ui {
                ctx.input_mut(|i| i.smooth_scroll_delta = egui::Vec2::ZERO);
            }
        }
        let ((resp, rect), visible) = {
            let area = match mode {
                ScaleMode::FitWidth => Some(egui::ScrollArea::vertical()),
                ScaleMode::FitHeight => Some(egui::ScrollArea::horizontal()),
                ScaleMode::Full => Some(egui::ScrollArea::both()),
                _ => None,
            };
            match area {
                Some(a) => {
                    let out = a.auto_shrink([false, false]).drag_to_scroll(false).show(ui, |ui| draw(ui));
                    (out.inner, out.inner_rect)
                }
                None => (draw(ui), avail),
            }
        };

        let focused = ctx.input(|i| i.focused);
        // a menu or dropdown is open: mouse and keys stay here until it closes
        let paused = self.menu_open || self.menu_prev || ctx.memory(|m| m.any_popup_open());
        self.input_paused.store(paused, Ordering::Relaxed);
        if (paused || !focused) && !self.held.lock().is_empty() {
            self.release_keys();
        }

        // (hooked keys are forwarded by the key-forward thread)

// Fallback keyboard path: egui only sees keys the hook did not capture
        // (hook unavailable, or another app owns the keyboard), so forward them.
        if focused && !paused && !self.hook_used.load(Ordering::Relaxed) {
            let (events, mods) = ctx.input(|i| (i.events.clone(), i.modifiers));
            for (bit, on, keysym, xt) in [
                (0, mods.shift, 0xffe1u32, 0x2au32),
                (1, mods.ctrl, 0xffe3, 0x1d),
                (2, mods.alt, 0xffe9, 0x38),
            ] {
                let was = self.egui_mods & (1 << bit) != 0;
                if on != was {
                    s.key(on, keysym, xt);
                    self.egui_mods ^= 1 << bit;
                }
            }
            for ev in events {
                let (key, pressed) = match ev {
                    egui::Event::Key { key, pressed, .. } => (key, pressed),
                    egui::Event::Copy => (egui::Key::C, true),
                    egui::Event::Cut => (egui::Key::X, true),
                    egui::Event::Paste(_) => (egui::Key::V, true),
                    _ => continue,
                };
                if let Some(keysym) = egui_keysym(key) {
                    if !self.fallback_logged {
                        self.fallback_logged = true;
                        log::info!("Keyboard: using window key events for {}", s.address);
                    }
                    s.key(pressed, keysym, 0);
                }
            }
        } else if self.egui_mods != 0 {
            for (bit, keysym, xt) in [(0, 0xffe1u32, 0x2au32), (1, 0xffe3, 0x1d), (2, 0xffe9, 0x38)] {
                if self.egui_mods & (1 << bit) != 0 {
                    s.key(false, keysym, xt);
                }
            }
            self.egui_mods = 0;
        }

        // pointer
        let (pos, mut b, scroll) = ctx.input(|i| {
            let mut b = 0u8;
            if i.pointer.button_down(egui::PointerButton::Primary) {
                b |= 1;
            }
            if i.pointer.button_down(egui::PointerButton::Middle) {
                b |= 2;
            }
            if i.pointer.button_down(egui::PointerButton::Secondary) {
                b |= 4;
            }
            (i.pointer.hover_pos(), b, i.raw_scroll_delta)
        });
        let over_overlay = matches!((pos, self.overlay_rect), (Some(p), Some(r)) if r.contains(p));
        // (inside the picture and not on a scroll bar or scrolled out of view)
        // anything drawn on top of the picture (a menu, the shared text window) keeps its clicks
        let covered = pos.is_some_and(|p| ctx.layer_id_at(p).is_some_and(|l| l != ui.layer_id()));
        let inside = pos.map(|p| rect.contains(p) && visible.contains(p)).unwrap_or(false) && !over_overlay && !covered && !paused;
        if b == 0 {
            self.swallow_press = false;
        } else if self.buttons == 0 && !inside {
            self.swallow_press = true;
        }
        if self.swallow_press {
            b = 0;
        }
        if let Some(p) = pos {
            if inside || self.buttons != 0 {
                let x = (((p.x - rect.min.x) / sx).clamp(0.0, fw - 1.0)) as u16;
                let y = (((p.y - rect.min.y) / sy).clamp(0.0, fh - 1.0)) as u16;
                let buttons = if inside || b == 0 { b } else { self.buttons & b };
                if (x, y) != self.last_pos || buttons != self.buttons {
                    s.pointer(x, y, buttons);
                    self.last_pos = (x, y);
                    self.buttons = buttons;
                }
                if inside {
                    self.scroll_acc += scroll;
                    let step = 40.0;
                    while self.scroll_acc.y >= step {
                        s.pointer(x, y, buttons | 8);
                        s.pointer(x, y, buttons);
                        self.scroll_acc.y -= step;
                    }
                    while self.scroll_acc.y <= -step {
                        s.pointer(x, y, buttons | 16);
                        s.pointer(x, y, buttons);
                        self.scroll_acc.y += step;
                    }
                    while self.scroll_acc.x >= step {
                        s.pointer(x, y, buttons | 32);
                        s.pointer(x, y, buttons);
                        self.scroll_acc.x -= step;
                    }
                    while self.scroll_acc.x <= -step {
                        s.pointer(x, y, buttons | 64);
                        s.pointer(x, y, buttons);
                        self.scroll_acc.x += step;
                    }
                }
            }
        }
        if resp.hovered() {
            resp.request_focus();
        }

        // draw the remote cursor shape locally (lowest possible latency)
        let cur = s.cursor.lock().clone();
        if let Some((c, gen)) = cur {
            if self.cursor_tex.as_ref().map(|t| t.1) != Some(gen) {
                let pixels = c.rgba.iter().map(|&p| Color32::from_rgba_unmultiplied(p as u8, (p >> 8) as u8, (p >> 16) as u8, (p >> 24) as u8)).collect();
                let img = egui::ColorImage { size: [c.width.max(1), c.height.max(1)], pixels };
                let t = ctx.load_texture(format!("cursor-{}", s.id), img, TextureOptions::NEAREST);
                self.cursor_tex = Some((t, gen, (c.hot_x, c.hot_y)));
            }
            if let (Some((t, _, (hx, hy))), Some(p), true) = (&self.cursor_tex, pos, inside) {
                ctx.set_cursor_icon(egui::CursorIcon::None);
                let cs = egui::vec2(sx.max(0.5), sy.max(0.5));
                let sz = t.size_vec2() * cs;
                let min = p - egui::vec2(*hx as f32, *hy as f32) * cs;
                ui.painter().image(t.id(), egui::Rect::from_min_size(min, sz), egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)), Color32::WHITE);
            }
        }
    }
}


impl Drop for SessionView {
    fn drop(&mut self) {
        #[cfg(windows)]
        if self.registered {
            crate::platform::keyhook::unregister(&self.session.title);
        }
    }
}
