//! The remote screen on a phone: zoom/pan, touch gestures, on-screen keyboard
//! and a drop-down bar with the session tools.
//!
//! Touchpad mode (default): drag moves the pointer, tap clicks, double-tap and
//! drag drags, long-press or two-finger tap right-clicks, two-finger drag
//! scrolls, pinch zooms (the view follows the pointer).
//! Direct mode: the pointer goes where you touch; drag is a left drag; two
//! fingers pan (when zoomed in) or scroll.

use crate::app::Core;
use crate::config::{AudioMode, QualityMode, ScaleMode};
use crate::keys::{char_keysym, egui_keysym, needs_shift, to_color_image, KEY_COMBOS, SHIFT};
use crate::platform::java;
use crate::viewer::{Answer, Session, State};
use eframe::egui::{self, pos2, vec2, Color32, Pos2, Rect, RichText, TextureHandle, TextureOptions, Vec2};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

const TAP_SLOP: f32 = 14.0;
const ACCENT_DIM: Color32 = Color32::from_rgb(0x2f, 0x7e, 0x5b);
const TAP_TIME: Duration = Duration::from_millis(300);
const LONG_PRESS: Duration = Duration::from_millis(550);
const SCROLL_STEP: f32 = 36.0;

struct OneFinger {
    id: u64,
    start: Pos2,
    last: Pos2,
    t0: Instant,
    moved: bool,
    /// left button held (double-tap-and-drag, or a direct-mode drag)
    dragging: bool,
    long_fired: bool,
}

struct TwoFinger {
    dist0: f32,
    last_dist: f32,
    last_center: Pos2,
    t0: Instant,
    moved: bool,
    zooming: bool,
}

pub enum Outcome {
    Keep,
    Close,
}

/// What touch does in a session.
#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    /// touch drives the pointer
    Mouse,
    /// the phone keyboard is up (touch still drives the pointer)
    Keyboard,
    /// nothing is sent: one finger pans, pinch zooms
    View,
}

pub struct RemoteView {
    pub session: Arc<Session>,
    tex: Option<TextureHandle>,
    /// replaced textures, kept until the frame that drew them has been submitted
    old_tex: Vec<(TextureHandle, u64)>,
    frame: u64,
    tex_gen: u64,
    cursor_tex: Option<(TextureHandle, u64, (usize, usize))>,
    /// How the screen is sized before zooming (starts from the setting)
    scale_mode: Option<ScaleMode>,
    /// physical pixels per UI point
    ppp: f32,
    /// 1.0 = the size mode's own size
    zoom: f32,
    /// remote point shown at the centre of the phone screen
    center: Pos2,
    centered: bool,
    /// remote pointer position
    cursor: Pos2,
    buttons: u8,
    last_sent: (u16, u16, u8),
    /// touches that started on the UI (bar, dialogs) are not sent
    ui_touches: Vec<u64>,
    fingers: HashMap<u64, Pos2>,
    one: Option<OneFinger>,
    two: Option<TwoFinger>,
    /// three-finger tap toggles the keyboard
    three: Option<Instant>,
    /// after a multi-finger gesture: ignore fingers until all are lifted
    wait_all_up: bool,
    last_tap: Option<(Instant, Pos2)>,
    scroll_acc: f32,
    pub direct: bool,
    pub mode: Mode,
    options_open: bool,
    orientation: u8,
    bar_open: bool,
    bar_rect: Option<Rect>,
    keys_rect: Option<Rect>,
    mouse_rect: Option<Rect>,
    /// remote screen size (for the mouse-button bar)
    fb_size: (f32, f32),
    /// buttons held down from the bar
    bar_buttons: u8,
    /// sticky modifiers from the extra-keys row (released after the next key)
    ctrl: bool,
    alt: bool,
    user: String,
    pass: String,
    unmuted_audio: Option<AudioMode>,
    note_open: bool,
    confirm_close: bool,
    /// Back was pressed: disconnect on the next frame
    close_now: bool,
}

/// X11 keysym for an Android KEYCODE_* (keys without a character).
fn android_keysym(code: i32) -> Option<u32> {
    Some(match code {
        67 => 0xff08,  // DEL (backspace)
        112 => 0xffff, // FORWARD_DEL
        66 | 160 => 0xff0d,
        61 => 0xff09,
        111 => 0xff1b,
        19 => 0xff52,
        20 => 0xff54,
        21 => 0xff51,
        22 => 0xff53,
        122 => 0xff50,
        123 => 0xff57,
        92 => 0xff55,
        93 => 0xff56,
        124 => 0xff63,
        131..=142 => 0xffbe + (code - 131) as u32, // F1..F12
        _ => return None,
    })
}

impl RemoteView {
    pub fn new(session: Arc<Session>, direct: bool, orientation: u8) -> RemoteView {
        java::set_orientation(orientation);
        RemoteView {
            session,
            tex: None,
            old_tex: Vec::new(),
            frame: 0,
            tex_gen: u64::MAX,
            cursor_tex: None,
            scale_mode: None,
            ppp: 1.0,
            zoom: 1.0,
            center: Pos2::ZERO,
            centered: false,
            cursor: Pos2::ZERO,
            buttons: 0,
            last_sent: (u16::MAX, u16::MAX, 0),
            ui_touches: Vec::new(),
            fingers: HashMap::new(),
            one: None,
            two: None,
            three: None,
            wait_all_up: false,
            last_tap: None,
            scroll_acc: 0.0,
            direct,
            mode: Mode::Mouse,
            options_open: false,
            orientation,
            bar_open: false,
            bar_rect: None,
            keys_rect: None,
            mouse_rect: None,
            fb_size: (1.0, 1.0),
            bar_buttons: 0,
            ctrl: false,
            alt: false,
            user: String::new(),
            pass: String::new(),
            unmuted_audio: None,
            note_open: false,
            confirm_close: false,
            close_now: false,
        }
    }

    pub fn connected(&self) -> bool {
        matches!(*self.session.state.lock(), State::Connected)
    }

    /// The Back button: close an open page, else disconnect.
    pub fn back(&mut self) {
        if self.note_open {
            self.note_open = false;
        } else if self.options_open {
            self.options_open = false;
        } else {
            // leave the session: back to the computer list
            self.session.answer(Answer::Cancel);
            self.close_now = true;
        }
    }

    // ---- keyboard -----------------------------------------------------------

    fn tap_key(&self, keysym: u32) {
        let s = &self.session;
        s.key(true, keysym, 0);
        s.key(false, keysym, 0);
    }

    fn with_mods(&mut self, f: impl FnOnce(&Self)) {
        let (ctrl, alt) = (self.ctrl, self.alt);
        if ctrl {
            self.session.key(true, 0xffe3, 0x1d);
        }
        if alt {
            self.session.key(true, 0xffe9, 0x38);
        }
        f(self);
        if alt {
            self.session.key(false, 0xffe9, 0x38);
        }
        if ctrl {
            self.session.key(false, 0xffe3, 0x1d);
        }
        self.ctrl = false;
        self.alt = false;
    }

    pub fn type_text(&mut self, text: &str) {
        for c in text.chars() {
            self.with_mods(|v| {
                let shift = needs_shift(c) && !v.ctrl && !v.alt;
                if shift {
                    v.session.key(true, SHIFT.0, SHIFT.1);
                }
                v.tap_key(char_keysym(c));
                if shift {
                    v.session.key(false, SHIFT.0, SHIFT.1);
                }
            });
        }
    }

    /// A key event from the on-screen keyboard.
    pub fn android_key(&mut self, code: i32, down: bool, ch: Option<char>) {
        if let Some(k) = android_keysym(code) {
            if down {
                self.with_mods(|v| v.tap_key(k));
            }
        } else if let (true, Some(c)) = (down, ch) {
            self.type_text(&c.to_string());
        }
    }

    // ---- geometry -----------------------------------------------------------

    fn scale(&self, view: Rect, fw: f32, fh: f32) -> Vec2 {
        let (sx, sy) = self.scale_mode.unwrap_or(ScaleMode::KeepRatio).scales(view.width(), view.height(), fw, fh, self.ppp);
        vec2(sx, sy) * self.zoom
    }

    fn to_screen(&self, view: Rect, scale: Vec2, p: Pos2) -> Pos2 {
        view.center() + (p - self.center) * scale
    }

    fn to_remote(&self, view: Rect, scale: Vec2, s: Pos2) -> Pos2 {
        self.center + (s - view.center()) / scale
    }

    fn clamp_center(&mut self, view: Rect, scale: Vec2, fw: f32, fh: f32) {
        let hw = view.width() / (2.0 * scale.x);
        let hh = view.height() / (2.0 * scale.y);
        self.center.x = if fw <= 2.0 * hw { fw / 2.0 } else { self.center.x.clamp(hw, fw - hw) };
        self.center.y = if fh <= 2.0 * hh { fh / 2.0 } else { self.center.y.clamp(hh, fh - hh) };
    }

    /// Touchpad mode: keep the pointer on screen.
    fn follow_cursor(&mut self, view: Rect, scale: Vec2) {
        let hw = view.width() / (2.0 * scale.x) * 0.85;
        let hh = view.height() / (2.0 * scale.y) * 0.85;
        let d = self.cursor - self.center;
        if d.x > hw {
            self.center.x = self.cursor.x - hw;
        } else if d.x < -hw {
            self.center.x = self.cursor.x + hw;
        }
        if d.y > hh {
            self.center.y = self.cursor.y - hh;
        } else if d.y < -hh {
            self.center.y = self.cursor.y + hh;
        }
    }

    fn zoom_at(&mut self, view: Rect, fw: f32, fh: f32, focus: Pos2, factor: f32) {
        let before = self.scale(view, fw, fh);
        let anchor = self.to_remote(view, before, focus);
        self.zoom = (self.zoom * factor).clamp(1.0, 8.0);
        let after = self.scale(view, fw, fh);
        self.center = anchor - (focus - view.center()) / after;
    }

    fn send_pointer(&mut self, fw: f32, fh: f32) {
        let x = self.cursor.x.clamp(0.0, fw - 1.0) as u16;
        let y = self.cursor.y.clamp(0.0, fh - 1.0) as u16;
        if (x, y, self.buttons) != self.last_sent {
            self.session.pointer(x, y, self.buttons);
            self.last_sent = (x, y, self.buttons);
        }
    }

    fn click(&mut self, fw: f32, fh: f32, button: u8) {
        self.buttons |= button;
        self.send_pointer(fw, fh);
        self.buttons &= !button;
        self.send_pointer(fw, fh);
    }

    fn wheel(&mut self, fw: f32, fh: f32, mask: u8) {
        let x = self.cursor.x.clamp(0.0, fw - 1.0) as u16;
        let y = self.cursor.y.clamp(0.0, fh - 1.0) as u16;
        self.session.pointer(x, y, self.buttons | mask);
        self.session.pointer(x, y, self.buttons);
    }

    // ---- touch ----------------------------------------------------------------

    fn on_ui(&self, ctx: &egui::Context, p: Pos2) -> bool {
        let in_rect = |r: Option<Rect>| r.map(|r| r.contains(p)).unwrap_or(false);
        // (an open dropdown also keeps the tap that closes it)
        ctx.memory(|m| m.any_popup_open()) || in_rect(self.bar_rect) || in_rect(self.keys_rect) || in_rect(self.mouse_rect) || ctx.layer_id_at(p).map(|l| l.order != egui::Order::Background).unwrap_or(false)
    }

    fn touches(&mut self, ctx: &egui::Context, view: Rect, fw: f32, fh: f32) {
        let view_only = self.mode == Mode::View;
        let events: Vec<egui::Event> = ctx.input(|i| i.events.clone());
        for ev in events {
            let egui::Event::Touch { id, phase, pos, .. } = ev else { continue };
            let id = id.0;
            let scale = self.scale(view, fw, fh);
            match phase {
                egui::TouchPhase::Start => {
                    if self.on_ui(ctx, pos) {
                        self.ui_touches.push(id);
                        continue;
                    }
                    self.fingers.insert(id, pos);
                    match self.fingers.len() {
                        1 if !self.wait_all_up => {
                            let double = !view_only && self.last_tap.map(|(t, p)| t.elapsed() < Duration::from_millis(350) && (p - pos).length() < 60.0).unwrap_or(false);
                            if self.direct && !view_only {
                                self.cursor = self.to_remote(view, scale, pos);
                                self.send_pointer(fw, fh);
                            }
                            if double {
                                self.buttons |= 1;
                                self.send_pointer(fw, fh);
                            }
                            self.one = Some(OneFinger { id, start: pos, last: pos, t0: Instant::now(), moved: false, dragging: double, long_fired: false });
                        }
                        2 => {
                            if let Some(o) = self.one.take() {
                                if o.dragging {
                                    self.buttons &= !1;
                                    self.send_pointer(fw, fh);
                                }
                            }
                            let (c, d) = self.pair();
                            self.two = Some(TwoFinger { dist0: d, last_dist: d, last_center: c, t0: Instant::now(), moved: false, zooming: false });
                            self.wait_all_up = true;
                        }
                        3 => {
                            self.two = None;
                            self.three = Some(Instant::now());
                        }
                        _ => {}
                    }
                }
                egui::TouchPhase::Move => {
                    if !self.fingers.contains_key(&id) {
                        continue;
                    }
                    self.fingers.insert(id, pos);
                    if let Some(mut o) = self.one.take() {
                        if o.id == id {
                            let delta = pos - o.last;
                            o.last = pos;
                            if (pos - o.start).length() > TAP_SLOP {
                                o.moved = true;
                            }
                            if o.moved && view_only {
                                self.center -= delta / scale;
                            } else if o.moved {
                                if self.direct {
                                    if !o.dragging && !o.long_fired {
                                        o.dragging = true;
                                        self.buttons |= 1;
                                        self.send_pointer(fw, fh);
                                    }
                                    self.cursor = self.to_remote(view, scale, pos);
                                } else {
                                    // a little acceleration for long swipes
                                    let speed = 1.0 + (delta.length() / 30.0).min(1.5);
                                    self.cursor += delta * speed / scale;
                                    self.cursor = pos2(self.cursor.x.clamp(0.0, fw - 1.0), self.cursor.y.clamp(0.0, fh - 1.0));
                                    self.follow_cursor(view, scale);
                                }
                                self.send_pointer(fw, fh);
                            }
                        }
                        self.one = Some(o);
                    }
                    if self.fingers.len() == 2 {
                        let (c, d) = self.pair();
                        if let Some(mut t) = self.two.take() {
                            let moved = c - t.last_center;
                            if (d - t.dist0).abs() > 40.0 {
                                t.zooming = true;
                            }
                            if moved.length() > 2.0 || (d - t.dist0).abs() > TAP_SLOP {
                                t.moved = true;
                            }
                            if t.zooming && t.last_dist > 0.0 {
                                self.zoom_at(view, fw, fh, c, d / t.last_dist);
                            }
                            let scale = self.scale(view, fw, fh);
                            // two fingers pan whenever part of the screen is out of view
                            let overflow = fw * scale.x > view.width() + 1.0 || fh * scale.y > view.height() + 1.0;
                            if t.zooming || view_only || (self.direct && overflow) {
                                self.center -= moved / scale; // pan with the fingers
                            } else {
                                self.scroll_acc += moved.y;
                                while self.scroll_acc > SCROLL_STEP {
                                    self.wheel(fw, fh, 8);
                                    self.scroll_acc -= SCROLL_STEP;
                                }
                                while self.scroll_acc < -SCROLL_STEP {
                                    self.wheel(fw, fh, 16);
                                    self.scroll_acc += SCROLL_STEP;
                                }
                            }
                            t.last_center = c;
                            t.last_dist = d;
                            self.two = Some(t);
                        }
                    }
                }
                egui::TouchPhase::End | egui::TouchPhase::Cancel => {
                    if let Some(i) = self.ui_touches.iter().position(|t| *t == id) {
                        self.ui_touches.remove(i);
                        continue;
                    }
                    if self.fingers.remove(&id).is_none() {
                        continue;
                    }
                    let cancel = phase == egui::TouchPhase::Cancel;
                    if let Some(o) = self.one.take() {
                        if o.id == id {
                            let tap = !o.moved && !o.long_fired && o.t0.elapsed() < TAP_TIME && !cancel && !view_only;
                            if o.dragging {
                                self.buttons &= !1;
                                self.send_pointer(fw, fh);
                                self.last_tap = None;
                            } else if tap {
                                self.click(fw, fh, 1);
                                self.last_tap = Some((Instant::now(), pos));
                            }
                        } else {
                            self.one = Some(o);
                        }
                    }
                    if let Some(t) = self.two.take() {
                        if !t.moved && t.t0.elapsed() < TAP_TIME && !cancel && self.three.is_none() && !view_only {
                            if self.direct {
                                self.cursor = self.to_remote(view, scale, t.last_center);
                            }
                            self.click(fw, fh, 4);
                        }
                    }
                    if self.fingers.is_empty() {
                        if let Some(t) = self.three.take() {
                            if t.elapsed() < Duration::from_millis(500) && !cancel {
                                let on = !self.keyboard_on();
                                self.set_keyboard(on);
                            }
                        }
                        self.wait_all_up = false;
                        self.scroll_acc = 0.0;
                    }
                }
            }
        }
        // long press: right click
        if let Some(o) = self.one.as_mut() {
            if !view_only && !o.moved && !o.dragging && !o.long_fired && o.t0.elapsed() >= LONG_PRESS {
                o.long_fired = true;
                self.click(fw, fh, 4);
            } else if !o.long_fired {
                ctx.request_repaint_after(Duration::from_millis(50));
            }
        }
        let scale = self.scale(view, fw, fh);
        self.clamp_center(view, scale, fw, fh);
    }

    fn pair(&self) -> (Pos2, f32) {
        let mut it = self.fingers.values();
        let (a, b) = match (it.next(), it.next()) {
            (Some(a), Some(b)) => (*a, *b),
            _ => return (Pos2::ZERO, 0.0),
        };
        (pos2((a.x + b.x) / 2.0, (a.y + b.y) / 2.0), (a - b).length())
    }

    pub fn set_keyboard(&mut self, on: bool) {
        if on {
            self.mode = Mode::Keyboard;
        } else if self.mode == Mode::Keyboard {
            self.mode = Mode::Mouse;
        }
    }

    pub fn keyboard_on(&self) -> bool {
        self.mode == Mode::Keyboard
    }

    // ---- drawing ------------------------------------------------------------

    fn upload(&mut self, ctx: &egui::Context) {
        self.frame += 1;
        let frame = self.frame;
        self.old_tex.retain(|(_, f)| frame < f + 3);
        let Some(mut fb) = self.session.fb.try_lock() else { return };
        if fb.width == 0 || fb.height == 0 {
            return;
        }
        if self.tex.is_none() || self.tex_gen != fb.generation {
            let img = to_color_image(&fb, 0, 0, fb.width, fb.height);
            if let Some(old) = self.tex.replace(ctx.load_texture(format!("remote-{}", self.session.id), img, TextureOptions::LINEAR)) {
                self.old_tex.push((old, frame));
            }
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

    pub fn show(&mut self, ctx: &egui::Context, core: &Arc<Core>) -> Outcome {
        if self.scale_mode.is_none() {
            self.scale_mode = Some(core.cfg.read().viewer.scale());
        }
        let s = self.session.clone();
        self.upload(ctx);
        let state = s.state.lock().clone();
        let mut close = self.close_now;
        egui::CentralPanel::default().frame(egui::Frame::none().fill(Color32::from_gray(16))).show(ctx, |ui| {
            let view = ui.max_rect();
            match &state {
                State::Connected => self.remote(ui, ctx, view),
                State::Connecting(msg) => {
                    ui.centered_and_justified(|ui| {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(RichText::new(msg).color(Color32::LIGHT_GRAY));
                        });
                    });
                }
                State::Closed(msg) => {
                    ui.vertical_centered(|ui| {
                        ui.add_space(view.height() / 3.0);
                        ui.label(RichText::new("Connection closed").size(22.0).color(Color32::LIGHT_GRAY));
                        ui.label(RichText::new(msg).color(Color32::GRAY));
                        ui.add_space(12.0);
                        if ui.button("  Back  ").clicked() {
                            close = true;
                        }
                    });
                }
                _ => {}
            }
        });
        match &state {
            State::VerifyFingerprint { fingerprint, previous } => {
                let (fingerprint, changed) = (fingerprint.clone(), previous.is_some());
                dialog(ctx, "Verify the remote computer", |ui| {
                    if changed {
                        ui.colored_label(Color32::from_rgb(0xe0, 0x50, 0x50), "WARNING: this computer's fingerprint has CHANGED since your last connection. Someone may be intercepting it - or PortlessVNC was reinstalled there.");
                    } else {
                        ui.label("First connection to this computer. Check that this matches the fingerprint shown on it:");
                    }
                    ui.add_space(6.0);
                    ui.label(RichText::new(crate::util::short_fingerprint(&fingerprint)).monospace().size(20.0).strong());
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
                let (need_user, message) = (*username, message.clone());
                dialog(ctx, "Sign in", |ui| {
                    ui.label(message);
                    if need_user {
                        ui.add(egui::TextEdit::singleline(&mut self.user).hint_text("Username").desired_width(f32::INFINITY));
                    }
                    let r = ui.add(egui::TextEdit::singleline(&mut self.pass).password(true).hint_text("Password (or one-time password)").desired_width(f32::INFINITY));
                    let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("Connect").strong()).clicked() || enter {
                            s.answer(Answer::Credentials(self.user.clone(), std::mem::take(&mut self.pass)));
                        }
                        if ui.button("Cancel").clicked() {
                            s.answer(Answer::Cancel);
                        }
                    });
                });
            }
            _ => {}
        }
        if matches!(state, State::Connected) {
            self.bar(ctx, core, &mut close);
            if self.keyboard_on() {
                self.extra_keys(ctx);
            } else {
                self.keys_rect = None;
            }
            if self.mode != Mode::View {
                self.mouse_buttons(ctx, core);
            } else {
                self.mouse_rect = None;
            }
            self.shared_text(ctx, core);
        }
        if self.confirm_close {
            dialog(ctx, "Disconnect?", |ui| {
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Disconnect").strong()).clicked() {
                        close = true;
                    }
                    if ui.button("Stay").clicked() {
                        self.confirm_close = false;
                    }
                });
            });
        }
        if close {
            self.session.close();
            return Outcome::Close;
        }
        Outcome::Keep
    }

    fn remote(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, view: Rect) {
        let Some(tex) = self.tex.clone() else { return };
        let [w, h] = tex.size();
        let (fw, fh) = (w as f32, h as f32);
        self.fb_size = (fw, fh);
        self.ppp = ctx.pixels_per_point();
        if !self.centered {
            self.center = pos2(fw / 2.0, fh / 2.0);
            self.cursor = self.center;
            self.centered = true;
        }
        self.touches(ctx, view, fw, fh);
        self.hardware_keys(ctx);
        let scale = self.scale(view, fw, fh);
        let img = Rect::from_min_max(self.to_screen(view, scale, Pos2::ZERO), self.to_screen(view, scale, pos2(fw, fh)));
        ui.painter().image(tex.id(), img, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);

        // the pointer, drawn locally so it never lags
        let at = self.to_screen(view, scale, self.cursor);
        let cur = self.session.cursor.lock().clone();
        let cs = scale.x.min(scale.y).clamp(0.8, 2.5);
        match cur {
            Some((c, gen)) if c.width > 0 && c.height > 0 => {
                if self.cursor_tex.as_ref().map(|t| t.1) != Some(gen) {
                    let pixels = c.rgba.iter().map(|&p| Color32::from_rgba_unmultiplied(p as u8, (p >> 8) as u8, (p >> 16) as u8, (p >> 24) as u8)).collect();
                    let img = egui::ColorImage { size: [c.width, c.height], pixels };
                    if let Some((old, _, _)) = self.cursor_tex.replace((ctx.load_texture(format!("cursor-{}", self.session.id), img, TextureOptions::NEAREST), gen, (c.hot_x, c.hot_y))) {
                        self.old_tex.push((old, self.frame));
                    }
                }
                if let Some((t, _, (hx, hy))) = &self.cursor_tex {
                    let min = at - vec2(*hx as f32, *hy as f32) * cs;
                    ui.painter().image(t.id(), Rect::from_min_size(min, t.size_vec2() * cs), Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
                }
            }
            _ => {
                ui.painter().circle(at, 6.0, Color32::from_white_alpha(180), egui::Stroke::new(1.5, Color32::BLACK));
            }
        }
    }

    /// A hardware (Bluetooth/USB) keyboard: its keys arrive as egui events.
    fn hardware_keys(&mut self, ctx: &egui::Context) {
        if ctx.wants_keyboard_input() || self.mode == Mode::View || self.options_open || ctx.memory(|m| m.any_popup_open()) {
            return;
        }
        let (events, mods) = ctx.input(|i| (i.events.clone(), i.modifiers));
        for ev in events {
            match ev {
                egui::Event::Text(t) => self.type_text(&t),
                egui::Event::Key { key, pressed: true, .. } => {
                    let k = egui_keysym(key);
                    // printable keys come as Text unless Ctrl/Alt is held
                    let printable = k.map(|k| (0x20..0x7f).contains(&k)).unwrap_or(false);
                    if let Some(k) = k.filter(|_| !printable || mods.ctrl || mods.alt) {
                        self.ctrl |= mods.ctrl;
                        self.alt |= mods.alt;
                        self.with_mods(|v| v.tap_key(k));
                    }
                }
                _ => {}
            }
        }
    }

    /// The tab: a small handle at the top that opens one row of big buttons
    /// (rotate, mouse / keyboard / view, mute, more).
    fn bar(&mut self, ctx: &egui::Context, core: &Arc<Core>, close: &mut bool) {
        let s = self.session.clone();
        let big = |t: &str| egui::Button::new(RichText::new(t).size(17.0)).min_size(vec2(64.0, 46.0));
        let resp = egui::Area::new(egui::Id::new(("bar", s.id))).order(egui::Order::Foreground).anchor(egui::Align2::CENTER_TOP, [0.0, 0.0]).show(ctx, |ui| {
            egui::Frame::none().fill(Color32::from_rgba_unmultiplied(28, 28, 28, 235)).rounding(egui::Rounding { nw: 0.0, ne: 0.0, sw: 12.0, se: 12.0 }).inner_margin(egui::Margin::symmetric(10.0, 6.0)).show(ui, |ui| {
                if !self.bar_open {
                    // the handle: wide enough to hit easily
                    if ui.add(egui::Button::new(RichText::new("Menu").size(16.0).color(Color32::LIGHT_GRAY)).frame(false).min_size(vec2(90.0, 26.0))).clicked() {
                        self.bar_open = true;
                    }
                    return;
                }
                ui.set_max_width(ctx.screen_rect().width() - 12.0);
                ui.horizontal_wrapped(|ui| {
                    let rot = ["Rotate: auto", "Rotate: wide", "Rotate: tall"][self.orientation.min(2) as usize];
                    if ui.add(big(rot)).clicked() {
                        self.orientation = (self.orientation + 1) % 3;
                        java::set_orientation(self.orientation);
                        core.cfg.write().viewer.orientation = self.orientation;
                        core.save_config();
                    }
                    // each tap moves to the next size mode
                    let cur = self.scale_mode.unwrap_or(ScaleMode::KeepRatio);
                    if ui.add(big(&format!("Size: {}", cur.short_label()))).clicked() {
                        let i = ScaleMode::ALL.iter().position(|m| *m == cur).unwrap_or(0);
                        self.scale_mode = Some(ScaleMode::ALL[(i + 1) % ScaleMode::ALL.len()]);
                        self.zoom = 1.0;
                    }
                    ui.separator();
                    for (m, label) in [(Mode::Mouse, "Mouse"), (Mode::Keyboard, "Keyboard"), (Mode::View, "View")] {
                        if ui.add(big(label).selected(self.mode == m)).clicked() {
                            self.mode = m;
                            if m != Mode::Mouse {
                                self.bar_open = false; // get out of the way
                            }
                        }
                    }
                    ui.separator();
                    let native = s.native.load(Ordering::Relaxed);
                    let muted = *s.audio.lock() == AudioMode::Off;
                    if ui.add_enabled(native, big(if muted { "Unmute" } else { "Mute" })).clicked() {
                        if muted {
                            let back = self.unmuted_audio.take().unwrap_or_else(|| match core.cfg.read().viewer.audio {
                                AudioMode::Off => AudioMode::Auto,
                                a => a,
                            });
                            s.set_audio(back);
                        } else {
                            self.unmuted_audio = Some(*s.audio.lock());
                            s.set_audio(AudioMode::Off);
                        }
                    }
                    if ui.add(big("More")).clicked() {
                        self.options_open = true;
                        self.bar_open = false;
                    }
                    if ui.add(big("Hide")).clicked() {
                        self.bar_open = false;
                    }
                });
            });
        });
        self.bar_rect = Some(resp.response.rect.expand(6.0));
        self.options(ctx, core, close);
    }

    /// Everything else, on its own page.
    fn options(&mut self, ctx: &egui::Context, core: &Arc<Core>, close: &mut bool) {
        if !self.options_open {
            return;
        }
        let s = self.session.clone();
        let screen = ctx.screen_rect();
        let mut open = true;
        egui::Window::new("Options")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .fixed_size(vec2((screen.width() - 24.0).min(560.0), 0.0))
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().max_height(screen.height() * 0.75).show(ui, |ui| {
                    let rtt = s.rtt_ms.load(Ordering::Relaxed);
                    let route = if s.via_vpn.load(Ordering::Relaxed) { "via VPN" } else { "direct" };
                    let kind = if s.native.load(Ordering::Relaxed) { "PortlessVNC" } else { "standard VNC" };
                    ui.label(RichText::new(format!("{} - {route} - {kind}{}", s.address, if rtt > 0 { format!(" - {rtt} ms") } else { String::new() })).small().weak());
                    ui.add_space(4.0);
                    ui.label(RichText::new("Send keys").strong());
                    ui.horizontal_wrapped(|ui| {
                        for (label, combo, _) in KEY_COMBOS {
                            if ui.button(*label).clicked() {
                                s.key_combo(combo);
                            }
                        }
                    });
                    ui.separator();
                    ui.label(RichText::new("Touch").strong());
                    let before = self.direct;
                    ui.radio_value(&mut self.direct, false, "Touchpad - drag moves the pointer, tap clicks");
                    ui.radio_value(&mut self.direct, true, "Direct - tap where you want to click");
                    if self.direct != before {
                        core.cfg.write().viewer.touch_direct = self.direct;
                        core.save_config();
                    }
                    ui.label(RichText::new("Screen size").strong());
                    let cur = self.scale_mode.unwrap_or(ScaleMode::KeepRatio);
                    egui::ComboBox::from_id_salt(("scale", s.id)).selected_text(cur.label()).show_ui(ui, |ui| {
                        for m in ScaleMode::ALL {
                            if ui.selectable_label(cur == m, m.label()).clicked() {
                                self.scale_mode = Some(m);
                                self.zoom = 1.0;
                            }
                        }
                    });
                    if ui.add_enabled(self.zoom > 1.0, egui::Button::new("Undo zoom")).clicked() {
                        self.zoom = 1.0;
                    }
                    ui.separator();
                    ui.label(RichText::new("Picture quality").strong());
                    let q = *s.quality.lock();
                    egui::ComboBox::from_id_salt(("quality", s.id)).selected_text(q.label()).show_ui(ui, |ui| {
                        for m in QualityMode::ALL {
                            if ui.selectable_label(q == m, m.label()).clicked() {
                                s.set_quality(m);
                            }
                        }
                    });
                    if s.native.load(Ordering::Relaxed) {
                        ui.label(RichText::new("Sound").strong());
                        let a = *s.audio.lock();
                        egui::ComboBox::from_id_salt(("audio", s.id)).selected_text(a.label()).show_ui(ui, |ui| {
                            for m in AudioMode::PRESETS {
                                if ui.selectable_label(a == m, m.label()).clicked() {
                                    s.set_audio(m);
                                }
                            }
                        });
                        ui.separator();
                        let label = if core.hub.note_unread() { "Shared text *" } else { "Shared text" };
                        if ui.button(label).clicked() {
                            self.note_open = true;
                            self.options_open = false;
                        }
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("Disconnect").color(Color32::from_rgb(0xf0, 0x70, 0x60))).clicked() {
                            *close = true;
                        }
                        if ui.button("Close").clicked() {
                            self.options_open = false;
                        }
                    });
                });
            });
        if !open {
            self.options_open = false;
        }
    }

    /// Keys the phone keyboard lacks, shown above it: sticky Ctrl/Alt, the
    /// usual navigation keys and one Combos key with the common shortcuts.
    fn extra_keys(&mut self, ctx: &egui::Context) {
        let resp = egui::TopBottomPanel::bottom(egui::Id::new(("extra-keys", self.session.id))).frame(egui::Frame::none().fill(Color32::from_gray(36)).inner_margin(4.0)).show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                let key = |t: &str| egui::Button::new(RichText::new(t).size(16.0)).min_size(vec2(44.0, 40.0));
                if ui.add(key("Ctrl").selected(self.ctrl)).clicked() {
                    self.ctrl = !self.ctrl;
                }
                if ui.add(key("Alt").selected(self.alt)).clicked() {
                    self.alt = !self.alt;
                }
                for (label, k) in [("Esc", 0xff1bu32), ("Tab", 0xff09), ("<", 0xff51), ("^", 0xff52), ("v", 0xff54), (">", 0xff53)] {
                    if ui.add(key(label)).clicked() {
                        self.with_mods(|v| v.tap_key(k));
                    }
                }
                let s = self.session.clone();
                ui.menu_button(RichText::new("Combos").size(16.0), |ui| {
                    const C: (u32, u32) = (0xffe3, 0x1d);
                    const A: (u32, u32) = (0xffe9, 0x38);
                    let combos: &[(&str, &[(u32, u32)])] = &[
                        ("Copy  (Ctrl+C)", &[C, (0x63, 0x2e)]),
                        ("Paste  (Ctrl+V)", &[C, (0x76, 0x2f)]),
                        ("Cut  (Ctrl+X)", &[C, (0x78, 0x2d)]),
                        ("Undo  (Ctrl+Z)", &[C, (0x7a, 0x2c)]),
                        ("Select all  (Ctrl+A)", &[C, (0x61, 0x1e)]),
                        ("Save  (Ctrl+S)", &[C, (0x73, 0x1f)]),
                        ("Alt+Tab", &[A, (0xff09, 0x0f)]),
                        ("Alt+F4", &[A, (0xffc1, 0x3e)]),
                        ("Ctrl+Alt+Del", &[C, A, (0xffff, 0xd3)]),
                        ("Win", &[crate::keys::WIN]),
                        ("Win+R", &[crate::keys::WIN, (0x72, 0x13)]),
                        ("Delete", &[(0xffff, 0xd3)]),
                        ("Home", &[(0xff50, 0xc7)]),
                        ("End", &[(0xff57, 0xcf)]),
                        ("Page up", &[(0xff55, 0xc9)]),
                        ("Page down", &[(0xff56, 0xd1)]),
                    ];
                    for (label, keys) in combos {
                        if ui.button(*label).clicked() {
                            s.key_combo(keys);
                            ui.close_menu();
                        }
                    }
                    ui.menu_button("F1 - F12", |ui| {
                        for n in 0..12u32 {
                            if ui.button(format!("F{}", n + 1)).clicked() {
                                s.key_combo(&[(0xffbe + n, 0)]);
                                ui.close_menu();
                            }
                        }
                    });
                });
                if ui.add(key("Hide")).clicked() {
                    self.set_keyboard(false);
                }
            });
        });
        self.keys_rect = Some(resp.response.rect);
    }
    /// Left / right mouse buttons at the bottom (above the keyboard's keys):
    /// held while pressed, so one finger can hold Left while another drags.
    fn mouse_buttons(&mut self, ctx: &egui::Context, core: &Arc<Core>) {
        let (fw, fh) = self.fb_size;
        let mut held = 0u8;
        let mut toggle = false;
        if !core.cfg.read().viewer.mouse_bar {
            // hidden: a small tab in the corner brings it back
            let resp = egui::Area::new(egui::Id::new(("mouse-tab", self.session.id))).order(egui::Order::Foreground).anchor(egui::Align2::RIGHT_BOTTOM, [-6.0, -6.0]).show(ctx, |ui| {
                if ui.add(egui::Button::new(RichText::new("Mouse").size(14.0)).fill(Color32::from_rgba_unmultiplied(40, 40, 40, 200))).clicked() {
                    toggle = true;
                }
            });
            self.mouse_rect = Some(resp.response.rect.expand(6.0));
        } else {
            let resp = egui::TopBottomPanel::bottom(egui::Id::new(("mouse-buttons", self.session.id))).frame(egui::Frame::none().fill(Color32::from_rgba_unmultiplied(20, 20, 20, 200)).inner_margin(4.0)).show_separator_line(false).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let w = ((ui.available_width() - 70.0) / 2.0 - ui.spacing().item_spacing.x).max(60.0);
                    for (label, bit) in [("Left", 1u8), ("Right", 4u8)] {
                        let down = self.bar_buttons & bit != 0;
                        let b = egui::Button::new(RichText::new(label).size(16.0)).min_size(vec2(w, 44.0)).fill(if down { ACCENT_DIM } else { Color32::from_gray(48) });
                        if ui.add(b).is_pointer_button_down_on() {
                            held |= bit;
                        }
                    }
                    if ui.add(egui::Button::new("Hide").min_size(vec2(60.0, 44.0))).clicked() {
                        toggle = true;
                    }
                });
            });
            self.mouse_rect = Some(resp.response.rect);
        }
        if toggle {
            let mut c = core.cfg.write();
            c.viewer.mouse_bar = !c.viewer.mouse_bar;
            drop(c);
            core.save_config();
        }
        if held != self.bar_buttons {
            self.buttons = (self.buttons & !self.bar_buttons) | held;
            self.bar_buttons = held;
            self.send_pointer(fw, fh);
        }
        if held != 0 {
            ctx.request_repaint();
        }
    }

    fn shared_text(&mut self, ctx: &egui::Context, core: &Arc<Core>) {
        if !self.note_open {
            return;
        }
        let hub = core.hub.clone();
        hub.note_mark_read();
        let mut open = true;
        egui::Window::new("Shared text").open(&mut open).collapsible(false).default_width(ctx.screen_rect().width() * 0.85).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
            let mut text = hub.note_text();
            egui::ScrollArea::vertical().max_height(ctx.screen_rect().height() * 0.4).show(ui, |ui| {
                if ui.add(egui::TextEdit::multiline(&mut text).desired_width(f32::INFINITY).desired_rows(6)).changed() {
                    hub.note_local_edit(text.clone());
                }
            });
            ui.horizontal(|ui| {
                if ui.button("Copy to phone").clicked() {
                    java::set_clipboard(&text);
                    java::toast("Copied");
                }
                if ui.button("Type it").on_hover_text("Types the text on the remote computer").clicked() {
                    self.type_text(&text);
                }
                if ui.button("Clear").clicked() {
                    hub.note_local_edit(String::new());
                }
            });
        });
        if !open {
            self.note_open = false;
        }
    }
}

/// A centred, touch-sized dialog.
pub fn dialog(ctx: &egui::Context, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    let w = (ctx.screen_rect().width() - 32.0).min(520.0);
    egui::Window::new(title).collapsible(false).resizable(false).fixed_size(Vec2::new(w, 0.0)).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, add);
}
