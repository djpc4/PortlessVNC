//! Shared by the desktop and Android viewers: key combinations, egui key
//! to X11 keysym mapping and framebuffer upload.

use eframe::egui::{self, Color32};

/// After a menu closes, mouse and keys stay local until this long has passed with
/// no further menu use or clicks.
pub const INPUT_RESUME_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

/// A small note that input is being held back, so the session doesn't look frozen.
pub fn paint_input_paused(painter: &egui::Painter, top_center: egui::Pos2) {
    let galley = painter.layout_no_wrap("Input paused".to_string(), egui::FontId::proportional(14.0), Color32::WHITE);
    let rect = egui::Rect::from_center_size(top_center + egui::vec2(0.0, 28.0), galley.size() + egui::vec2(16.0, 8.0));
    painter.rect_filled(rect, 6.0, Color32::from_black_alpha(190));
    painter.galley(rect.min + egui::vec2(8.0, 4.0), galley, Color32::WHITE);
}

pub fn to_color_image(fb: &crate::rfb::decode::FrameBuffer, x0: usize, y0: usize, x1: usize, y1: usize) -> egui::ColorImage {
    let (w, h) = (x1 - x0, y1 - y0);
    let mut pixels = Vec::with_capacity(w * h);
    for y in y0..y1 {
        let row = &fb.pixels[y * fb.width + x0..y * fb.width + x1];
        pixels.extend(row.iter().map(|&p| Color32::from_rgba_premultiplied(p as u8, (p >> 8) as u8, (p >> 16) as u8, 255)));
    }
    egui::ColorImage { size: [w, h], pixels }
}

// keysym / XT scancode pairs (extended keys have 0x80 set)
pub const CTRL: (u32, u32) = (0xffe3, 0x1d);
pub const ALT: (u32, u32) = (0xffe9, 0x38);
pub const SHIFT: (u32, u32) = (0xffe1, 0x2a);
pub const WIN: (u32, u32) = (0xffeb, 0xdb);

/// Key combinations offered in the session's "Keys" menu.
pub const KEY_COMBOS: &[(&str, &[(u32, u32)], &str)] = &[
    ("Ctrl+Alt+Del", &[CTRL, ALT, (0xffff, 0xd3)], "Windows only accepts this from a service; works with Linux and other servers"),
    ("Ctrl+Shift+Esc  (Task Manager)", &[CTRL, SHIFT, (0xff1b, 0x01)], ""),
    ("Alt+Tab", &[ALT, (0xff09, 0x0f)], ""),
    ("Alt+F4", &[ALT, (0xffc1, 0x3e)], ""),
    ("Win  (Start menu)", &[WIN], ""),
    ("Win+R  (Run)", &[WIN, (0x72, 0x13)], ""),
    ("Win+E  (Explorer)", &[WIN, (0x65, 0x12)], ""),
    ("Win+D  (show desktop)", &[WIN, (0x64, 0x20)], ""),
    ("Ctrl+Esc", &[CTRL, (0xff1b, 0x01)], ""),
    ("PrintScreen", &[(0xff61, 0xb7)], ""),
    ("Alt+PrintScreen", &[ALT, (0xff61, 0xb7)], ""),
];

/// X11 keysym for an egui key (base, unshifted symbol; the remote side
/// applies Shift itself).
pub fn egui_keysym(k: egui::Key) -> Option<u32> {
    use egui::Key::*;
    Some(match k {
        ArrowDown => 0xff54,
        ArrowLeft => 0xff51,
        ArrowRight => 0xff53,
        ArrowUp => 0xff52,
        Escape => 0xff1b,
        Tab => 0xff09,
        Backspace => 0xff08,
        Enter => 0xff0d,
        Space => 0x20,
        Insert => 0xff63,
        Delete => 0xffff,
        Home => 0xff50,
        End => 0xff57,
        PageUp => 0xff55,
        PageDown => 0xff56,
        Comma => b',' as u32,
        Backslash => b'\\' as u32,
        Slash => b'/' as u32,
        OpenBracket => b'[' as u32,
        CloseBracket => b']' as u32,
        Backtick => 0x60,
        Minus => b'-' as u32,
        Period => b'.' as u32,
        Equals | Plus => b'=' as u32,
        Semicolon | Colon => b';' as u32,
        Quote => b'\'' as u32,
        Questionmark => b'/' as u32,
        Pipe => b'\\' as u32,
        F1 => 0xffbe,
        F2 => 0xffbf,
        F3 => 0xffc0,
        F4 => 0xffc1,
        F5 => 0xffc2,
        F6 => 0xffc3,
        F7 => 0xffc4,
        F8 => 0xffc5,
        F9 => 0xffc6,
        F10 => 0xffc7,
        F11 => 0xffc8,
        F12 => 0xffc9,
        other => {
            let n = other.name();
            let ch = n.chars().next()?;
            if n.len() == 1 && ch.is_ascii_alphabetic() {
                ch.to_ascii_lowercase() as u32
            } else if let Some(d) = n.strip_prefix("Num").or(Some(n)).filter(|d| d.len() == 1 && d.chars().all(|c| c.is_ascii_digit())) {
                d.as_bytes()[0] as u32
            } else {
                return None;
            }
        }
    })
}

/// X11 keysym for a typed character (Latin-1 maps directly, the rest uses
/// the Unicode keysym range).
pub fn char_keysym(c: char) -> u32 {
    match c {
        '\n' | '\r' => 0xff0d,
        '\t' => 0xff09,
        '\u{8}' => 0xff08,
        c if (c as u32) < 0x100 => c as u32,
        c => 0x0100_0000 | c as u32,
    }
}

/// Characters typed with Shift on a US layout: sent with Shift held, since
/// many servers (Windows ones in particular) only type the base key.
pub fn needs_shift(c: char) -> bool {
    c.is_ascii_uppercase() || "~!@#$%^&*()_+{}|:\"<>?".contains(c)
}