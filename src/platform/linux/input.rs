//! X11 input injection with the XTest extension.

use parking_lot::Mutex;
use std::collections::HashMap;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::ConnectionExt as _;
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
const BUTTON_PRESS: u8 = 4;
const BUTTON_RELEASE: u8 = 5;
const MOTION_NOTIFY: u8 = 6;

struct Injector {
    conn: RustConnection,
    root: u32,
    /// keysym -> keycode from the current keyboard mapping
    keymap: HashMap<u32, u8>,
}

static INJ: Mutex<Option<Injector>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&Injector) -> R) -> Option<R> {
    let mut g = INJ.lock();
    if g.is_none() {
        let (conn, screen) = x11rb::connect(None).ok()?;
        let root = conn.setup().roots[screen].root;
        let (min, max) = (conn.setup().min_keycode, conn.setup().max_keycode);
        let mut keymap = HashMap::new();
        if let Ok(r) = conn.get_keyboard_mapping(min, max - min + 1).ok()?.reply() {
            let per = r.keysyms_per_keycode as usize;
            for (i, chunk) in r.keysyms.chunks(per.max(1)).enumerate() {
                for &ks in chunk.iter().take(2) {
                    if ks != 0 {
                        keymap.entry(ks).or_insert(min + i as u8);
                    }
                }
            }
        }
        *g = Some(Injector { conn, root, keymap });
    }
    g.as_ref().map(f)
}

fn fake(inj: &Injector, kind: u8, detail: u8, x: i16, y: i16) {
    let _ = inj.conn.xtest_fake_input(kind, detail, x11rb::CURRENT_TIME, if kind == MOTION_NOTIFY { inj.root } else { x11rb::NONE }, x, y, 0);
}

/// Pointer event in capture coordinates (`origin` = captured area's top-left).
pub fn pointer(x: i32, y: i32, origin: (i32, i32), mask: u8, prev: u8) {
    with(|inj| {
        fake(inj, MOTION_NOTIFY, 0, (origin.0 + x) as i16, (origin.1 + y) as i16);
        // RFB button bits -> X buttons: 1 left, 2 middle, 3 right, 4/5 wheel, 6/7 h-wheel
        for (bit, button) in [(1u8, 1u8), (2, 2), (4, 3)] {
            if (mask ^ prev) & bit != 0 {
                fake(inj, if mask & bit != 0 { BUTTON_PRESS } else { BUTTON_RELEASE }, button, 0, 0);
            }
        }
        let pressed = mask & !prev;
        for (bit, button) in [(8u8, 4u8), (16, 5), (32, 6), (64, 7)] {
            if pressed & bit != 0 {
                fake(inj, BUTTON_PRESS, button, 0, 0);
                fake(inj, BUTTON_RELEASE, button, 0, 0);
            }
        }
        let _ = inj.conn.flush();
    });
}

pub fn char_to_keysym(c: char) -> u32 {
    let u = c as u32;
    if (0x20..=0x7e).contains(&u) || (0xa0..=0xff).contains(&u) { u } else { 0x0100_0000 | u }
}

/// Inject an X11 keysym (standard RFB KeyEvent).
pub fn key_sym(down: bool, keysym: u32) {
    with(|inj| {
        let ks = if (0x41..=0x5a).contains(&keysym) { keysym + 0x20 } else { keysym }; // letters: base key
        let code = inj.keymap.get(&ks).or_else(|| inj.keymap.get(&keysym)).copied();
        match code {
            Some(c) => {
                fake(inj, if down { KEY_PRESS } else { KEY_RELEASE }, c, 0, 0);
                let _ = inj.conn.flush();
            }
            None => log::debug!("no X11 keycode for keysym {keysym:#x}"),
        }
    });
}

/// XT (set 1) scancode, QEMU encoding (0x80 = E0-extended) -> evdev code.
fn xt_to_evdev(xt: u32) -> Option<u8> {
    if xt & 0x80 == 0 {
        // set-1 make codes 1..0x58 match the Linux evdev KEY_* numbers
        return (1..=0x58).contains(&xt).then_some(xt as u8);
    }
    Some(match xt & 0x7f {
        0x1c => 96,  // KP Enter
        0x1d => 97,  // Right Ctrl
        0x35 => 98,  // KP /
        0x37 => 99,  // Print Screen
        0x38 => 100, // Right Alt / AltGr
        0x47 => 102, // Home
        0x48 => 103, // Up
        0x49 => 104, // Page Up
        0x4b => 105, // Left
        0x4d => 106, // Right
        0x4f => 107, // End
        0x50 => 108, // Down
        0x51 => 109, // Page Down
        0x52 => 110, // Insert
        0x53 => 111, // Delete
        0x5b => 125, // Left Super
        0x5c => 126, // Right Super
        0x5d => 127, // Menu
        _ => return None,
    })
}

/// Inject a hardware scancode (QEMU extended key event): X keycode = evdev + 8.
pub fn key_scancode(down: bool, xt: u32, keysym: u32) {
    match xt_to_evdev(xt) {
        Some(ev) => {
            with(|inj| {
                fake(inj, if down { KEY_PRESS } else { KEY_RELEASE }, ev + 8, 0, 0);
                let _ = inj.conn.flush();
            });
        }
        None => key_sym(down, keysym),
    }
}
