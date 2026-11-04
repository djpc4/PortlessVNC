//! Input injection with SendInput (works without admin for non-elevated
//! windows; elevated windows/UAC prompts are protected by UIPI).

use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN};

/// Marker put in dwExtraInfo so our own keyboard hook can ignore injected input.
pub const INJECT_MARKER: usize = 0x504C_5331;

fn send(inputs: &[INPUT]) {
    if crate::config::machine_mode() {
        let _ = super::desktop::sync_thread(); // inject on the desktop the user sees
    }
    unsafe {
        SendInput(inputs, std::mem::size_of::<INPUT>() as i32);
    }
}

fn mouse_input(dx: i32, dy: i32, data: i32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 { mi: MOUSEINPUT { dx, dy, mouseData: data as _, dwFlags: flags, time: 0, dwExtraInfo: INJECT_MARKER } },
    }
}

/// Pointer event in capture coordinates. `origin` is the captured area's
/// top-left in desktop coordinates.
pub fn pointer(x: i32, y: i32, origin: (i32, i32), mask: u8, prev: u8) {
    let (vx, vy, vw, vh) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN).max(2),
            GetSystemMetrics(SM_CYVIRTUALSCREEN).max(2),
        )
    };
    let ax = ((origin.0 + x - vx) as i64 * 65535 / (vw - 1) as i64) as i32;
    let ay = ((origin.1 + y - vy) as i64 * 65535 / (vh - 1) as i64) as i32;
    let mut ev = vec![mouse_input(ax, ay, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK)];
    let changed = mask ^ prev;
    let btn = |bit: u8, down: MOUSE_EVENT_FLAGS, up: MOUSE_EVENT_FLAGS| -> Option<INPUT> {
        if changed & bit != 0 {
            Some(mouse_input(0, 0, 0, if mask & bit != 0 { down } else { up }))
        } else {
            None
        }
    };
    ev.extend(btn(1, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP));
    ev.extend(btn(2, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP));
    ev.extend(btn(4, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP));
    // wheel "buttons" fire on press
    let pressed = mask & !prev;
    if pressed & 8 != 0 {
        ev.push(mouse_input(0, 0, 120, MOUSEEVENTF_WHEEL));
    }
    if pressed & 16 != 0 {
        ev.push(mouse_input(0, 0, -120, MOUSEEVENTF_WHEEL));
    }
    if pressed & 32 != 0 {
        ev.push(mouse_input(0, 0, -120, MOUSEEVENTF_HWHEEL));
    }
    if pressed & 64 != 0 {
        ev.push(mouse_input(0, 0, 120, MOUSEEVENTF_HWHEEL));
    }
    send(&ev);
}

fn key_input(vk: u16, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: VIRTUAL_KEY(vk), wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: INJECT_MARKER } },
    }
}

/// (keysym, virtual key, extended)
const KEYSYM_VK: &[(u32, u16, bool)] = &[
    (0xff08, 0x08, false), // BackSpace
    (0xff09, 0x09, false), // Tab
    (0xfe20, 0x09, false), // ISO_Left_Tab
    (0xff0d, 0x0D, false), // Return
    (0xff13, 0x13, false), // Pause
    (0xff14, 0x91, false), // Scroll_Lock
    (0xff15, 0x2C, false), // Sys_Req
    (0xff1b, 0x1B, false), // Escape
    (0xff50, 0x24, true),  // Home
    (0xff51, 0x25, true),  // Left
    (0xff52, 0x26, true),  // Up
    (0xff53, 0x27, true),  // Right
    (0xff54, 0x28, true),  // Down
    (0xff55, 0x21, true),  // Prior
    (0xff56, 0x22, true),  // Next
    (0xff57, 0x23, true),  // End
    (0xff61, 0x2C, true),  // Print
    (0xff63, 0x2D, true),  // Insert
    (0xff67, 0x5D, true),  // Menu
    (0xff7f, 0x90, true),  // Num_Lock
    (0xff8d, 0x0D, true),  // KP_Enter
    (0xff95, 0x24, false), // KP_Home
    (0xff96, 0x25, false), // KP_Left
    (0xff97, 0x26, false), // KP_Up
    (0xff98, 0x27, false), // KP_Right
    (0xff99, 0x28, false), // KP_Down
    (0xff9a, 0x21, false), // KP_Prior
    (0xff9b, 0x22, false), // KP_Next
    (0xff9c, 0x23, false), // KP_End
    (0xff9e, 0x2D, false), // KP_Insert
    (0xff9f, 0x2E, false), // KP_Delete
    (0xffaa, 0x6A, false), // KP_Multiply
    (0xffab, 0x6B, false), // KP_Add
    (0xffac, 0x6C, false), // KP_Separator
    (0xffad, 0x6D, false), // KP_Subtract
    (0xffae, 0x6E, false), // KP_Decimal
    (0xffaf, 0x6F, true),  // KP_Divide
    (0xffb0, 0x60, false),
    (0xffb1, 0x61, false),
    (0xffb2, 0x62, false),
    (0xffb3, 0x63, false),
    (0xffb4, 0x64, false),
    (0xffb5, 0x65, false),
    (0xffb6, 0x66, false),
    (0xffb7, 0x67, false),
    (0xffb8, 0x68, false),
    (0xffb9, 0x69, false),
    (0xffe1, 0xA0, false), // Shift_L
    (0xffe2, 0xA1, false), // Shift_R
    (0xffe3, 0xA2, false), // Control_L
    (0xffe4, 0xA3, true),  // Control_R
    (0xffe5, 0x14, false), // Caps_Lock
    (0xffe7, 0x5B, true),  // Meta_L
    (0xffe8, 0x5C, true),  // Meta_R
    (0xffe9, 0xA4, false), // Alt_L
    (0xffea, 0xA5, true),  // Alt_R
    (0xfe03, 0xA5, true),  // ISO_Level3_Shift (AltGr)
    (0xffeb, 0x5B, true),  // Super_L
    (0xffec, 0x5C, true),  // Super_R
    (0xffff, 0x2E, true),  // Delete
];

fn keysym_to_vk(keysym: u32) -> Option<(u16, bool)> {
    if (0xffbe..=0xffd5).contains(&keysym) {
        return Some((0x70 + (keysym - 0xffbe) as u16, false)); // F1..F24
    }
    KEYSYM_VK.iter().find(|(k, _, _)| *k == keysym).map(|&(_, vk, ext)| (vk, ext))
}

pub fn vk_to_keysym(vk: u16, extended: bool) -> Option<u32> {
    if (0x70..=0x87).contains(&vk) {
        return Some(0xffbe + (vk - 0x70) as u32);
    }
    // prefer entries matching the extended flag (e.g. Return vs KP_Enter)
    let special = match (vk, extended) {
        (0x0D, true) => Some(0xff8d),
        (0x0D, false) => Some(0xff0d),
        (0x2E, _) => Some(0xffff),
        (0x24, _) => Some(0xff50),
        (0x25, _) => Some(0xff51),
        (0x26, _) => Some(0xff52),
        (0x27, _) => Some(0xff53),
        (0x28, _) => Some(0xff54),
        (0x21, _) => Some(0xff55),
        (0x22, _) => Some(0xff56),
        (0x23, _) => Some(0xff57),
        (0x2D, _) => Some(0xff63),
        (0x2C, _) => Some(0xff61),
        (0x10, _) | (0xA0, _) => Some(0xffe1),
        (0xA1, _) => Some(0xffe2),
        (0x11, false) | (0xA2, _) => Some(0xffe3),
        (0x11, true) | (0xA3, _) => Some(0xffe4),
        (0x12, false) | (0xA4, _) => Some(0xffe9),
        (0x12, true) | (0xA5, _) => Some(0xffea),
        _ => None,
    };
    if special.is_some() {
        return special;
    }
    if let Some(&(k, _, _)) = KEYSYM_VK.iter().find(|(_, v, _)| *v == vk) {
        return Some(k);
    }
    // printable: base character of the key on the local layout
    let ch = unsafe { MapVirtualKeyW(vk as u32, MAPVK_VK_TO_CHAR) } & 0x7FFF;
    if ch >= 0x20 {
        let c = char::from_u32(ch)?.to_lowercase().next()?;
        return Some(char_to_keysym(c));
    }
    None
}

pub fn char_to_keysym(c: char) -> u32 {
    let u = c as u32;
    if (0x20..=0x7e).contains(&u) || (0xa0..=0xff).contains(&u) { u } else { 0x0100_0000 | u }
}

fn keysym_to_char(keysym: u32) -> Option<char> {
    if (0x20..=0x7e).contains(&keysym) || (0xa0..=0xff).contains(&keysym) {
        char::from_u32(keysym)
    } else if keysym & 0xff00_0000 == 0x0100_0000 {
        char::from_u32(keysym & 0x00ff_ffff)
    } else {
        None
    }
}

/// Inject an X11 keysym (standard RFB KeyEvent).
pub fn key_sym(down: bool, keysym: u32) {
    let up = if down { KEYBD_EVENT_FLAGS(0) } else { KEYEVENTF_KEYUP };
    if let Some((vk, ext)) = keysym_to_vk(keysym) {
        let scan = unsafe { MapVirtualKeyW(vk as u32, MAPVK_VK_TO_VSC) } as u16;
        let flags = up | if ext { KEYEVENTF_EXTENDEDKEY } else { KEYBD_EVENT_FLAGS(0) };
        send(&[key_input(vk, scan, flags)]);
        return;
    }
    if let Some(c) = keysym_to_char(keysym) {
        let mut buf = [0u16; 2];
        let units = c.encode_utf16(&mut buf);
        if units.len() == 1 {
            let r = unsafe { VkKeyScanW(units[0]) };
            if r != -1 {
                let vk = (r & 0xff) as u16;
                let scan = unsafe { MapVirtualKeyW(vk as u32, MAPVK_VK_TO_VSC) } as u16;
                send(&[key_input(vk, scan, up)]);
                return;
            }
        }
        // Not on the local layout: type it as Unicode.
        let ev: Vec<INPUT> = units.iter().map(|&u| key_input(0, u, KEYEVENTF_UNICODE | up)).collect();
        send(&ev);
    }
}

/// Inject a hardware scancode (QEMU extended key event). `xt` uses the QEMU
/// encoding: extended (0xE0-prefixed) keys have the high bit set.
pub fn key_scancode(down: bool, xt: u32, keysym: u32) {
    if xt == 0 {
        return key_sym(down, keysym);
    }
    let ext = xt & 0x80 != 0 || xt > 0xff;
    let scan = (xt & 0x7f) as u16;
    let mut flags = KEYEVENTF_SCANCODE;
    if ext {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    if !down {
        flags |= KEYEVENTF_KEYUP;
    }
    send(&[key_input(0, scan, flags)]);
}
