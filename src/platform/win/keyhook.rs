//! Low-level keyboard hook for the viewer: while a session window is in the
//! foreground, every key (including Win, Alt+Tab, Ctrl+Esc) is captured with
//! its scancode and forwarded to that session. Works without admin rights.

use super::input::{vk_to_keysym, INJECT_MARKER};
use crossbeam_channel::Sender;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::*;

#[derive(Clone, Copy, Debug)]
pub struct KeyEvent {
    pub down: bool,
    pub keysym: u32,
    /// QEMU-style XT scancode (0 if unknown)
    pub xt: u32,
}

static SESSIONS: OnceLock<Mutex<HashMap<String, Sender<KeyEvent>>>> = OnceLock::new();
static INSTALLED: AtomicBool = AtomicBool::new(false);
pub static CAPTURE_SYSTEM_KEYS: AtomicBool = AtomicBool::new(true);

fn sessions() -> &'static Mutex<HashMap<String, Sender<KeyEvent>>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a session window title; keys typed while that window is in the
/// foreground go to `tx`.
pub fn register(title: &str, tx: Sender<KeyEvent>) {
    sessions().lock().insert(title.to_string(), tx);
}

pub fn unregister(title: &str) {
    sessions().lock().remove(title);
}

fn foreground_title() -> String {
    unsafe {
        let hwnd = GetForegroundWindow();
        let mut buf = [0u16; 512];
        // InternalGetWindowText reads the caption without sending a message to
        // the window's (GUI) thread, so the hook can never block on it.
        let n = InternalGetWindowText(hwnd, &mut buf);
        String::from_utf16_lossy(&buf[..n.max(0) as usize])
    }
}

static TEST_INJECTED: OnceLock<bool> = OnceLock::new();

pub static HOOK_CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Must stay minimal: no logging, no locks shared with the GUI, no repaint
/// requests. Anything that can block here stalls the whole system's keyboard
/// and makes Windows silently remove the hook.
unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    HOOK_CALLS.fetch_add(1, Ordering::Relaxed);
    if code == HC_ACTION as i32 {
        let kb = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
        // (PVNC_TEST_INJECTED=1 lets automated tests feed synthetic keys; our own
        // injected input is always ignored to avoid loops)
        let injected = kb.dwExtraInfo == INJECT_MARKER || (kb.flags.0 & LLKHF_INJECTED.0 != 0 && !*TEST_INJECTED.get_or_init(|| std::env::var_os("PVNC_TEST_INJECTED").is_some()));
        if !injected {
            let tx = {
                let map = sessions().lock();
                if map.is_empty() { None } else { map.get(&foreground_title()).cloned() }
            };
            {
                if let Some(tx) = tx {
                    let msg = wparam.0 as u32;
                    let down = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
                    let extended = kb.flags.0 & LLKHF_EXTENDED.0 != 0;
                    let vk = kb.vkCode as u16;
                    let system_key = matches!(vk, 0x5B | 0x5C) || (vk == 0x09 && kb.flags.0 & LLKHF_ALTDOWN.0 != 0);
                    if system_key && !CAPTURE_SYSTEM_KEYS.load(Ordering::Relaxed) {
                        return CallNextHookEx(HHOOK::default(), code, wparam, lparam);
                    }
                    let scan = kb.scanCode;
                    let xt = if scan == 0 { 0 } else if extended { 0x80 | (scan & 0x7f) } else { scan & 0x7f };
                    if let Some(keysym) = vk_to_keysym(vk, extended) {
                        let _ = tx.send(KeyEvent { down, keysym, xt });
                        return LRESULT(1); // swallow: the key belongs to the remote machine
                    }
                }
            }
        }
    }
    CallNextHookEx(HHOOK::default(), code, wparam, lparam)
}

/// Install the hook on its own thread with its own message loop, so slow GUI
/// frames can never make Windows time out (and silently remove) the hook.
/// Safe to call repeatedly.
pub fn install() {
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::Builder::new()
        .name("keyhook".into())
        .spawn(|| unsafe {
            let hinst = GetModuleHandleW(None).unwrap_or_default();
            match SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), hinst, 0) {
                Ok(_) => log::debug!("keyboard hook installed"),
                Err(e) => {
                    log::warn!("Could not install keyboard hook ({e}); using window key events instead");
                    INSTALLED.store(false, Ordering::SeqCst);
                    return;
                }
            }
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        })
        .ok();
}
