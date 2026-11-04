//! Follow the input desktop. Windows shows the sign-in screen, UAC prompts and
//! the lock screen on a separate "Winlogon" desktop; a thread can only capture
//! or inject input on the desktop it is attached to. When running as SYSTEM in
//! service mode, capture and input threads re-attach whenever it changes.
//! (As a normal user the secure desktop cannot be opened and this is a no-op.)

use std::cell::RefCell;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::StationsAndDesktops::*;
use windows::Win32::System::Threading::GetCurrentThreadId;

thread_local! {
    static CURRENT: RefCell<Option<(HDESK, String)>> = const { RefCell::new(None) };
}

fn desktop_name(h: HDESK) -> String {
    let mut buf = [0u16; 128];
    let mut needed = 0u32;
    unsafe {
        if GetUserObjectInformationW(HANDLE(h.0), UOI_NAME, Some(buf.as_mut_ptr() as *mut _), (buf.len() * 2) as u32, Some(&mut needed)).is_ok() {
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            return String::from_utf16_lossy(&buf[..end]);
        }
    }
    String::new()
}

/// Attach the calling thread to the current input desktop if it changed.
/// Returns Some(new name) when the thread switched desktops.
pub fn sync_thread() -> Option<String> {
    unsafe {
        // GENERIC_ALL (0x10000000) on the desktop object
        let input = OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ACCESS_FLAGS(0x1000_0000)).ok()?;
        let name = desktop_name(input);
        let same = CURRENT.with(|c| c.borrow().as_ref().map(|(_, n)| *n == name)).unwrap_or_else(|| {
            let cur = GetThreadDesktop(GetCurrentThreadId()).ok();
            cur.map(|d| desktop_name(d) == name).unwrap_or(false)
        });
        if same {
            let _ = CloseDesktop(input);
            return None;
        }
        if SetThreadDesktop(input).is_err() {
            let _ = CloseDesktop(input);
            return None;
        }
        CURRENT.with(|c| {
            if let Some((old, _)) = c.borrow_mut().replace((input, name.clone())) {
                let _ = CloseDesktop(old);
            }
        });
        Some(name)
    }
}

/// Name of the desktop currently receiving input ("Default", "Winlogon", ...).
pub fn input_desktop_name() -> String {
    unsafe {
        match OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ACCESS_FLAGS(0x0001)) {
            Ok(h) => {
                let n = desktop_name(h);
                let _ = CloseDesktop(h);
                n
            }
            Err(_) => "Winlogon".into(), // not accessible -> a secure desktop
        }
    }
}
