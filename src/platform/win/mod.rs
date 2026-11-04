//! Windows implementation: capture (DXGI + GDI fallback), input injection,
//! clipboard, keyboard hook and misc helpers. Nothing here needs admin rights.

pub mod appinstall;
pub mod capture;
pub mod clipboard;
pub mod desktop;
pub mod input;
pub mod keyhook;
pub mod service;
pub mod tray;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN};
use windows::Win32::Security::{LogonUserW, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Encrypt with DPAPI for the current Windows user (no admin needed).
pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(&input, PCWSTR::null(), None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out).ok()?;
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out.pbData as *mut core::ffi::c_void));
        Some(v)
    }
}

/// Encrypt with DPAPI for this machine (used for the service's settings,
/// which live in a folder only SYSTEM and Administrators can read).
pub fn protect_machine(data: &[u8]) -> Option<Vec<u8>> {
    use windows::Win32::Security::Cryptography::CRYPTPROTECT_LOCAL_MACHINE;
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(&input, PCWSTR::null(), None, None, None, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &mut out).ok()?;
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out.pbData as *mut core::ffi::c_void));
        Some(v)
    }
}

/// Protect secrets the way the current mode needs (machine scope for the service).
pub fn protect_for_config(data: &[u8]) -> Option<Vec<u8>> {
    if crate::config::machine_mode() { protect_machine(data) } else { protect(data) }
}

pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out).ok()?;
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out.pbData as *mut core::ffi::c_void));
        Some(v)
    }
}

/// Per-user autostart via HKCU\...\Run (no admin rights required).
pub fn set_autostart(enabled: bool) -> anyhow::Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    let status = if enabled {
        let exe = std::env::current_exe()?;
        let value = format!("\"{}\" --minimized", exe.display());
        std::process::Command::new("reg").args(["add", key, "/v", "PortlessVNC", "/t", "REG_SZ", "/d", &value, "/f"]).creation_flags(CREATE_NO_WINDOW).status()?
    } else {
        std::process::Command::new("reg").args(["delete", key, "/v", "PortlessVNC", "/f"]).creation_flags(CREATE_NO_WINDOW).status()?
    };
    if !status.success() && enabled {
        anyhow::bail!("reg.exe failed");
    }
    Ok(())
}

/// Validate Windows credentials ("user", ".\user" or "DOMAIN\user").
pub fn check_system_login(user: &str, pass: &str) -> bool {
    let (domain, name) = match user.split_once('\\') {
        Some((d, n)) => (d.to_string(), n.to_string()),
        None => match user.split_once('@') {
            Some(_) => (String::new(), user.to_string()),
            None => (".".to_string(), user.to_string()),
        },
    };
    let (wn, wd, wp) = (wide(&name), wide(&domain), wide(pass));
    unsafe {
        let mut token = HANDLE::default();
        let dom = if domain.is_empty() { PCWSTR::null() } else { PCWSTR(wd.as_ptr()) };
        let ok = LogonUserW(PCWSTR(wn.as_ptr()), dom, PCWSTR(wp.as_ptr()), LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &mut token).is_ok();
        if ok {
            let _ = CloseHandle(token);
        }
        ok
    }
}

pub fn current_user() -> String {
    std::env::var("USERNAME").unwrap_or_default()
}
