//! `PortlessVNC.exe --tray`: notification-area icon for service mode. Runs as
//! the signed-in user (started at sign-in via HKLM\...\Run), shows the
//! service's status and offers quick actions. Exits when the service is
//! removed.

use crate::servicectl::{self, Status};
use parking_lot::Mutex;
use std::time::{Duration, Instant};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Shell::*;
use windows::Win32::UI::WindowsAndMessaging::*;

const WM_TRAY: u32 = WM_APP + 5;
const ID_COPY_IP: usize = 1;
const ID_COPY_OTP: usize = 2;
const ID_NEW_OTP: usize = 3;
const ID_OPEN: usize = 4;
const ID_SETTINGS: usize = 5;
const ID_EXIT: usize = 6;
const ID_RECONNECT: usize = 7;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shade {
    Green,
    Orange,
    Grey,
}

struct State {
    status: Option<Status>,
    shade: Option<Shade>,
    icon: HICON,
    taskbar_created: u32,
    last_service_check: Instant,
}

unsafe impl Send for State {}

static STATE: Mutex<Option<State>> = Mutex::new(None);

/// A 32x32 filled circle with a light ring, in the given colour.
unsafe fn make_icon(rgb: (u8, u8, u8)) -> HICON {
    const S: i32 = 32;
    let dc = GetDC(HWND::default());
    let mut bmi = BITMAPINFO::default();
    bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    bmi.bmiHeader.biWidth = S;
    bmi.bmiHeader.biHeight = -S;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB.0;
    let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
    let color = CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &mut bits, None, 0).unwrap_or_default();
    ReleaseDC(HWND::default(), dc);
    if !bits.is_null() {
        let px = std::slice::from_raw_parts_mut(bits as *mut u32, (S * S) as usize);
        let c = (S as f32 - 1.0) / 2.0;
        for y in 0..S {
            for x in 0..S {
                let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
                let i = (y * S + x) as usize;
                px[i] = if d <= 12.0 {
                    0xFF00_0000 | ((rgb.0 as u32) << 16) | ((rgb.1 as u32) << 8) | rgb.2 as u32
                } else if d <= 15.0 {
                    0xFFF0_F0F0 // white ring so it shows on dark and light taskbars
                } else {
                    0
                };
            }
        }
    }
    let mask_bits = vec![0u8; (S * S / 8) as usize];
    let mask = CreateBitmap(S, S, 1, 1, Some(mask_bits.as_ptr() as *const _));
    let info = ICONINFO { fIcon: true.into(), xHotspot: 0, yHotspot: 0, hbmMask: mask, hbmColor: color };
    let icon = CreateIconIndirect(&info).unwrap_or_default();
    let _ = DeleteObject(color);
    let _ = DeleteObject(mask);
    icon
}

fn shade_of(s: &Option<Status>) -> Shade {
    match s {
        Some(st) if st.vpn_ip.is_some() => Shade::Green,
        Some(st) if st.vpn_state == "connecting" || st.vpn_state == "reconnecting" => Shade::Orange,
        _ => Shade::Grey,
    }
}

fn tooltip(s: &Option<Status>) -> String {
    match s {
        Some(st) => match &st.vpn_ip {
            Some(ip) => {
                let addr = if st.vpn_port == 5900 { ip.clone() } else { format!("{ip}:{}", st.vpn_port) };
                format!("PortlessVNC - {addr}{}", if st.viewers.is_empty() { String::new() } else { format!(" ({} connected)", st.viewers.len()) })
            }
            None => format!("PortlessVNC - VPN {}", st.vpn_state),
        },
        None => "PortlessVNC - service not running".into(),
    }
}

unsafe fn update_icon(hwnd: HWND, add: bool) {
    let mut g = STATE.lock();
    let Some(st) = g.as_mut() else { return };
    let shade = shade_of(&st.status);
    if st.shade != Some(shade) || add {
        if !st.icon.is_invalid() && st.shade != Some(shade) {
            let _ = DestroyIcon(st.icon);
            st.icon = HICON::default();
        }
        if st.icon.is_invalid() {
            st.icon = make_icon(match shade {
                Shade::Green => (0x2f, 0x9e, 0x6b),
                Shade::Orange => (0xe0, 0x8a, 0x20),
                Shade::Grey => (0x80, 0x80, 0x80),
            });
        }
        st.shade = Some(shade);
    }
    let mut nid = NOTIFYICONDATAW { cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32, hWnd: hwnd, uID: 1, uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP, uCallbackMessage: WM_TRAY, hIcon: st.icon, ..Default::default() };
    let tip: Vec<u16> = tooltip(&st.status).encode_utf16().take(127).collect();
    nid.szTip[..tip.len()].copy_from_slice(&tip);
    let _ = Shell_NotifyIconW(if add { NIM_ADD } else { NIM_MODIFY }, &nid);
}

fn spawn(arg: Option<&str>) {
    if let Ok(exe) = std::env::current_exe() {
        let mut c = std::process::Command::new(exe);
        if let Some(a) = arg {
            c.arg(a);
        }
        let _ = c.spawn();
    }
}

unsafe fn show_menu(hwnd: HWND) {
    let status = STATE.lock().as_ref().and_then(|s| s.status.clone());
    let Ok(menu) = CreatePopupMenu() else { return };
    let item = |id: usize, text: &str, enabled: bool| {
        let t = super::wide(text);
        let flags = if enabled { MF_STRING } else { MF_STRING | MF_GRAYED };
        let _ = AppendMenuW(menu, flags, id, PCWSTR(t.as_ptr()));
    };
    match status.as_ref().and_then(|s| s.vpn_ip.clone().map(|ip| (ip, s.vpn_port))) {
        Some((ip, port)) => item(ID_COPY_IP, &format!("VPN address: {}{}   (copy)", ip, if port == 5900 { String::new() } else { format!(":{port}") }), true),
        None => item(0, &format!("VPN: {}", status.as_ref().map(|s| s.vpn_state.as_str()).unwrap_or("service not running")), false),
    }
    match status.as_ref().and_then(|s| s.otp.clone()) {
        Some(otp) => {
            item(ID_COPY_OTP, &format!("One-time password: {otp}   (copy)"), true);
            item(ID_NEW_OTP, "New one-time password", true);
        }
        None => item(0, "One-time password: off", false),
    }
    if let Some(n) = status.as_ref().map(|s| s.viewers.len()).filter(|n| *n > 0) {
        item(0, &format!("{n} viewer(s) connected"), false);
    }
    item(ID_RECONNECT, "Reconnect VPN", status.is_some());
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    item(ID_OPEN, "Open PortlessVNC", true);
    item(ID_SETTINGS, "Service settings...", true);
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    item(ID_EXIT, "Hide tray icon", true);
    let mut pt = POINT::default();
    let _ = GetCursorPos(&mut pt);
    let _ = SetForegroundWindow(hwnd); // required so the menu closes when clicking elsewhere
    let cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, None).0 as usize;
    let _ = DestroyMenu(menu);
    match cmd {
        ID_COPY_IP => {
            if let Some(s) = status {
                if let Some(ip) = s.vpn_ip {
                    let t = if s.vpn_port == 5900 { ip } else { format!("{ip}:{}", s.vpn_port) };
                    super::clipboard::set_text(hwnd, &t);
                }
            }
        }
        ID_COPY_OTP => {
            if let Some(otp) = status.and_then(|s| s.otp) {
                super::clipboard::set_text(hwnd, &otp);
            }
        }
        ID_NEW_OTP => servicectl::request("new-otp"),
        ID_RECONNECT => servicectl::request("reconnect"),
        ID_OPEN => spawn(None),
        ID_SETTINGS => spawn(Some("--service-config")),
        ID_EXIT => {
            let _ = DestroyWindow(hwnd);
        }
        _ => {}
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let taskbar_created = STATE.lock().as_ref().map(|s| s.taskbar_created).unwrap_or(0);
    match msg {
        WM_TRAY => {
            match lparam.0 as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => spawn(None),
                WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        WM_TIMER => {
            let status = servicectl::read_status();
            let check_service = {
                let mut g = STATE.lock();
                let st = g.as_mut().unwrap();
                st.status = status;
                let due = st.last_service_check.elapsed() > Duration::from_secs(15);
                if due {
                    st.last_service_check = Instant::now();
                }
                due && st.status.is_none()
            };
            if check_service && !super::service::service_installed() {
                let _ = DestroyWindow(hwnd); // service was removed: nothing to show
                return LRESULT(0);
            }
            update_icon(hwnd, false);
            LRESULT(0)
        }
        WM_DESTROY => {
            let nid = NOTIFYICONDATAW { cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32, hWnd: hwnd, uID: 1, ..Default::default() };
            let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
            PostQuitMessage(0);
            LRESULT(0)
        }
        m if m == taskbar_created && m != 0 => {
            update_icon(hwnd, true); // Explorer restarted: add the icon again
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub fn run() -> i32 {
    unsafe {
        // one tray per user session
        let _mutex = CreateMutexW(None, true, w!("Local\\PortlessVNC-Tray"));
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return 0;
        }
        let hinst = GetModuleHandleW(None).unwrap_or_default();
        let class = w!("PortlessVNCTray");
        let wc = WNDCLASSW { lpfnWndProc: Some(wndproc), hInstance: hinst.into(), lpszClassName: class, ..Default::default() };
        RegisterClassW(&wc);
        let taskbar_created = RegisterWindowMessageW(w!("TaskbarCreated"));
        *STATE.lock() = Some(State { status: servicectl::read_status(), shade: None, icon: HICON::default(), taskbar_created, last_service_check: Instant::now() });
        let Ok(hwnd) = CreateWindowExW(WINDOW_EX_STYLE(0), class, w!("PortlessVNC tray"), WINDOW_STYLE(0), 0, 0, 0, 0, HWND::default(), None, hinst, None) else {
            return 1;
        };
        update_icon(hwnd, true);
        SetTimer(hwnd, 1, 2000, None);
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    0
}
