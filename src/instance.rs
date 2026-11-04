//! One window per kind (the app, Service settings): a second launch hands its
//! request to the running window over loopback and exits, instead of opening
//! another window. The running window writes its port to a small file.

use eframe::egui;
use parking_lot::Mutex;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

const HELLO: &str = "PVNC-WINDOW 1";

static PENDING: Mutex<Vec<String>> = Mutex::new(Vec::new());
static CTX: OnceLock<egui::Context> = OnceLock::new();
static TITLE: OnceLock<String> = OnceLock::new();

fn port_file(service_config: bool) -> PathBuf {
    if service_config {
        crate::servicectl::public_dir().join("settings-window.port")
    } else {
        crate::config::user_config_dir().join("window.port")
    }
}

/// Ask a running window to take `msg` ("show" or "connect <addr>").
/// True when one did, so this launch should exit.
pub fn hand_off(service_config: bool, msg: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(port_file(service_config)) else { return false };
    let Ok(port) = text.trim().parse::<u16>() else { return false };
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    // the launcher owns the foreground right now: let the running window take it
    #[cfg(windows)]
    unsafe {
        use windows::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, ASFW_ANY};
        let _ = AllowSetForegroundWindow(ASFW_ANY);
    }
    if writeln!(s, "{HELLO}\n{msg}").is_err() {
        return false;
    }
    let mut reply = String::new();
    BufReader::new(s).read_line(&mut reply).is_ok() && reply.trim() == "ok"
}

/// Decide whether this launch opens the window (true) or handed `msg` to the
/// one that has it (false). A lock file settles launches that start together
/// (one tray click can start two); the loser waits for the winner to listen.
pub fn claim(service_config: bool, title: &str, msg: &str) -> bool {
    static LOCK: OnceLock<std::fs::File> = OnceLock::new();
    let _ = TITLE.set(title.to_string());
    let port = port_file(service_config);
    if let Some(d) = port.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let Ok(file) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(port.with_extension("lock")) else {
        if hand_off(service_config, msg) {
            return false;
        }
        listen(service_config);
        return true;
    };
    let until = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if file.try_lock().is_ok() {
            let _ = LOCK.set(file); // held until this process exits
            listen(service_config);
            return true;
        }
        if hand_off(service_config, msg) {
            return false;
        }
        if std::time::Instant::now() > until {
            log::warn!("another PortlessVNC window holds the lock but does not answer; opening anyway");
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// Become the window others hand off to.
fn listen(service_config: bool) {
    let Ok(l) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else { return };
    let Ok(port) = l.local_addr().map(|a| a.port()) else { return };
    let file = port_file(service_config);
    if let Some(d) = file.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(&file, port.to_string());
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut r = BufReader::new(&s);
            let (mut hello, mut msg) = (String::new(), String::new());
            if r.read_line(&mut hello).is_err() || hello.trim() != HELLO || r.read_line(&mut msg).is_err() {
                continue;
            }
            let _ = (&s).write_all(b"ok\n");
            PENDING.lock().push(msg.trim().to_string());
            std::thread::spawn(raise);
        }
    });
}

/// Called once the GUI exists, so a hand-off can wake it.
pub fn set_context(ctx: &egui::Context) {
    let _ = CTX.set(ctx.clone());
}

/// Requests handed over since the last call.
pub fn take() -> Vec<String> {
    std::mem::take(&mut *PENDING.lock())
}

fn raise() {
    // a minimized window may not repaint, so restore it natively first
    #[cfg(windows)]
    unsafe {
        use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
        use windows::Win32::UI::WindowsAndMessaging::*;
        unsafe extern "system" fn each(hwnd: HWND, _: LPARAM) -> BOOL {
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == std::process::id() {
                let mut buf = [0u16; 256];
                let n = InternalGetWindowText(hwnd, &mut buf) as usize; // no message: never waits on the window
                if TITLE.get().map(|t| *t == String::from_utf16_lossy(&buf[..n])).unwrap_or(false) {
                    if IsIconic(hwnd).as_bool() {
                        let _ = ShowWindowAsync(hwnd, SW_RESTORE);
                    } else {
                        let _ = ShowWindowAsync(hwnd, SW_SHOW);
                    }
                    let _ = SetForegroundWindow(hwnd);
                    return BOOL(0);
                }
            }
            BOOL(1)
        }
        let _ = EnumWindows(Some(each), LPARAM(0));
    }
    if let Some(ctx) = CTX.get() {
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        ctx.request_repaint();
    }
}
