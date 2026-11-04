//! Background service (runs as LocalSystem from boot).
//!
//! A service lives in session 0, which has no screen, so it starts a helper
//! ("agent", `PortlessVNC.exe --agent`) inside the active console session
//! using its own SYSTEM token. Running as SYSTEM there lets the agent capture
//! and control the login screen, UAC prompts and the lock screen. The service
//! restarts the agent if it exits or when the console session changes
//! (logon, logoff, user switch), and performs Ctrl+Alt+Del (SendSAS) for it.

use crate::servicectl::{install_dir, machine_dir, public_dir, requests_dir, SERVICE_NAME};
use std::ffi::OsString;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::{DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TokenPrimary, TokenSessionId, TOKEN_ALL_ACCESS, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY};
use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows::Win32::System::Threading::*;
use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

const CREATE_NO_WINDOW_FLAG: u32 = 0x0800_0000;
const RUN_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const SAS_EVENT: PCWSTR = w!("Global\\PortlessVNC-SAS");
const STOP_EVENT: PCWSTR = w!("Global\\PortlessVNC-AgentStop");

define_windows_service!(ffi_service_main, service_main);

/// Entry point for `PortlessVNC.exe --service` (called by the SCM).
pub fn run_dispatcher() -> i32 {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("This command is used by Windows to start the PortlessVNC service ({e}).");
            1
        }
    }
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        log::error!("service: {e:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let handle = service_control_handler::register(SERVICE_NAME, move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            s2.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let status = |state: ServiceState| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(5),
        process_id: None,
    };
    handle.set_service_status(status(ServiceState::Running))?;

    unsafe {
        let sas = CreateEventW(None, false, false, SAS_EVENT).ok();
        let agent_stop = CreateEventW(None, true, false, STOP_EVENT).ok();
        let exe = std::env::current_exe()?;
        let mut agent: Option<(HANDLE, u32)> = None; // (process, session)
        let mut last_start = Instant::now() - Duration::from_secs(60);
        while !stop.load(Ordering::SeqCst) {
            // Ctrl+Alt+Del requested by the agent
            if let Some(ev) = sas {
                if WaitForSingleObject(ev, 0) == WAIT_OBJECT_0 {
                    send_sas();
                }
            }
            let session = WTSGetActiveConsoleSessionId();
            let alive = agent.map(|(p, _)| WaitForSingleObject(p, 0) != WAIT_OBJECT_0).unwrap_or(false);
            let wrong_session = agent.map(|(_, s)| s != session).unwrap_or(false);
            if (!alive || wrong_session) && agent.is_some() {
                if let Some((p, _)) = agent.take() {
                    if let Some(ev) = agent_stop {
                        let _ = SetEvent(ev);
                    }
                    if WaitForSingleObject(p, 3000) != WAIT_OBJECT_0 {
                        let _ = TerminateProcess(p, 0);
                    }
                    let _ = CloseHandle(p);
                    if let Some(ev) = agent_stop {
                        let _ = ResetEvent(ev);
                    }
                }
            }
            if agent.is_none() && session != 0xFFFF_FFFF && last_start.elapsed() > Duration::from_secs(2) {
                last_start = Instant::now();
                match launch_in_session(&exe, session) {
                    Ok(p) => agent = Some((p, session)),
                    Err(e) => log::warn!("service: cannot start agent in session {session}: {e}"),
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        if let Some((p, _)) = agent.take() {
            if let Some(ev) = agent_stop {
                let _ = SetEvent(ev);
            }
            if WaitForSingleObject(p, 3000) != WAIT_OBJECT_0 {
                let _ = TerminateProcess(p, 0);
            }
            let _ = CloseHandle(p);
        }
    }
    handle.set_service_status(status(ServiceState::Stopped))?;
    Ok(())
}

/// Start `exe --agent` as SYSTEM inside `session`, on the interactive desktop.
unsafe fn launch_in_session(exe: &Path, session: u32) -> anyhow::Result<HANDLE> {
    let mut tok = HANDLE::default();
    OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT, &mut tok)?;
    let mut dup = HANDLE::default();
    let r = DuplicateTokenEx(tok, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, &mut dup);
    let _ = CloseHandle(tok);
    r?;
    SetTokenInformation(dup, TokenSessionId, &session as *const u32 as *const _, 4)?;
    let mut desktop = super::wide("winsta0\\default");
    let si = STARTUPINFOW { cb: std::mem::size_of::<STARTUPINFOW>() as u32, lpDesktop: PWSTR(desktop.as_mut_ptr()), ..Default::default() };
    let mut pi = PROCESS_INFORMATION::default();
    let exe_w = super::wide(&exe.to_string_lossy());
    let mut cmd = super::wide(&format!("\"{}\" --agent", exe.display()));
    let res = CreateProcessAsUserW(dup, PCWSTR(exe_w.as_ptr()), PWSTR(cmd.as_mut_ptr()), None, None, false, PROCESS_CREATION_FLAGS(CREATE_NO_WINDOW_FLAG), None, PCWSTR::null(), &si, &mut pi);
    let _ = CloseHandle(dup);
    res?;
    let _ = CloseHandle(pi.hThread);
    Ok(pi.hProcess)
}

/// Ctrl+Alt+Del via sas.dll (allowed for services by the SoftwareSASGeneration policy).
unsafe fn send_sas() {
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    if let Ok(lib) = LoadLibraryW(w!("sas.dll")) {
        if let Some(f) = GetProcAddress(lib, windows::core::s!("SendSAS")) {
            let send: extern "system" fn(i32) = std::mem::transmute(f);
            send(0);
        }
    }
}

// ---- helpers used by the agent ------------------------------------------------

/// Agent side: ask the service to press Ctrl+Alt+Del. Returns false outside service mode.
pub fn request_sas() -> bool {
    unsafe {
        match OpenEventW(EVENT_MODIFY_STATE, false, SAS_EVENT) {
            Ok(h) => {
                let _ = SetEvent(h);
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

/// Agent side: has the service asked us to exit?
pub fn stop_requested() -> bool {
    unsafe {
        match OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, false, STOP_EVENT) {
            Ok(h) => {
                let signalled = WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
                let _ = CloseHandle(h);
                signalled
            }
            Err(_) => false,
        }
    }
}

// ---- install / uninstall ------------------------------------------------------

pub fn is_elevated() -> bool {
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION};
    unsafe {
        let mut tok = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).is_err() {
            return false;
        }
        let mut e = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(tok, TokenElevation, Some(&mut e as *mut _ as *mut _), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len).is_ok();
        let _ = CloseHandle(tok);
        ok && e.TokenIsElevated != 0
    }
}

/// Re-run this exe elevated with `args` (shows the UAC prompt) and wait for it.
pub fn run_elevated(args: &str) -> anyhow::Result<u32> {
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    let exe = std::env::current_exe()?;
    let exe_w = super::wide(&exe.to_string_lossy());
    let args_w = super::wide(args);
    unsafe {
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: w!("runas"),
            lpFile: PCWSTR(exe_w.as_ptr()),
            lpParameters: PCWSTR(args_w.as_ptr()),
            nShow: 1,
            ..Default::default()
        };
        ShellExecuteExW(&mut info).map_err(|e| anyhow::anyhow!("elevation was cancelled or failed ({e})"))?;
        let mut code = 0u32;
        if !info.hProcess.is_invalid() {
            WaitForSingleObject(info.hProcess, INFINITE);
            let _ = GetExitCodeProcess(info.hProcess, &mut code);
            let _ = CloseHandle(info.hProcess);
        }
        Ok(code)
    }
}

fn run(cmd: &str, args: &[&str]) -> bool {
    std::process::Command::new(cmd).args(args).creation_flags(CREATE_NO_WINDOW_FLAG).status().map(|s| s.success()).unwrap_or(false)
}

pub fn service_installed() -> bool {
    run("sc.exe", &["query", SERVICE_NAME])
}

fn message(text: &str) {
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};
    let t = super::wide(text);
    unsafe {
        MessageBoxW(None, PCWSTR(t.as_ptr()), w!("PortlessVNC service"), MB_OK | MB_ICONINFORMATION);
    }
}

/// `--install-service` (must run elevated). Copies the exe to Program Files,
/// moves the current user's hosting settings, VPN profile and certificate to
/// the machine folder, and registers an auto-start LocalSystem service.
pub fn install(user_dir: &Path) -> i32 {
    match install_inner(user_dir) {
        Ok(()) => {
            message("PortlessVNC is now installed as a service.\n\nIt starts with Windows (before anyone signs in), keeps the VPN connected and allows control of the sign-in screen and UAC prompts.\n\nYour normal PortlessVNC window now shows the service's address and one-time password.");
            0
        }
        Err(e) => {
            message(&format!("Installing the service failed:\n\n{e:#}"));
            1
        }
    }
}

fn install_inner(user_dir: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(is_elevated(), "administrator rights are required");
    let pf = install_dir();
    let pd = machine_dir();
    if service_installed() {
        run("sc.exe", &["stop", SERVICE_NAME]);
        std::thread::sleep(Duration::from_secs(3));
    }
    std::fs::create_dir_all(&pf)?;
    let target = pf.join("PortlessVNC.exe");
    let me = std::env::current_exe()?;
    if me != target {
        // the old copy may still be shutting down
        let mut ok = false;
        for _ in 0..10 {
            if std::fs::copy(&me, &target).is_ok() {
                ok = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        anyhow::ensure!(ok, "could not copy PortlessVNC.exe to {}", pf.display());
    }
    std::fs::create_dir_all(requests_dir())?;
    migrate_settings(user_dir, &pd)?;

    // folder permissions: settings for SYSTEM/Administrators only; status
    // readable by everyone; requests writable by everyone
    let pd_s = pd.to_string_lossy().into_owned();
    run("icacls", &[&pd_s, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]);
    run("icacls", &[&public_dir().to_string_lossy(), "/grant", "*S-1-5-32-545:(OI)(CI)RX", "*S-1-5-11:(OI)(CI)RX"]);
    run("icacls", &[&requests_dir().to_string_lossy(), "/grant", "*S-1-5-32-545:(OI)(CI)M", "*S-1-5-11:(OI)(CI)M"]);

    // let services generate Ctrl+Alt+Del
    let pol = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    let had_policy = run("reg", &["query", pol, "/v", "SoftwareSASGeneration"]);
    if !had_policy {
        run("reg", &["add", pol, "/v", "SoftwareSASGeneration", "/t", "REG_DWORD", "/d", "1", "/f"]);
        let _ = std::fs::write(pd.join("sas-policy-added"), b"1");
    }

    // tray icon for every user at sign-in (runs as that user)
    run("reg", &["add", RUN_KEY, "/v", "PortlessVNC Tray", "/t", "REG_SZ", "/d", &format!("\"{}\" --tray", target.display()), "/f"]);

    let bin = format!("\"{}\" --service", target.display());
    if !service_installed() {
        anyhow::ensure!(run("sc.exe", &["create", SERVICE_NAME, "binPath=", &bin, "start=", "auto", "DisplayName=", "PortlessVNC"]), "sc create failed");
    } else {
        run("sc.exe", &["config", SERVICE_NAME, "binPath=", &bin, "start=", "auto"]);
    }
    run("sc.exe", &["description", SERVICE_NAME, "PortlessVNC remote access (VNC server + built-in VPN client)"]);
    run("sc.exe", &["failure", SERVICE_NAME, "reset=", "60", "actions=", "restart/2000/restart/5000/restart/10000"]);
    anyhow::ensure!(run("sc.exe", &["start", SERVICE_NAME]), "the service was installed but did not start");
    // show the tray now, de-elevated (a second copy exits on its own if the
    // non-elevated launcher also starts one)
    run("runas", &["/trustlevel:0x20000", &format!("\"{}\" --tray", target.display())]);
    Ok(())
}

/// Copy hosting settings, the VPN profile (with re-encrypted credentials) and
/// the certificate from the installing user to the machine folder.
fn migrate_settings(user_dir: &Path, pd: &Path) -> anyhow::Result<()> {
    use base64::Engine;
    std::fs::create_dir_all(pd)?;
    let existing = pd.join("config.json").exists();
    if existing {
        // Updating an existing install: the service's own settings win. Its VPN
        // profile, saved login and hosting settings are only changed through
        // "Service settings" / "Enter VPN login", never by a reinstall.
        let mut machine = crate::config::Config::load(pd);
        machine.server.enabled = true;
        machine.save(pd)?;
        return Ok(());
    }
    let user = crate::config::Config::load(user_dir);
    let mut machine = if existing { crate::config::Config::load(pd) } else { user.clone() };
    if !existing {
        machine.recent.clear();
        machine.address_book.clear();
        machine.known_hosts.clear();
        machine.start_with_windows = false;
    }
    machine.server = user.server.clone();
    machine.server.enabled = true;
    machine.vpn.keep_connected = true;
    machine.vpn.resume = true;
    if let Some(p) = user.vpn.profiles.get(user.vpn.selected).cloned() {
        let src = PathBuf::from(&p.ovpn_path);
        let dest = pd.join("profile.ovpn");
        std::fs::copy(&src, &dest).map_err(|e| anyhow::anyhow!("copying VPN profile {}: {e}", src.display()))?;
        // user-scope DPAPI -> machine-scope DPAPI (the folder is admin/SYSTEM only)
        let password = p.password_protected.as_ref().and_then(|b| {
            let raw = base64::engine::general_purpose::STANDARD.decode(b).ok()?;
            super::unprotect(&raw)
        });
        let protected = password.and_then(|pw| super::protect_machine(&pw)).map(|b| base64::engine::general_purpose::STANDARD.encode(b));
        machine.vpn.profiles = vec![crate::config::VpnProfile { name: p.name.clone(), ovpn_path: dest.to_string_lossy().into_owned(), username: p.username.clone(), password_protected: protected }];
        machine.vpn.selected = 0;
    }
    machine.save(pd)?;
    for f in ["server-cert.der", "server-key.der"] {
        if !pd.join(f).exists() {
            let _ = std::fs::copy(user_dir.join(f), pd.join(f));
        }
    }
    Ok(())
}

/// Start the tray icon from the installed copy, as the current user.
pub fn start_tray() {
    let exe = install_dir().join("PortlessVNC.exe");
    let _ = std::process::Command::new(exe).arg("--tray").spawn();
}

/// `--uninstall-service` (must run elevated).
pub fn uninstall() -> i32 {
    if !is_elevated() {
        message("Administrator rights are required.");
        return 1;
    }
    run("sc.exe", &["stop", SERVICE_NAME]);
    std::thread::sleep(Duration::from_secs(3));
    let ok = run("sc.exe", &["delete", SERVICE_NAME]);
    let pd = machine_dir();
    if pd.join("sas-policy-added").exists() {
        run("reg", &["delete", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "/v", "SoftwareSASGeneration", "/f"]);
    }
    run("reg", &["delete", RUN_KEY, "/v", "PortlessVNC Tray", "/f"]);
    let _ = std::fs::remove_dir_all(&pd);
    let pf = install_dir();
    // close tray icons / windows started from the installed copy (not ourselves)
    let script = format!(
        "Get-Process PortlessVNC -ErrorAction SilentlyContinue | Where-Object {{ $_.Id -ne {} -and $_.Path -like '{}*' }} | Stop-Process -Force",
        std::process::id(),
        pf.display()
    );
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script]);
    let me_installed = std::env::current_exe().map(|e| e.starts_with(&pf)).unwrap_or(false);
    if me_installed {
        // we are running from that folder: remove it right after we exit
        let cmd = format!("ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{}\"", pf.display());
        let _ = std::process::Command::new("cmd").args(["/c", &cmd]).creation_flags(CREATE_NO_WINDOW_FLAG | 0x0000_0008).spawn();
    } else {
        for _ in 0..10 {
            if std::fs::remove_dir_all(&pf).is_ok() || !pf.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    message(if ok { "The PortlessVNC service was removed." } else { "The service could not be removed (was it installed?)." });
    if ok { 0 } else { 1 }
}
