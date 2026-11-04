//! Per-user install of the program itself (no admin rights): copy to
//! %LOCALAPPDATA%\Programs\PortlessVNC, Start menu (and optional desktop)
//! shortcut, and an "Apps & features" entry so Windows can uninstall it.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use windows::core::{w, PCWSTR};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDYES, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_YESNO, MESSAGEBOX_STYLE};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const UNINSTALL_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\PortlessVNC";

pub fn app_dir() -> PathBuf {
    dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")).join("Programs").join("PortlessVNC")
}

pub fn installed_exe() -> PathBuf {
    app_dir().join("PortlessVNC.exe")
}

pub fn is_installed() -> bool {
    installed_exe().exists()
}

/// Is this process running from the installed copy?
pub fn running_installed() -> bool {
    std::env::current_exe().map(|e| e.starts_with(app_dir())).unwrap_or(false)
}

fn ask(text: &str, style: MESSAGEBOX_STYLE) -> bool {
    let t = super::wide(text);
    unsafe { MessageBoxW(None, PCWSTR(t.as_ptr()), w!("PortlessVNC"), style) == IDYES }
}

fn tell(text: &str) {
    let t = super::wide(text);
    unsafe {
        MessageBoxW(None, PCWSTR(t.as_ptr()), w!("PortlessVNC"), MB_OK | MB_ICONINFORMATION);
    }
}

fn run(cmd: &str, args: &[&str]) -> bool {
    std::process::Command::new(cmd).args(args).creation_flags(CREATE_NO_WINDOW).status().map(|s| s.success()).unwrap_or(false)
}

/// Create a .lnk shortcut (via the Windows Script Host COM object).
fn shortcut(lnk: &Path, target: &Path) -> bool {
    let q = |p: &Path| p.display().to_string().replace('\'', "''");
    let script = format!(
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath = '{}'; $s.WorkingDirectory = '{}'; $s.Description = 'PortlessVNC remote access'; $s.Save()",
        q(lnk),
        q(target),
        q(target.parent().unwrap_or(Path::new(".")))
    );
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script])
}

fn start_menu_lnk() -> Option<PathBuf> {
    Some(dirs::data_dir()?.join(r"Microsoft\Windows\Start Menu\Programs\PortlessVNC.lnk"))
}

fn desktop_lnk() -> Option<PathBuf> {
    Some(dirs::desktop_dir()?.join("PortlessVNC.lnk"))
}

/// Close PortlessVNC windows running from the per-user install folder (not
/// ourselves, not the service or its tray).
fn close_installed_copies() {
    let script = format!(
        "Get-Process PortlessVNC -ErrorAction SilentlyContinue | Where-Object {{ $_.Id -ne {} -and $_.Path -like '{}*' }} | Stop-Process -Force",
        std::process::id(),
        app_dir().display().to_string().replace('\'', "''")
    );
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script]);
}

/// `--install-app`: copy this exe into the user's programs folder, add
/// shortcuts and the Apps & features entry, then start the installed copy.
pub fn install() -> i32 {
    let dir = app_dir();
    let target = installed_exe();
    let me = match std::env::current_exe() {
        Ok(m) => m,
        Err(e) => {
            tell(&format!("Install failed: {e}"));
            return 1;
        }
    };
    if std::fs::create_dir_all(&dir).is_err() {
        tell("Install failed: cannot create the program folder.");
        return 1;
    }
    if me != target {
        // an older installed copy may still be running
        close_installed_copies();
        let mut ok = false;
        for _ in 0..10 {
            if std::fs::copy(&me, &target).is_ok() {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        if !ok {
            tell(&format!("Install failed: could not copy the program to\n{}\n\nClose other PortlessVNC windows and try again.", dir.display()));
            return 1;
        }
    }
    if let Some(l) = start_menu_lnk() {
        shortcut(&l, &target);
    }
    if ask("PortlessVNC is installed for your account (Start menu and Apps & features).\n\nAlso put a shortcut on the desktop?", MB_YESNO | MB_ICONQUESTION) {
        if let Some(l) = desktop_lnk() {
            shortcut(&l, &target);
        }
    }
    let t = target.display().to_string();
    let uninstall = format!("\"{t}\" --uninstall-app");
    for (name, kind, value) in [
        ("DisplayName", "REG_SZ", "PortlessVNC".to_string()),
        ("DisplayVersion", "REG_SZ", env!("CARGO_PKG_VERSION").to_string()),
        ("Publisher", "REG_SZ", "PortlessVNC".to_string()),
        ("DisplayIcon", "REG_SZ", t.clone()),
        ("InstallLocation", "REG_SZ", dir.display().to_string()),
        ("UninstallString", "REG_SZ", uninstall),
        ("NoModify", "REG_DWORD", "1".to_string()),
        ("NoRepair", "REG_DWORD", "1".to_string()),
    ] {
        run("reg", &["add", UNINSTALL_KEY, "/v", name, "/t", kind, "/d", &value, "/f"]);
    }
    // "start with Windows" should launch the installed copy from now on
    let run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    if run("reg", &["query", run_key, "/v", "PortlessVNC"]) {
        run("reg", &["add", run_key, "/v", "PortlessVNC", "/t", "REG_SZ", "/d", &format!("\"{t}\" --minimized"), "/f"]);
    }
    if me != target {
        let _ = std::process::Command::new(&target).spawn();
    }
    0
}

/// `--uninstall-app`: remove the per-user install (optionally the settings).
pub fn uninstall() -> i32 {
    if !ask("Uninstall PortlessVNC from this account?", MB_YESNO | MB_ICONQUESTION) {
        return 1;
    }
    if super::service::service_installed() && ask("The PortlessVNC background service is also installed.\n\nRemove it too? (asks for administrator rights)", MB_YESNO | MB_ICONQUESTION) {
        let _ = super::service::run_elevated("--uninstall-service");
    }
    let wipe_settings = ask("Also delete your PortlessVNC settings (address book, VPN profiles, saved logins)?", MB_YESNO | MB_ICONQUESTION);
    for l in [start_menu_lnk(), desktop_lnk()].into_iter().flatten() {
        let _ = std::fs::remove_file(l);
    }
    run("reg", &["delete", UNINSTALL_KEY, "/f"]);
    run("reg", &["delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "PortlessVNC", "/f"]);
    if wipe_settings {
        let _ = std::fs::remove_dir_all(crate::config::user_config_dir());
    }
    // close other copies, then remove the folder once we have exited
    close_installed_copies();
    let dir = app_dir();
    let cmd = format!("ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{}\"", dir.display());
    let _ = std::process::Command::new("cmd").args(["/c", &cmd]).creation_flags(CREATE_NO_WINDOW | 0x0000_0008).spawn();
    tell("PortlessVNC was uninstalled.");
    0
}
