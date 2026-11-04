//! Linux background service (systemd, runs as root from boot).
//!
//! `portlessvnc --service` is a supervisor: it finds the X server on the
//! active virtual terminal (the display manager's login screen, later the
//! user's session) together with its authority file, and runs the host
//! (`--agent`) against it. When the display, its owner or authority changes
//! (sign-in, sign-out, user switch) the agent is restarted on the new one.
//! Audio is recorded from the signed-in user's PulseAudio/PipeWire.

use crate::servicectl::{install_dir, machine_dir, public_dir, requests_dir};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const UNIT: &str = "/etc/systemd/system/portlessvnc.service";
/// tray icon for every user at sign-in
const TRAY_AUTOSTART: &str = "/etc/xdg/autostart/portlessvnc-tray.desktop";

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct XTarget {
    pub display: String,
    pub auth: Option<String>,
    pub user: String,
    pub uid: u32,
    pub greeter: bool,
}

fn active_vt() -> Option<u32> {
    let s = std::fs::read_to_string("/sys/class/tty/tty0/active").ok()?;
    s.trim().strip_prefix("tty")?.parse().ok()
}

fn loginctl(args: &[&str]) -> Option<String> {
    let out = Command::new("loginctl").args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// (user name, uid, is greeter) of the active graphical session on seat0.
fn active_session_user() -> Option<(String, u32, bool)> {
    let sid = loginctl(&["show-seat", "seat0", "-p", "ActiveSession", "--value"])?;
    if sid.is_empty() {
        return None;
    }
    let props = loginctl(&["show-session", &sid, "-p", "Name", "-p", "User", "-p", "Class"])?;
    let mut name = String::new();
    let mut uid = 0;
    let mut greeter = false;
    for l in props.lines() {
        match l.split_once('=') {
            Some(("Name", v)) => name = v.to_string(),
            Some(("User", v)) => uid = v.parse().unwrap_or(0),
            Some(("Class", v)) => greeter = v == "greeter",
            _ => {}
        }
    }
    Some((name, uid, greeter))
}

/// The X server on the active VT (or the first one found).
pub fn active_x() -> Option<XTarget> {
    let vt = active_vt();
    let mut found: Vec<(Option<u32>, String, Option<String>)> = Vec::new();
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(raw) = std::fs::read(e.path().join("cmdline")) else { continue };
        let args: Vec<String> = raw.split(|&b| b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
        let Some(bin) = args.first() else { continue };
        let base = bin.rsplit('/').next().unwrap_or(bin);
        if base != "Xorg" && base != "X" {
            continue;
        }
        let display = args.iter().find(|a| a.starts_with(':')).cloned().unwrap_or_else(|| ":0".into());
        let auth = args.iter().position(|a| a == "-auth").and_then(|i| args.get(i + 1)).cloned();
        let avt = args.iter().find_map(|a| a.strip_prefix("vt").and_then(|n| n.parse().ok()));
        found.push((avt, display, auth));
    }
    let pick = found.iter().find(|f| f.0.is_some() && f.0 == vt).or(found.first())?.clone();
    let (user, uid, greeter) = active_session_user().unwrap_or_default();
    let mut auth = pick.2;
    // sessions started without -auth (startx) use the user's ~/.Xauthority
    if auth.is_none() && !user.is_empty() {
        let home = PathBuf::from("/home").join(&user).join(".Xauthority");
        if home.exists() {
            auth = Some(home.to_string_lossy().into_owned());
        }
    }
    Some(XTarget { display: pick.1, auth, user, uid, greeter })
}

fn spawn_agent(target: &Option<XTarget>) -> std::io::Result<Child> {
    let exe = std::env::current_exe()?;
    let mut c = Command::new(exe);
    c.arg("--agent");
    match target {
        Some(t) => {
            c.env("DISPLAY", &t.display);
            match &t.auth {
                Some(a) => c.env("XAUTHORITY", a),
                None => c.env_remove("XAUTHORITY"),
            };
            if !t.user.is_empty() && !t.greeter {
                c.env("PVNC_SESSION_USER", &t.user).env("PVNC_SESSION_UID", t.uid.to_string());
            }
            if t.greeter {
                c.env("PVNC_DESKTOP", "Winlogon"); // shown as "sign-in screen" in the window
            }
        }
        None => {
            c.env_remove("DISPLAY");
        }
    }
    c.spawn()
}

fn stop(child: &mut Child) {
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(3) {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// `--service`: run by systemd as root.
pub fn run_supervisor() -> i32 {
    log::info!("PortlessVNC service {} starting", env!("CARGO_PKG_VERSION"));
    let mut current: Option<XTarget> = None;
    let mut child: Option<Child> = None;
    let mut last_start = Instant::now() - Duration::from_secs(60);
    loop {
        let target = active_x();
        let exited = child.as_mut().map(|c| matches!(c.try_wait(), Ok(Some(_)))).unwrap_or(true);
        if (target != current || exited) && last_start.elapsed() > Duration::from_secs(2) {
            if let Some(mut c) = child.take() {
                stop(&mut c);
            }
            match &target {
                Some(t) => log::info!("service: hosting display {} ({})", t.display, if t.greeter { "login screen".to_string() } else if t.user.is_empty() { "no session".into() } else { format!("user {}", t.user) }),
                None => log::info!("service: no X display yet (VPN only)"),
            }
            last_start = Instant::now();
            match spawn_agent(&target) {
                Ok(c) => child = Some(c),
                Err(e) => log::warn!("service: cannot start the host: {e}"),
            }
            current = target;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

// ---- elevation, install, uninstall ------------------------------------------

pub fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Re-run this exe as root through polkit (graphical password prompt).
pub fn run_elevated(args: &str) -> anyhow::Result<u32> {
    let exe = std::env::current_exe()?;
    let mut c = Command::new("pkexec");
    // pkexec drops the environment: pass the display through for GUI modes
    c.arg("env");
    for v in ["DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"] {
        if let Ok(val) = std::env::var(v) {
            c.arg(format!("{v}={val}"));
        }
    }
    c.arg(exe);
    c.args(args.split_whitespace().map(|a| a.trim_matches('"')));
    let st = c.status().map_err(|e| anyhow::anyhow!("pkexec is not available ({e}); install policykit-1 or run with sudo"))?;
    Ok(st.code().unwrap_or(1) as u32)
}

fn run(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args).status().map(|s| s.success()).unwrap_or(false)
}

pub fn service_installed() -> bool {
    Path::new(UNIT).exists()
}

/// Start the tray icon from the installed copy, as the current (normal) user.
pub fn start_tray() {
    let _ = Command::new(install_dir().join("portlessvnc")).arg("--tray").spawn();
}

/// `--install-service` (as root).
pub fn install(user_dir: &Path) -> i32 {
    match install_inner(user_dir) {
        Ok(()) => {
            log::info!("PortlessVNC service installed and started");
            0
        }
        Err(e) => {
            log::error!("installing the service failed: {e:#}");
            eprintln!("Installing the service failed: {e:#}");
            1
        }
    }
}

fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
}

fn install_inner(user_dir: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(is_elevated(), "root rights are required");
    let pf = install_dir();
    let pd = machine_dir();
    if service_installed() {
        run("systemctl", &["stop", "portlessvnc"]);
    }
    std::fs::create_dir_all(&pf)?;
    let target = pf.join("portlessvnc");
    let me = std::env::current_exe()?;
    if me != target {
        let tmp = target.with_extension("new");
        std::fs::copy(&me, &tmp)?;
        std::fs::rename(&tmp, &target)?;
    }
    set_mode(&target, 0o755);
    std::fs::create_dir_all(&pd)?;
    set_mode(&pd, 0o700); // settings, VPN login, key: root only
    std::fs::create_dir_all(requests_dir())?;
    set_mode(&public_dir(), 0o755); // status: everyone may read
    set_mode(&requests_dir(), 0o1777); // requests: everyone may drop one (sticky)
    migrate_settings(user_dir, &pd)?;
    std::fs::write(
        UNIT,
        format!(
            "[Unit]\nDescription=PortlessVNC remote access (VNC server + built-in VPN client)\nAfter=network-online.target display-manager.service\nWants=network-online.target\n\n[Service]\nExecStart={} --service\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
            target.display()
        ),
    )?;
    let _ = std::fs::create_dir_all("/etc/xdg/autostart");
    let _ = std::fs::write(TRAY_AUTOSTART, format!("[Desktop Entry]\nType=Application\nName=PortlessVNC tray\nComment=Status of the PortlessVNC service\nExec={} --tray\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n", target.display()));
    run("systemctl", &["daemon-reload"]);
    anyhow::ensure!(run("systemctl", &["enable", "--now", "portlessvnc"]), "systemctl could not start the service");
    Ok(())
}

/// First install: copy the user's hosting settings, VPN profile and saved
/// login (re-encrypted with the service's key) and certificate. Later
/// installs keep the service's own settings.
fn migrate_settings(user_dir: &Path, pd: &Path) -> anyhow::Result<()> {
    use base64::Engine;
    crate::config::set_machine_mode(); // secrets below use the service's key
    if pd.join("config.json").exists() {
        let mut machine = crate::config::Config::load(pd);
        machine.server.enabled = true;
        machine.save(pd)?;
        return Ok(());
    }
    let user = crate::config::Config::load(user_dir);
    let mut machine = user.clone();
    machine.recent.clear();
    machine.address_book.clear();
    machine.known_hosts.clear();
    machine.start_with_windows = false;
    machine.server.enabled = true;
    machine.vpn.keep_connected = true;
    machine.vpn.resume = true;
    if let Some(p) = user.vpn.profiles.get(user.vpn.selected).cloned() {
        let dest = pd.join("profile.ovpn");
        std::fs::copy(&p.ovpn_path, &dest).map_err(|e| anyhow::anyhow!("copying VPN profile {}: {e}", p.ovpn_path))?;
        let password = p.password_protected.as_ref().and_then(|b| {
            let raw = base64::engine::general_purpose::STANDARD.decode(b).ok()?;
            super::unprotect_from_dir(user_dir, &raw)
        });
        let protected = password.and_then(|pw| super::protect(&pw)).map(|b| base64::engine::general_purpose::STANDARD.encode(b));
        machine.vpn.profiles = vec![crate::config::VpnProfile { name: p.name.clone(), ovpn_path: dest.to_string_lossy().into_owned(), username: p.username.clone(), password_protected: protected }];
        machine.vpn.selected = 0;
    }
    machine.save(pd)?;
    for f in ["server-cert.der", "server-key.der"] {
        let _ = std::fs::copy(user_dir.join(f), pd.join(f));
    }
    Ok(())
}

/// `--uninstall-service` (as root).
pub fn uninstall() -> i32 {
    if !is_elevated() {
        eprintln!("root rights are required");
        return 1;
    }
    run("systemctl", &["disable", "--now", "portlessvnc"]);
    let _ = std::fs::remove_file(UNIT);
    let _ = std::fs::remove_file(TRAY_AUTOSTART);
    run("systemctl", &["daemon-reload"]);
    let _ = std::fs::remove_dir_all(machine_dir());
    let _ = std::fs::remove_dir_all(public_dir().parent().unwrap_or(Path::new("/var/lib/portlessvnc")));
    let _ = std::fs::remove_dir_all(install_dir());
    log::info!("PortlessVNC service removed");
    0
}
