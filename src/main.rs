//! PortlessVNC - hybrid VNC server + viewer with a built-in userspace
//! OpenVPN client for remote access without port forwarding.
//!
//! Command line:
//!   --minimized   start minimized (used by "start with Windows")
//!   --host-only   only show the hosting panel (no connect UI)
//!   --connect X   open a viewer session to X at startup
//!   --install-service / --uninstall-service   (asks for admin rights)
//!   --service-config                          edit the service's settings (admin)
//!   --service / --agent                       used by Windows / the service itself

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod agent;
mod app;
mod audio;
mod config;
mod ext;
mod gui;
mod hub;
mod instance;
mod keys;
mod netinfo;
mod platform;
mod rfb;
mod selftest;
mod server;
mod servicectl;
mod tls;
mod util;
mod viewer;
mod vpn;

use eframe::egui;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let has = |f: &str| args.iter().any(|a| a == f);
    #[cfg(windows)]
    {
        // service mode (no console: log to the machine folder)
        if has("--service") {
            util::init_logging_to(Some(servicectl::public_dir().join("service.log")));
            std::process::exit(platform::service::run_dispatcher());
        }
        if has("--agent") {
            util::init_logging_to(Some(servicectl::public_dir().join("agent.log")));
            std::process::exit(agent::run());
        }
    }
    #[cfg(target_os = "linux")]
    {
        // service mode (systemd, root): log to the public folder
        if has("--service") {
            util::init_logging_to(Some(servicectl::public_dir().join("service.log")));
            std::process::exit(platform::service::run_supervisor());
        }
        if has("--agent") {
            util::init_logging_to(Some(servicectl::public_dir().join("agent.log")));
            std::process::exit(agent::run());
        }
    }
    util::init_logging();
    // one Service settings window: a second one (and its password prompt) just raises the first
    if has("--service-config") && instance::hand_off(true, "show") {
        std::process::exit(0);
    }
    #[cfg(target_os = "linux")]
    {
        use platform::service;
        if let Some(i) = args.iter().position(|a| a == "--install-service") {
            let user_dir = args.get(i + 1).map(std::path::PathBuf::from).unwrap_or_else(config::user_config_dir);
            let code = if service::is_elevated() {
                service::install(&user_dir)
            } else {
                let code = service::run_elevated(&format!("--install-service {}", user_dir.display())).map(|c| c as i32).unwrap_or(1);
                if code == 0 {
                    service::start_tray(); // as this user
                }
                code
            };
            std::process::exit(code);
        }
        if has("--tray") {
            std::process::exit(platform::tray::run());
        }
        if has("--uninstall-service") {
            let code = if service::is_elevated() { service::uninstall() } else { service::run_elevated("--uninstall-service").map(|c| c as i32).unwrap_or(1) };
            std::process::exit(code);
        }
        if has("--service-config") && !service::is_elevated() {
            let args = if has("--vpn-login") { "--service-config --vpn-login" } else { "--service-config" };
            std::process::exit(service::run_elevated(args).map(|c| c as i32).unwrap_or(1));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if has("--install-app") {
            std::process::exit(platform::appinstall::install());
        }
        if has("--uninstall-app") {
            std::process::exit(platform::appinstall::uninstall());
        }
    }
    #[cfg(windows)]
    {
        use platform::service;
        if let Some(i) = args.iter().position(|a| a == "--install-service") {
            let user_dir = args.get(i + 1).map(std::path::PathBuf::from).unwrap_or_else(config::user_config_dir);
            let code = if service::is_elevated() {
                service::install(&user_dir)
            } else {
                let code = service::run_elevated(&format!("--install-service \"{}\"", user_dir.display())).map(|c| c as i32).unwrap_or(1);
                if code == 0 {
                    service::start_tray(); // as this (normal) user, not elevated
                }
                code
            };
            std::process::exit(code);
        }
        if has("--install-app") {
            std::process::exit(platform::appinstall::install());
        }
        if has("--uninstall-app") {
            std::process::exit(platform::appinstall::uninstall());
        }
        if has("--tray") {
            std::process::exit(platform::tray::run());
        }
        if has("--uninstall-service") {
            let code = if service::is_elevated() { service::uninstall() } else { service::run_elevated("--uninstall-service").map(|c| c as i32).unwrap_or(1) };
            std::process::exit(code);
        }
        if has("--service-config") && !service::is_elevated() {
            let args = if has("--vpn-login") { "--service-config --vpn-login" } else { "--service-config" };
            std::process::exit(service::run_elevated(args).map(|c| c as i32).unwrap_or(1));
        }
    }
    let service_config = has("--service-config");
    if service_config {
        config::set_machine_mode();
    }
    let minimized = has("--minimized");
    let host_only = has("--host-only");
    let connect = args.iter().position(|a| a == "--connect").and_then(|i| args.get(i + 1).cloned());
    if let Some(i) = args.iter().position(|a| a == "--keyremote") {
        std::process::exit(selftest::key_remote(&args[i + 1..]));
    }
    if let Some(i) = args.iter().position(|a| a == "--vpnpair") {
        std::process::exit(selftest::vpn_pair(args.get(i + 1).map(|s| s.as_str()).unwrap_or("")));
    }
    if let Some(i) = args.iter().position(|a| a == "--vpntest") {
        std::process::exit(selftest::vpn_test(args.get(i + 1).map(|s| s.as_str()).unwrap_or("")));
    }
    #[cfg(windows)]
    if has("--hookdiag") {
        // Keyboard-capture check for users: type in ANY other window for 15 s.
        use windows::core::w;
        use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};
        unsafe {
            MessageBoxW(None, w!("Click OK, then type a few words in any other window (e.g. Notepad) for 15 seconds."), w!("PortlessVNC keyboard test"), MB_OK | MB_ICONINFORMATION);
        }
        platform::keyhook::install();
        std::thread::sleep(std::time::Duration::from_secs(15));
        let n = platform::keyhook::HOOK_CALLS.load(std::sync::atomic::Ordering::Relaxed);
        let msg = format!("The keyboard hook saw {n} key events (each key press and release counts as one).\n\n{}\0", if n > 0 { "Key capture works on this computer." } else { "No keys were seen: keyboard capture is blocked on this computer (security software or policy)." });
        let wide: Vec<u16> = msg.encode_utf16().collect();
        unsafe {
            MessageBoxW(None, windows::core::PCWSTR(wide.as_ptr()), w!("PortlessVNC keyboard test"), MB_OK | MB_ICONINFORMATION);
        }
        std::process::exit(0);
    }
    #[cfg(windows)]
    if has("--hooktest") {
        platform::keyhook::install();
        std::thread::sleep(std::time::Duration::from_millis(500));
        unsafe {
            use windows::Win32::UI::Input::KeyboardAndMouse::{keybd_event, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP};
            keybd_event(0x10, 0x2a, KEYBD_EVENT_FLAGS(0), 0);
            keybd_event(0x10, 0x2a, KEYEVENTF_KEYUP, 0);
        }
        std::thread::sleep(std::time::Duration::from_millis(4000));
        println!("hook callbacks: {}", platform::keyhook::HOOK_CALLS.load(std::sync::atomic::Ordering::Relaxed));
        std::process::exit(0);
    }
    if has("--selftest") {
        std::process::exit(selftest::run());
    }
    // one window of each kind: hand this launch to the running one
    let title = if service_config { "PortlessVNC - Service settings" } else { "PortlessVNC" };
    let msg = match (&connect, minimized) {
        (Some(a), _) => format!("connect {a}"),
        (None, true) => "none".to_string(), // sign-in autostart: leave it as it is
        (None, false) => "show".to_string(),
    };
    if !instance::claim(service_config, title, &msg) {
        std::process::exit(0);
    }

    let core = match app::Core::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("PortlessVNC failed to start: {e:#}");
            log::error!("startup failed: {e:#}");
            std::process::exit(1);
        }
    };
    #[cfg(windows)]
    {
        // before the GUI starts, on its own thread (see keyhook.rs)
        platform::keyhook::install();
        platform::clipboard::start(core.hub.clone());
        platform::keyhook::CAPTURE_SYSTEM_KEYS.store(core.cfg.read().viewer.capture_system_keys, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(target_os = "linux")]
    platform::clipboard::start(core.hub.clone());
    // the service hosts this computer; this window only views (or edits the service's settings)
    let service_running = service_config || servicectl::read_status().is_some();
    core.server.set_suppressed(service_running);
    if !service_config {
        core.server.restart();
    }
    log::info!("PortlessVNC {} started (settings in {})", env!("CARGO_PKG_VERSION"), core.dir.display());

    let run = |renderer: eframe::Renderer| -> Result<(), eframe::Error> {
        let options = eframe::NativeOptions {
            renderer,
            viewport: egui::ViewportBuilder::default().with_title(title).with_inner_size([1060.0, 700.0]).with_min_inner_size([640.0, 480.0]),
            ..Default::default()
        };
        let core = core.clone();
        let connect = connect.clone();
        eframe::run_native(
            "PortlessVNC",
            options,
            Box::new(move |cc| {
                instance::set_context(&cc.egui_ctx);
                let mut a = gui::App::new(cc, core.clone(), host_only || service_config, minimized, service_config);
                if let Some(addr) = connect {
                    a.connect_to(&addr, "", "");
                }
                Ok(Box::new(a))
            }),
        )
    };
    // wgpu (Direct3D 12 / Vulkan) first; fall back to OpenGL on old or GPU-less machines.
    if let Err(e) = run(eframe::Renderer::Wgpu) {
        log::warn!("wgpu renderer failed ({e}); falling back to OpenGL");
        if let Err(e) = run(eframe::Renderer::Glow) {
            eprintln!("Could not open a window: {e}");
        }
    }
    let _ = Arc::strong_count(&core);
}
