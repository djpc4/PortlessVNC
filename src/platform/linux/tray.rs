//! `portlessvnc --tray`: notification-area icon for service mode on Linux
//! (StatusNotifierItem over D-Bus: shown by Cinnamon, KDE, XFCE, MATE; GNOME
//! needs the AppIndicator extension). Runs as the signed-in user, started at
//! sign-in from /etc/xdg/autostart while the service is installed.

use crate::servicectl::{self, Status};
use ksni::blocking::TrayMethods;
use ksni::menu::StandardItem;
use ksni::{Icon, MenuItem, ToolTip};
use std::time::Duration;

struct PvncTray {
    status: Option<Status>,
    clipboard: Option<arboard::Clipboard>,
}

fn addr(s: &Status) -> Option<String> {
    s.vpn_ip.as_ref().map(|ip| if s.vpn_port == 5900 { ip.clone() } else { format!("{ip}:{}", s.vpn_port) })
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

impl PvncTray {
    fn copy(&mut self, text: String) {
        if self.clipboard.is_none() {
            self.clipboard = arboard::Clipboard::new().ok();
        }
        if let Some(cb) = self.clipboard.as_mut() {
            let _ = cb.set_text(text); // the clipboard object stays alive to serve it
        }
    }
}

/// 32x32 dot (ARGB32, network byte order as SNI expects).
fn dot(rgb: (u8, u8, u8)) -> Icon {
    const S: i32 = 32;
    let mut data = Vec::with_capacity((S * S * 4) as usize);
    let c = (S as f32 - 1.0) / 2.0;
    for y in 0..S {
        for x in 0..S {
            let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
            let px = if d <= 12.0 {
                [0xFF, rgb.0, rgb.1, rgb.2]
            } else if d <= 15.0 {
                [0xFF, 0xF0, 0xF0, 0xF0]
            } else {
                [0, 0, 0, 0]
            };
            data.extend_from_slice(&px);
        }
    }
    Icon { width: S, height: S, data }
}

impl ksni::Tray for PvncTray {
    fn id(&self) -> String {
        "portlessvnc".into()
    }
    fn title(&self) -> String {
        "PortlessVNC".into()
    }
    fn icon_pixmap(&self) -> Vec<Icon> {
        let rgb = match &self.status {
            Some(s) if s.vpn_ip.is_some() => (0x2f, 0x9e, 0x6b),
            Some(s) if s.vpn_state == "connecting" || s.vpn_state == "reconnecting" => (0xe0, 0x8a, 0x20),
            _ => (0x80, 0x80, 0x80),
        };
        vec![dot(rgb)]
    }
    fn tool_tip(&self) -> ToolTip {
        let description = match &self.status {
            Some(s) => match addr(s) {
                Some(a) => format!("{a}{}", if s.viewers.is_empty() { String::new() } else { format!(" ({} connected)", s.viewers.len()) }),
                None => format!("VPN {}", s.vpn_state),
            },
            None => "service not running".into(),
        };
        ToolTip { title: "PortlessVNC".into(), description, icon_name: String::new(), icon_pixmap: Vec::new() }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        spawn(None);
    }
    fn menu(&self) -> Vec<MenuItem<Self>> {
        let s = self.status.clone();
        let mut items: Vec<MenuItem<Self>> = Vec::new();
        match s.as_ref().and_then(addr) {
            Some(a) => items.push(
                StandardItem {
                    label: format!("VPN address: {a}  (copy)"),
                    activate: Box::new(move |t: &mut Self| t.copy(a.clone())),
                    ..Default::default()
                }
                .into(),
            ),
            None => items.push(StandardItem { label: format!("VPN: {}", s.as_ref().map(|s| s.vpn_state.clone()).unwrap_or_else(|| "service not running".into())), enabled: false, ..Default::default() }.into()),
        }
        match s.as_ref().and_then(|s| s.otp.clone()) {
            Some(otp) => {
                items.push(StandardItem { label: format!("One-time password: {otp}  (copy)"), activate: Box::new(move |t: &mut Self| t.copy(otp.clone())), ..Default::default() }.into());
                items.push(StandardItem { label: "New one-time password".into(), activate: Box::new(|_| servicectl::request("new-otp")), ..Default::default() }.into());
            }
            None => items.push(StandardItem { label: "One-time password: off".into(), enabled: false, ..Default::default() }.into()),
        }
        if let Some(n) = s.as_ref().map(|s| s.viewers.len()).filter(|n| *n > 0) {
            items.push(StandardItem { label: format!("{n} viewer(s) connected"), enabled: false, ..Default::default() }.into());
        }
        items.push(StandardItem { label: "Reconnect VPN".into(), enabled: s.is_some(), activate: Box::new(|_| servicectl::request("reconnect")), ..Default::default() }.into());
        items.push(MenuItem::Separator);
        items.push(StandardItem { label: "Open PortlessVNC".into(), activate: Box::new(|_| spawn(None)), ..Default::default() }.into());
        items.push(StandardItem { label: "Service settings...".into(), activate: Box::new(|_| spawn(Some("--service-config"))), ..Default::default() }.into());
        items.push(MenuItem::Separator);
        items.push(StandardItem { label: "Hide tray icon".into(), activate: Box::new(|_| std::process::exit(0)), ..Default::default() }.into());
        items
    }
}

pub fn run() -> i32 {
    let tray = PvncTray { status: servicectl::read_status(), clipboard: None };
    let handle = match tray.spawn() {
        Ok(h) => h,
        Err(e) => {
            log::warn!("No system tray available ({e:?}); on GNOME install the AppIndicator extension");
            return 1;
        }
    };
    let mut missing = 0u32;
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let status = servicectl::read_status();
        // the service was removed: nothing to show any more
        missing = if status.is_none() { missing + 1 } else { 0 };
        if missing > 8 && !super::service::service_installed() {
            return 0;
        }
        if handle.update(|t| t.status = status).is_none() {
            return 0; // tray host went away
        }
    }
}
