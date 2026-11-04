//! Non-Windows placeholders (Linux/macOS support is planned).

pub mod capture {
    use crate::rfb::encode::Frame;
    pub struct MonitorInfo {
        pub name: String,
        pub x: i32,
        pub y: i32,
        pub width: u32,
        pub height: u32,
    }
    pub fn monitors() -> Vec<MonitorInfo> {
        Vec::new()
    }
    pub struct Capturer;
    impl Capturer {
        pub fn new(_monitor: usize) -> anyhow::Result<Self> {
            anyhow::bail!("screen capture is not implemented on this platform yet")
        }
        pub fn capture(&mut self, _timeout_ms: u32) -> anyhow::Result<Option<Frame>> {
            Ok(None)
        }
        pub fn origin(&self) -> (i32, i32) {
            (0, 0)
        }
        pub fn cursor(&mut self) -> Option<crate::server::CursorShape> {
            None
        }
    }
}

pub mod input {
    pub fn pointer(_x: i32, _y: i32, _origin: (i32, i32), _mask: u8, _prev: u8) {}
    pub fn key_sym(_down: bool, _keysym: u32) {}
    pub fn key_scancode(_down: bool, _xt: u32, _keysym: u32) {}
}

pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
    Some(data.to_vec())
}
pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    Some(data.to_vec())
}
pub fn set_autostart(_enabled: bool) -> anyhow::Result<()> {
    Ok(())
}
pub fn check_system_login(_user: &str, _pass: &str) -> bool {
    false
}
pub fn current_user() -> String {
    std::env::var("USER").unwrap_or_default()
}
