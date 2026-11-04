//! Linux (X11) implementation: shared-memory screen capture, XTest input,
//! clipboard, per-user install/autostart and secret storage.

pub mod appinstall;
pub mod service;
pub mod tray;
pub mod capture;
pub mod clipboard;
pub mod input;

use aes_gcm::aead::{Aead, KeyInit};
use std::io::Write;
use std::path::PathBuf;

/// Per-user key that encrypts saved passwords (file readable only by the
/// user, like ~/.ssh keys). Linux has no DPAPI equivalent without a keyring.
fn secret_key() -> Option<[u8; 32]> {
    key_at(&crate::config::config_dir().join(".secret-key"), true)
}

/// Read (or create) the 32-byte key at path.
fn key_at(path: &std::path::Path, create: bool) -> Option<[u8; 32]> {
    let path = path.to_path_buf();
    if let Ok(b) = std::fs::read(&path) {
        if b.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            return Some(k);
        }
    }
    if !create {
        return None;
    }
    let mut k = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut k);
    std::fs::create_dir_all(path.parent()?).ok()?;
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path).ok()?
    };
    f.write_all(&k).ok()?;
    Some(k)
}

pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
    let key = secret_key()?;
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).ok()?;
    let mut nonce = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
    let ct = cipher.encrypt(aes_gcm::Nonce::from_slice(&nonce), data).ok()?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Some(out)
}

pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    unprotect_with(&secret_key()?, data)
}

/// Decrypt a secret saved by another settings folder (e.g. the installing
/// user's, when the service takes over their VPN login).
pub fn unprotect_from_dir(dir: &std::path::Path, data: &[u8]) -> Option<Vec<u8>> {
    unprotect_with(&key_at(&dir.join(".secret-key"), false)?, data)
}

fn unprotect_with(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let key = *key;
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).ok()?;
    cipher.decrypt(aes_gcm::Nonce::from_slice(&data[..12]), &data[12..]).ok()
}

pub fn protect_for_config(data: &[u8]) -> Option<Vec<u8>> {
    protect(data)
}

fn autostart_file() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("autostart").join("portlessvnc.desktop"))
}

/// "Start when I sign in": an XDG autostart entry (works on GNOME, Cinnamon,
/// MATE, XFCE, KDE).
pub fn set_autostart(enabled: bool) -> anyhow::Result<()> {
    let file = autostart_file().ok_or_else(|| anyhow::anyhow!("no config folder"))?;
    if !enabled {
        let _ = std::fs::remove_file(&file);
        return Ok(());
    }
    std::fs::create_dir_all(file.parent().unwrap())?;
    let exe = std::env::current_exe()?;
    std::fs::write(
        &file,
        format!("[Desktop Entry]\nType=Application\nName=PortlessVNC\nComment=Remote access over your VPN\nExec=\"{}\" --minimized\nTerminal=false\nX-GNOME-Autostart-enabled=true\n", exe.display()),
    )?;
    Ok(())
}

/// Linux accounts (PAM) are not supported yet.
pub fn check_system_login(_user: &str, _pass: &str) -> bool {
    false
}

pub fn current_user() -> String {
    std::env::var("USER").unwrap_or_default()
}
