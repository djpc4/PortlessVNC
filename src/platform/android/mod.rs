//! Android (client only): no screen capture or input injection; secrets are
//! encrypted with a key kept in the app's private storage (other apps cannot
//! read it); the Java side (MainActivity) provides the keyboard, file picker,
//! clipboard and Downloads.

pub mod java;

pub use super::stub::{capture, check_system_login, input};

use aes_gcm::aead::{Aead, KeyInit};
use std::io::Write;

fn secret_key() -> Option<[u8; 32]> {
    let path = crate::config::config_dir().join(".secret-key");
    if let Ok(b) = std::fs::read(&path) {
        if b.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            return Some(k);
        }
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
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&secret_key()?).ok()?;
    let mut nonce = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
    let ct = cipher.encrypt(aes_gcm::Nonce::from_slice(&nonce), data).ok()?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Some(out)
}

pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&secret_key()?).ok()?;
    cipher.decrypt(aes_gcm::Nonce::from_slice(&data[..12]), &data[12..]).ok()
}

pub fn protect_for_config(data: &[u8]) -> Option<Vec<u8>> {
    protect(data)
}

pub fn current_user() -> String {
    String::new()
}
