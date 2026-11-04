//! Classic VNC authentication (DES challenge/response) and the standard
//! fixed-key password obfuscation used by VNC servers to store passwords.

use des::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use des::Des;

/// Fixed key used by RealVNC/TightVNC/UltraVNC to obfuscate stored passwords
/// ({23,82,107,6,35,78,88,7}), already bit-reversed for standard DES.
const OBFUSCATION_KEY: [u8; 8] = [0xE8, 0x4A, 0xD6, 0x60, 0xC4, 0x72, 0x1A, 0xE0];

fn vnc_key(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    for (i, b) in password.bytes().take(8).enumerate() {
        // VNC uses the bits of each key byte in reverse order.
        key[i] = b.reverse_bits();
    }
    key
}

fn des_ecb_encrypt(key: &[u8; 8], data: &mut [u8]) {
    let cipher = Des::new_from_slice(key).expect("8 byte key");
    for chunk in data.chunks_mut(8) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
}

fn des_ecb_decrypt(key: &[u8; 8], data: &mut [u8]) {
    let cipher = Des::new_from_slice(key).expect("8 byte key");
    for chunk in data.chunks_mut(8) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
}

/// Response to a 16-byte VNC auth challenge.
pub fn response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let key = vnc_key(password);
    let mut out = *challenge;
    des_ecb_encrypt(&key, &mut out);
    out
}

pub fn verify(password: &str, challenge: &[u8; 16], resp: &[u8]) -> bool {
    if resp.len() != 16 {
        return false;
    }
    let expected = response(password, challenge);
    // constant-time-ish compare
    expected.iter().zip(resp).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Obfuscate a password the way standard VNC servers store it (hex of 8 DES bytes).
pub fn obfuscate(password: &str) -> String {
    let mut buf = [0u8; 8];
    for (i, b) in password.bytes().take(8).enumerate() {
        buf[i] = b;
    }
    des_ecb_encrypt(&OBFUSCATION_KEY, &mut buf);
    hex::encode(buf)
}

pub fn deobfuscate(hex_str: &str) -> Option<String> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes);
    des_ecb_decrypt(&OBFUSCATION_KEY, &mut buf);
    let end = buf.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8(buf[..end].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn obfuscation_roundtrip() {
        let o = obfuscate("secret1");
        assert_eq!(deobfuscate(&o).unwrap(), "secret1");
    }
    #[test]
    fn known_vector() {
        // "password" obfuscated with the standard key is a well-known value.
        assert_eq!(obfuscate("password"), "dbd83cfd727a1458");
    }
}
