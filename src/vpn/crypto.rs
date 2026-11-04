//! OpenVPN cryptography: PRF/key expansion, control channel wrapping
//! (tls-auth / tls-crypt / tls-crypt-v2) and data channel ciphers.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use anyhow::{bail, Result};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Digest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Md5,
}

impl Digest {
    pub fn parse(s: &str) -> Option<Digest> {
        Some(match s.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Digest::Sha1,
            "SHA256" => Digest::Sha256,
            "SHA384" => Digest::Sha384,
            "SHA512" => Digest::Sha512,
            "MD5" => Digest::Md5,
            _ => return None,
        })
    }
    pub fn len(self) -> usize {
        match self {
            Digest::Sha1 => 20,
            Digest::Sha256 => 32,
            Digest::Sha384 => 48,
            Digest::Sha512 => 64,
            Digest::Md5 => 16,
        }
    }
    pub fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        macro_rules! run {
            ($t:ty) => {{
                let mut m = <Hmac<$t> as Mac>::new_from_slice(key).expect("hmac key");
                for p in parts {
                    m.update(p);
                }
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self {
            Digest::Sha1 => run!(sha1::Sha1),
            Digest::Sha256 => run!(sha2::Sha256),
            Digest::Sha384 => run!(sha2::Sha384),
            Digest::Sha512 => run!(sha2::Sha512),
            Digest::Md5 => run!(md5::Md5),
        }
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---- TLS 1.0 PRF as used by OpenVPN's legacy key derivation ---------------

fn p_hash(d: Digest, secret: &[u8], seed: &[u8], out: &mut [u8]) {
    let mut a = d.hmac(secret, &[seed]);
    let mut pos = 0;
    while pos < out.len() {
        let chunk = d.hmac(secret, &[&a, seed]);
        let n = chunk.len().min(out.len() - pos);
        out[pos..pos + n].copy_from_slice(&chunk[..n]);
        pos += n;
        a = d.hmac(secret, &[&a]);
    }
}

pub fn tls1_prf(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let half = (secret.len() + 1) / 2;
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() - half..];
    let mut full_seed = label.to_vec();
    full_seed.extend_from_slice(seed);
    let mut o1 = vec![0u8; len];
    let mut o2 = vec![0u8; len];
    p_hash(Digest::Md5, s1, &full_seed, &mut o1);
    p_hash(Digest::Sha1, s2, &full_seed, &mut o2);
    o1.iter().zip(&o2).map(|(a, b)| a ^ b).collect()
}

/// OpenVPN key-method-2 key expansion (pre-2.6 servers / no tls-ekm).
pub fn openvpn_prf_keys(pre_master: &[u8], c_rand1: &[u8], s_rand1: &[u8], c_rand2: &[u8], s_rand2: &[u8], c_sid: &[u8; 8], s_sid: &[u8; 8]) -> Vec<u8> {
    let mut seed1 = c_rand1.to_vec();
    seed1.extend_from_slice(s_rand1);
    let master = tls1_prf(pre_master, b"OpenVPN master secret", &seed1, 48);
    let mut seed2 = c_rand2.to_vec();
    seed2.extend_from_slice(s_rand2);
    seed2.extend_from_slice(c_sid);
    seed2.extend_from_slice(s_sid);
    tls1_prf(&master, b"OpenVPN key expansion", &seed2, 256)
}

/// Split a 256-byte "key2" block into (cipher, hmac) halves of key `idx` (0/1).
pub fn key2_part(block: &[u8], idx: usize) -> (&[u8], &[u8]) {
    let base = idx * 128;
    (&block[base..base + 64], &block[base + 64..base + 128])
}

// ---- control channel wrapping ----------------------------------------------

pub enum Wrap {
    None,
    Auth { digest: Digest, out_key: Vec<u8>, in_keys: Vec<Vec<u8>>, pid: u32 },
    Crypt { out_c: Vec<u8>, out_h: Vec<u8>, in_keys: Vec<(Vec<u8>, Vec<u8>)>, pid: u32 },
}

fn unix_time() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0)
}

impl Wrap {
    /// `direction` follows OpenVPN: Some(1) = this side uses key 1 to send.
    pub fn tls_auth(key: &[u8], digest: Digest, direction: Option<u8>) -> Wrap {
        let h = |i: usize| key2_part(key, i).1[..digest.len()].to_vec();
        match direction {
            Some(1) => Wrap::Auth { digest, out_key: h(1), in_keys: vec![h(0), h(1)], pid: 1 },
            Some(0) => Wrap::Auth { digest, out_key: h(0), in_keys: vec![h(1), h(0)], pid: 1 },
            _ => Wrap::Auth { digest, out_key: h(0), in_keys: vec![h(0)], pid: 1 },
        }
    }

    /// tls-crypt: the client sends with key 1 and receives with key 0.
    pub fn tls_crypt(key: &[u8]) -> Wrap {
        let k = |i: usize| {
            let (c, h) = key2_part(key, i);
            (c[..32].to_vec(), h[..32].to_vec())
        };
        let (oc, oh) = k(1);
        Wrap::Crypt { out_c: oc, out_h: oh, in_keys: vec![k(0), k(1)], pid: 1 }
    }

    /// Build a wire packet: `op` = opcode/key-id byte, `rest` = ack array,
    /// message id and payload.
    pub fn wrap(&mut self, op: u8, sid: &[u8; 8], rest: &[u8]) -> Vec<u8> {
        match self {
            Wrap::None => {
                let mut v = Vec::with_capacity(9 + rest.len());
                v.push(op);
                v.extend_from_slice(sid);
                v.extend_from_slice(rest);
                v
            }
            Wrap::Auth { digest, out_key, pid, .. } => {
                let p = pid.to_be_bytes();
                let t = unix_time().to_be_bytes();
                *pid = pid.wrapping_add(1);
                let mac = digest.hmac(out_key, &[&p, &t, &[op], sid, rest]);
                let mut v = Vec::with_capacity(9 + mac.len() + 8 + rest.len());
                v.push(op);
                v.extend_from_slice(sid);
                v.extend_from_slice(&mac);
                v.extend_from_slice(&p);
                v.extend_from_slice(&t);
                v.extend_from_slice(rest);
                v
            }
            Wrap::Crypt { out_c, out_h, pid, .. } => {
                let p = pid.to_be_bytes();
                let t = unix_time().to_be_bytes();
                *pid = pid.wrapping_add(1);
                let tag = Digest::Sha256.hmac(out_h, &[&[op], sid, &p, &t, rest]);
                let mut enc = rest.to_vec();
                let mut c = ctr::Ctr128BE::<aes::Aes256>::new(out_c.as_slice().into(), tag[..16].into());
                c.apply_keystream(&mut enc);
                let mut v = Vec::with_capacity(9 + 8 + 32 + enc.len());
                v.push(op);
                v.extend_from_slice(sid);
                v.extend_from_slice(&p);
                v.extend_from_slice(&t);
                v.extend_from_slice(&tag);
                v.extend_from_slice(&enc);
                v
            }
        }
    }

    /// Verify/decrypt a received control packet; returns (op, session id, rest).
    pub fn unwrap(&mut self, pkt: &[u8]) -> Option<(u8, [u8; 8], Vec<u8>)> {
        if pkt.len() < 9 {
            return None;
        }
        let op = pkt[0];
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&pkt[1..9]);
        match self {
            Wrap::None => Some((op, sid, pkt[9..].to_vec())),
            Wrap::Auth { digest, in_keys, .. } => {
                let hl = digest.len();
                if pkt.len() < 9 + hl + 8 {
                    return None;
                }
                let mac = &pkt[9..9 + hl];
                let pt = &pkt[9 + hl..9 + hl + 8];
                let rest = &pkt[9 + hl + 8..];
                let d = *digest;
                let i = in_keys.iter().position(|k| ct_eq(&d.hmac(k, &[pt, &[op], &sid, rest]), mac))?;
                if i != 0 {
                    in_keys.swap(0, i); // learn the peer's direction
                }
                Some((op, sid, rest.to_vec()))
            }
            Wrap::Crypt { in_keys, .. } => {
                if pkt.len() < 9 + 8 + 32 {
                    return None;
                }
                let pt = &pkt[9..17];
                let tag = &pkt[17..49];
                let mut hit = None;
                for (i, (kc, kh)) in in_keys.iter().enumerate() {
                    let mut dec = pkt[49..].to_vec();
                    let mut c = ctr::Ctr128BE::<aes::Aes256>::new(kc.as_slice().into(), tag[..16].into());
                    c.apply_keystream(&mut dec);
                    let calc = Digest::Sha256.hmac(kh, &[&[op], &sid, pt, &dec]);
                    if ct_eq(&calc, tag) {
                        hit = Some((i, dec));
                        break;
                    }
                }
                let (i, dec) = hit?;
                if i != 0 {
                    in_keys.swap(0, i);
                }
                Some((op, sid, dec))
            }
        }
    }
}

// ---- data channel -----------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
}

impl CipherKind {
    pub fn parse(s: &str) -> Option<CipherKind> {
        Some(match s.to_ascii_uppercase().as_str() {
            "AES-128-GCM" => CipherKind::Aes128Gcm,
            "AES-256-GCM" => CipherKind::Aes256Gcm,
            "CHACHA20-POLY1305" => CipherKind::ChaCha20Poly1305,
            "AES-128-CBC" => CipherKind::Aes128Cbc,
            "AES-192-CBC" => CipherKind::Aes192Cbc,
            "AES-256-CBC" => CipherKind::Aes256Cbc,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            CipherKind::Aes128Gcm => "AES-128-GCM",
            CipherKind::Aes256Gcm => "AES-256-GCM",
            CipherKind::ChaCha20Poly1305 => "CHACHA20-POLY1305",
            CipherKind::Aes128Cbc => "AES-128-CBC",
            CipherKind::Aes192Cbc => "AES-192-CBC",
            CipherKind::Aes256Cbc => "AES-256-CBC",
        }
    }
    pub fn is_aead(self) -> bool {
        matches!(self, CipherKind::Aes128Gcm | CipherKind::Aes256Gcm | CipherKind::ChaCha20Poly1305)
    }
    fn key_len(self) -> usize {
        match self {
            CipherKind::Aes128Gcm | CipherKind::Aes128Cbc => 16,
            CipherKind::Aes192Cbc => 24,
            _ => 32,
        }
    }
}

struct DirKeys {
    cipher: Vec<u8>,
    hmac: Vec<u8>,
    implicit_iv: [u8; 8],
}

pub struct DataChannel {
    pub kind: CipherKind,
    digest: Digest,
    out: DirKeys,
    inp: [DirKeys; 2],
    in_idx: usize,
    pub pid: u32,
}

impl DataChannel {
    /// `block` is the 256-byte key2 block. The client sends with key 0 and
    /// receives with key 1 (the other order is tried if decryption fails).
    pub fn new(kind: CipherKind, digest: Digest, block: &[u8]) -> DataChannel {
        let mk = |i: usize| {
            let (c, h) = key2_part(block, i);
            let mut iv = [0u8; 8];
            iv.copy_from_slice(&h[..8]);
            DirKeys { cipher: c[..kind.key_len()].to_vec(), hmac: h[..digest.len()].to_vec(), implicit_iv: iv }
        };
        DataChannel { kind, digest, out: mk(0), inp: [mk(1), mk(0)], in_idx: 0, pid: 1 }
    }

    /// Encrypt `payload`. `header` is the opcode byte (+3-byte peer-id for V2).
    pub fn encrypt(&mut self, header: &[u8], payload: &[u8]) -> Vec<u8> {
        let pid = self.pid.to_be_bytes();
        self.pid = self.pid.wrapping_add(1);
        if self.kind.is_aead() {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&pid);
            nonce[4..].copy_from_slice(&self.out.implicit_iv);
            let mut aad = Vec::with_capacity(8);
            if header.len() == 4 {
                aad.extend_from_slice(header);
            }
            aad.extend_from_slice(&pid);
            let mut buf = payload.to_vec();
            let tag = aead_seal(self.kind, &self.out.cipher, &nonce, &aad, &mut buf);
            let mut v = Vec::with_capacity(header.len() + 4 + 16 + buf.len());
            v.extend_from_slice(header);
            v.extend_from_slice(&pid);
            v.extend_from_slice(&tag);
            v.extend_from_slice(&buf);
            v
        } else {
            let mut iv = [0u8; 16];
            rand::Rng::fill(&mut rand::thread_rng(), &mut iv);
            let mut pt = pid.to_vec();
            pt.extend_from_slice(payload);
            let ct = cbc_encrypt(self.kind, &self.out.cipher, &iv, &pt);
            let mac = self.digest.hmac(&self.out.hmac, &[&iv, &ct]);
            let mut v = Vec::with_capacity(header.len() + mac.len() + 16 + ct.len());
            v.extend_from_slice(header);
            v.extend_from_slice(&mac);
            v.extend_from_slice(&iv);
            v.extend_from_slice(&ct);
            v
        }
    }

    pub fn decrypt(&mut self, pkt: &[u8], header_len: usize) -> Option<Vec<u8>> {
        for attempt in 0..2 {
            let idx = (self.in_idx + attempt) % 2;
            if let Some(v) = self.decrypt_with(idx, pkt, header_len) {
                self.in_idx = idx;
                return Some(v);
            }
        }
        None
    }

    fn decrypt_with(&self, idx: usize, pkt: &[u8], hl: usize) -> Option<Vec<u8>> {
        let k = &self.inp[idx];
        if self.kind.is_aead() {
            if pkt.len() < hl + 20 {
                return None;
            }
            let pid = &pkt[hl..hl + 4];
            let tag = &pkt[hl + 4..hl + 20];
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(pid);
            nonce[4..].copy_from_slice(&k.implicit_iv);
            let mut aad = Vec::with_capacity(8);
            if hl == 4 {
                aad.extend_from_slice(&pkt[..4]);
            }
            aad.extend_from_slice(pid);
            let mut buf = pkt[hl + 20..].to_vec();
            aead_open(self.kind, &k.cipher, &nonce, &aad, &mut buf, tag).then_some(buf)
        } else {
            let ml = self.digest.len();
            if pkt.len() < hl + ml + 16 + 16 {
                return None;
            }
            let mac = &pkt[hl..hl + ml];
            let iv = &pkt[hl + ml..hl + ml + 16];
            let ct = &pkt[hl + ml + 16..];
            if !ct_eq(&self.digest.hmac(&k.hmac, &[iv, ct]), mac) {
                return None;
            }
            let pt = cbc_decrypt(self.kind, &k.cipher, iv, ct)?;
            if pt.len() < 4 {
                return None;
            }
            Some(pt[4..].to_vec())
        }
    }
}

fn aead_seal(kind: CipherKind, key: &[u8], nonce: &[u8; 12], aad: &[u8], buf: &mut Vec<u8>) -> [u8; 16] {
    let n = aes_gcm::Nonce::from_slice(nonce);
    let tag = match kind {
        CipherKind::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key).unwrap().encrypt_in_place_detached(n, aad, buf),
        CipherKind::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(key).unwrap().encrypt_in_place_detached(n, aad, buf),
        _ => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).unwrap().encrypt_in_place_detached(n, aad, buf),
    };
    let mut out = [0u8; 16];
    if let Ok(t) = tag {
        out.copy_from_slice(&t);
    }
    out
}

fn aead_open(kind: CipherKind, key: &[u8], nonce: &[u8; 12], aad: &[u8], buf: &mut Vec<u8>, tag: &[u8]) -> bool {
    let n = aes_gcm::Nonce::from_slice(nonce);
    let t = aes_gcm::Tag::from_slice(tag);
    match kind {
        CipherKind::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key).unwrap().decrypt_in_place_detached(n, aad, buf, t).is_ok(),
        CipherKind::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(key).unwrap().decrypt_in_place_detached(n, aad, buf, t).is_ok(),
        _ => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).unwrap().decrypt_in_place_detached(n, aad, buf, t).is_ok(),
    }
}

fn cbc_encrypt(kind: CipherKind, key: &[u8], iv: &[u8], pt: &[u8]) -> Vec<u8> {
    use cipher::block_padding::Pkcs7;
    match kind {
        CipherKind::Aes128Cbc => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv).unwrap().encrypt_padded_vec_mut::<Pkcs7>(pt),
        CipherKind::Aes192Cbc => cbc::Encryptor::<aes::Aes192>::new_from_slices(key, iv).unwrap().encrypt_padded_vec_mut::<Pkcs7>(pt),
        _ => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv).unwrap().encrypt_padded_vec_mut::<Pkcs7>(pt),
    }
}

fn cbc_decrypt(kind: CipherKind, key: &[u8], iv: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    use cipher::block_padding::Pkcs7;
    match kind {
        CipherKind::Aes128Cbc => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv).ok()?.decrypt_padded_vec_mut::<Pkcs7>(ct).ok(),
        CipherKind::Aes192Cbc => cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv).ok()?.decrypt_padded_vec_mut::<Pkcs7>(ct).ok(),
        _ => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).ok()?.decrypt_padded_vec_mut::<Pkcs7>(ct).ok(),
    }
}

pub fn check_supported(kind: &str) -> Result<CipherKind> {
    match CipherKind::parse(kind) {
        Some(k) => Ok(k),
        None => bail!("data channel cipher {kind} is not supported (supported: AES-128/256-GCM, CHACHA20-POLY1305, AES-128/192/256-CBC)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aead_roundtrip() {
        let block: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
        let mut a = DataChannel::new(CipherKind::Aes256Gcm, Digest::Sha1, &block);
        let mut b = DataChannel::new(CipherKind::Aes256Gcm, Digest::Sha1, &block);
        // b plays the server: swap directions
        std::mem::swap(&mut b.out, &mut b.inp[1]);
        let pkt = a.encrypt(&[0x48, 0, 0, 1], b"hello");
        let _ = &mut b;
        // a's out key is key0; b receives with inp[...]: decrypt tries both
        let mut c = DataChannel::new(CipherKind::Aes256Gcm, Digest::Sha1, &block);
        assert_eq!(c.decrypt(&pkt, 4).unwrap(), b"hello");
    }
    #[test]
    fn tls_crypt_roundtrip() {
        let key: Vec<u8> = (0..256u32).map(|i| (i * 7) as u8).collect();
        let mut w = Wrap::tls_crypt(&key);
        let pkt = w.wrap(0x38, &[1; 8], b"abcdef");
        let mut r = Wrap::tls_crypt(&key);
        let (op, sid, rest) = r.unwrap(&pkt).unwrap();
        assert_eq!((op, sid, rest), (0x38, [1; 8], b"abcdef".to_vec()));
    }
}
