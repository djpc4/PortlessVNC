//! PortlessVNC extension messages, carried inside a normal RFB connection.
//!
//! Negotiation: the viewer advertises pseudo-encoding `ENC_PORTLESS_EXT` in
//! SetEncodings; a PortlessVNC server answers with a pseudo-rectangle of the
//! same encoding. Only after that does either side send message type
//! `MSG_PORTLESS_EXT`, so standard VNC software never sees these messages.
//!
//! Wire format: `[211][subtype u8][length u32 BE][payload]`.

use crate::rfb::{PutExt, MSG_PORTLESS_EXT};

pub const VERSION: u16 = 1;

pub const HELLO: u8 = 1;
pub const CLIP_TEXT: u8 = 2;
pub const FILES_OFFER: u8 = 3;
pub const FILE_REQ: u8 = 4;
pub const FILE_DATA: u8 = 5;
pub const FILE_END: u8 = 6;
pub const FILE_ERR: u8 = 7;
pub const SEND_BEGIN: u8 = 8;
pub const CANCEL: u8 = 9;
pub const AUDIO_CTRL: u8 = 10;
pub const AUDIO_FMT: u8 = 11;
pub const AUDIO_DATA: u8 = 12;
pub const QUALITY_CTRL: u8 = 13;
pub const STATS: u8 = 14;
pub const PING: u8 = 15;
pub const PONG: u8 = 16;
/// Shared notepad: [version u64][utf-8 text]. Newest version wins.
pub const NOTE_TEXT: u8 = 17;

/// Capability bits exchanged in HELLO.
pub const CAP_AUDIO: u32 = 1;
pub const CAP_CLIPBOARD: u32 = 2;
pub const CAP_FILES: u32 = 4;

pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

pub fn frame(sub: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 6);
    v.push(MSG_PORTLESS_EXT);
    v.push(sub);
    v.put_u32(payload.len() as u32);
    v.extend_from_slice(payload);
    v
}

pub fn hello(caps: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.put_u16(VERSION);
    p.put_u32(caps);
    p.put_str16(concat!("PortlessVNC ", env!("CARGO_PKG_VERSION")));
    p
}

/// One entry of a file offer (clipboard copy of files/folders).
#[derive(Clone, Debug)]
pub struct OfferEntry {
    pub rel_path: String,
    pub size: u64,
    pub is_dir: bool,
}

pub fn encode_offer(offer_id: u32, entries: &[OfferEntry]) -> Vec<u8> {
    let mut p = Vec::new();
    p.put_u32(offer_id);
    p.put_u32(entries.len() as u32);
    for e in entries {
        p.put_u8(e.is_dir as u8);
        p.put_u64(e.size);
        p.put_str16(&e.rel_path);
    }
    p
}

pub fn decode_offer(b: &[u8]) -> std::io::Result<(u32, Vec<OfferEntry>)> {
    let mut c = crate::rfb::Cur::new(b);
    let id = c.u32()?;
    let n = c.u32()? as usize;
    let mut v = Vec::with_capacity(n.min(100_000));
    for _ in 0..n {
        let is_dir = c.u8()? != 0;
        let size = c.u64()?;
        let rel_path = c.str16()?;
        v.push(OfferEntry { rel_path, size, is_dir });
    }
    Ok((id, v))
}
