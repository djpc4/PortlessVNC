//! RFB (VNC) protocol core: constants, pixel formats and wire helpers shared by
//! the server and the viewer.

pub mod decode;
pub mod encode;
pub mod vncauth;

use std::io::{self, Read};

// ---- security types -------------------------------------------------------
pub const SEC_NONE: u8 = 1;
pub const SEC_VNC_AUTH: u8 = 2;
pub const SEC_RA2: u8 = 5;
pub const SEC_VENCRYPT: u8 = 19;

// VeNCrypt sub-types
pub const VENC_PLAIN: u32 = 256;
pub const VENC_X509_NONE: u32 = 260;
pub const VENC_X509_VNC: u32 = 261;
pub const VENC_X509_PLAIN: u32 = 262;

// ---- encodings ------------------------------------------------------------
pub const ENC_RAW: i32 = 0;
pub const ENC_COPYRECT: i32 = 1;
pub const ENC_HEXTILE: i32 = 5;
pub const ENC_TIGHT: i32 = 7;
pub const ENC_ZRLE: i32 = 16;

// pseudo-encodings
pub const ENC_CURSOR: i32 = -239;
pub const ENC_DESKTOP_SIZE: i32 = -223;
pub const ENC_LAST_RECT: i32 = -224;
pub const ENC_EXT_DESKTOP_SIZE: i32 = -308;
pub const ENC_QEMU_EXT_KEY: i32 = -258;
/// Tight JPEG quality level 0..9 is -32..-23
pub const ENC_QUALITY_0: i32 = -32;
pub const ENC_QUALITY_9: i32 = -23;
/// Tight compression level 0..9 is -256..-247
pub const ENC_COMPRESS_0: i32 = -256;
pub const ENC_COMPRESS_9: i32 = -247;
/// Our own capability pseudo-encoding ("PLS1"). A viewer advertising this is a
/// PortlessVNC peer; the server acknowledges with a pseudo-rect of the same
/// encoding, after which both sides may send extension messages.
pub const ENC_PORTLESS_EXT: i32 = 0x504C_5331;

// ---- message types --------------------------------------------------------
pub const C2S_SET_PIXEL_FORMAT: u8 = 0;
pub const C2S_SET_ENCODINGS: u8 = 2;
pub const C2S_FB_UPDATE_REQUEST: u8 = 3;
pub const C2S_KEY_EVENT: u8 = 4;
pub const C2S_POINTER_EVENT: u8 = 5;
pub const C2S_CLIENT_CUT_TEXT: u8 = 6;
pub const C2S_QEMU: u8 = 255;

pub const S2C_FB_UPDATE: u8 = 0;
pub const S2C_SET_COLOUR_MAP: u8 = 1;
pub const S2C_BELL: u8 = 2;
pub const S2C_SERVER_CUT_TEXT: u8 = 3;

/// Extension message type (both directions), only used after negotiation.
pub const MSG_PORTLESS_EXT: u8 = 211;

/// Tight JPEG quality per quality level (same table TigerVNC uses).
pub const TIGHT_JPEG_QUALITY: [u8; 10] = [15, 29, 41, 42, 62, 77, 79, 86, 92, 100];

// ---- pixel format ---------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelFormat {
    pub bpp: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_color: bool,
    pub rmax: u16,
    pub gmax: u16,
    pub bmax: u16,
    pub rshift: u8,
    pub gshift: u8,
    pub bshift: u8,
}

impl PixelFormat {
    /// Server's native format: 32bpp little-endian BGRX (matches Windows capture).
    pub const fn bgrx() -> Self {
        PixelFormat { bpp: 32, depth: 24, big_endian: false, true_color: true, rmax: 255, gmax: 255, bmax: 255, rshift: 16, gshift: 8, bshift: 0 }
    }

    /// Viewer's preferred format: 32bpp little-endian RGBX (matches egui Color32 layout).
    pub const fn rgbx() -> Self {
        PixelFormat { bpp: 32, depth: 24, big_endian: false, true_color: true, rmax: 255, gmax: 255, bmax: 255, rshift: 0, gshift: 8, bshift: 16 }
    }

    pub fn parse(b: &[u8]) -> Self {
        PixelFormat {
            bpp: b[0],
            depth: b[1],
            big_endian: b[2] != 0,
            true_color: b[3] != 0,
            rmax: u16::from_be_bytes([b[4], b[5]]),
            gmax: u16::from_be_bytes([b[6], b[7]]),
            bmax: u16::from_be_bytes([b[8], b[9]]),
            rshift: b[10],
            gshift: b[11],
            bshift: b[12],
        }
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[self.bpp, self.depth, self.big_endian as u8, self.true_color as u8]);
        out.extend_from_slice(&self.rmax.to_be_bytes());
        out.extend_from_slice(&self.gmax.to_be_bytes());
        out.extend_from_slice(&self.bmax.to_be_bytes());
        out.extend_from_slice(&[self.rshift, self.gshift, self.bshift, 0, 0, 0]);
    }

    pub fn bytes_per_pixel(&self) -> usize {
        (self.bpp as usize / 8).max(1)
    }

    pub fn is_valid_true_color(&self) -> bool {
        self.true_color && matches!(self.bpp, 8 | 16 | 32) && self.rmax > 0 && self.gmax > 0 && self.bmax > 0
    }

    /// Pack 8-bit r,g,b into this format's pixel value.
    #[inline]
    pub fn pack(&self, r: u8, g: u8, b: u8) -> u32 {
        let sc = |v: u8, max: u16| -> u32 {
            if max == 255 { v as u32 } else { (v as u32 * max as u32 + 127) / 255 }
        };
        (sc(r, self.rmax) << self.rshift) | (sc(g, self.gmax) << self.gshift) | (sc(b, self.bmax) << self.bshift)
    }

    /// Unpack a pixel value of this format into 8-bit r,g,b.
    #[inline]
    pub fn unpack(&self, v: u32) -> (u8, u8, u8) {
        let ex = |v: u32, shift: u8, max: u16| -> u8 {
            let c = (v >> shift) & max as u32;
            if max == 255 { c as u8 } else if max == 0 { 0 } else { ((c * 255 + max as u32 / 2) / max as u32) as u8 }
        };
        (ex(v, self.rshift, self.rmax), ex(v, self.gshift, self.gmax), ex(v, self.bshift, self.bmax))
    }

    #[inline]
    pub fn put_value(&self, out: &mut Vec<u8>, v: u32) {
        match self.bpp {
            32 => {
                if self.big_endian { out.extend_from_slice(&v.to_be_bytes()) } else { out.extend_from_slice(&v.to_le_bytes()) }
            }
            16 => {
                let v = v as u16;
                if self.big_endian { out.extend_from_slice(&v.to_be_bytes()) } else { out.extend_from_slice(&v.to_le_bytes()) }
            }
            _ => out.push(v as u8),
        }
    }

    #[inline]
    pub fn read_value(&self, b: &[u8]) -> u32 {
        match self.bpp {
            32 => {
                let a = [b[0], b[1], b[2], b[3]];
                if self.big_endian { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
            }
            16 => {
                let a = [b[0], b[1]];
                (if self.big_endian { u16::from_be_bytes(a) } else { u16::from_le_bytes(a) }) as u32
            }
            _ => b[0] as u32,
        }
    }

    /// ZRLE "CPIXEL" size: 3 bytes for 32bpp formats whose colour bits fit in 24 bits.
    pub fn cpixel_len(&self) -> usize {
        if self.bpp == 32 && self.depth <= 24 && self.true_color && (self.fits_ls3() || self.fits_ms3()) { 3 } else { self.bytes_per_pixel() }
    }

    fn colour_mask(&self) -> u32 {
        ((self.rmax as u32) << self.rshift) | ((self.gmax as u32) << self.gshift) | ((self.bmax as u32) << self.bshift)
    }
    fn fits_ls3(&self) -> bool {
        self.colour_mask() & 0xFF00_0000 == 0
    }
    fn fits_ms3(&self) -> bool {
        self.colour_mask() & 0x0000_00FF == 0
    }

    #[inline]
    pub fn put_cpixel(&self, out: &mut Vec<u8>, v: u32) {
        if self.cpixel_len() == 3 {
            let v = if self.fits_ls3() { v } else { v >> 8 };
            // CPIXELs keep the byte order of the pixel format
            if self.big_endian {
                out.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
            } else {
                out.extend_from_slice(&[v as u8, (v >> 8) as u8, (v >> 16) as u8]);
            }
        } else {
            self.put_value(out, v)
        }
    }

    #[inline]
    pub fn read_cpixel(&self, b: &[u8]) -> u32 {
        if self.cpixel_len() == 3 {
            let v = if self.big_endian {
                ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32
            } else {
                b[0] as u32 | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
            };
            if self.fits_ls3() { v } else { v << 8 }
        } else {
            self.read_value(b)
        }
    }

    /// Tight "TPIXEL" is packed R,G,B when the format is 32bpp/depth 24/8-bit channels.
    pub fn tight_rgb(&self) -> bool {
        self.bpp == 32 && self.depth == 24 && self.true_color && self.rmax == 255 && self.gmax == 255 && self.bmax == 255
    }
}

// ---- wire helpers ---------------------------------------------------------

pub trait ReadExt: Read {
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut b = [0u8; 1];
        self.read_exact(&mut b)?;
        Ok(b[0])
    }
    fn read_u16(&mut self) -> io::Result<u16> {
        let mut b = [0u8; 2];
        self.read_exact(&mut b)?;
        Ok(u16::from_be_bytes(b))
    }
    fn read_u32(&mut self) -> io::Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }
    fn read_i32(&mut self) -> io::Result<i32> {
        Ok(self.read_u32()? as i32)
    }
    fn read_u64(&mut self) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact(&mut b)?;
        Ok(u64::from_be_bytes(b))
    }
    fn read_vec(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut v = vec![0u8; n];
        self.read_exact(&mut v)?;
        Ok(v)
    }
    fn skip(&mut self, n: usize) -> io::Result<()> {
        let mut buf = [0u8; 256];
        let mut left = n;
        while left > 0 {
            let k = left.min(buf.len());
            self.read_exact(&mut buf[..k])?;
            left -= k;
        }
        Ok(())
    }
}
impl<R: Read + ?Sized> ReadExt for R {}

pub trait PutExt {
    fn put_u8(&mut self, v: u8);
    fn put_u16(&mut self, v: u16);
    fn put_u32(&mut self, v: u32);
    fn put_i32(&mut self, v: i32);
    fn put_u64(&mut self, v: u64);
    fn put_str16(&mut self, s: &str);
}
impl PutExt for Vec<u8> {
    fn put_u8(&mut self, v: u8) {
        self.push(v)
    }
    fn put_u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_be_bytes())
    }
    fn put_u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_be_bytes())
    }
    fn put_i32(&mut self, v: i32) {
        self.extend_from_slice(&v.to_be_bytes())
    }
    fn put_u64(&mut self, v: u64) {
        self.extend_from_slice(&v.to_be_bytes())
    }
    fn put_str16(&mut self, s: &str) {
        let b = s.as_bytes();
        let n = b.len().min(u16::MAX as usize);
        self.put_u16(n as u16);
        self.extend_from_slice(&b[..n]);
    }
}

/// Cursor-style reader over a byte slice (used for parsing extension payloads).
pub struct Cur<'a> {
    pub b: &'a [u8],
    pub pos: usize,
}
impl<'a> Cur<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Cur { b, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short message"));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> io::Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self) -> io::Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn u64(&mut self) -> io::Result<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    pub fn str16(&mut self) -> io::Result<String> {
        let n = self.u16()? as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.pos..];
        self.pos = self.b.len();
        s
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}
impl Rect {
    pub fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Rect { x, y, w, h }
    }
    pub fn area(&self) -> usize {
        self.w as usize * self.h as usize
    }
}

pub fn put_rect_header(out: &mut Vec<u8>, r: Rect, enc: i32) {
    out.put_u16(r.x);
    out.put_u16(r.y);
    out.put_u16(r.w);
    out.put_u16(r.h);
    out.put_i32(enc);
}

/// Tight "compact length" (1-3 bytes, 7 bits per byte).
pub fn put_compact_len(out: &mut Vec<u8>, len: usize) {
    let mut b = (len & 0x7F) as u8;
    if len > 0x7F {
        out.push(b | 0x80);
        b = ((len >> 7) & 0x7F) as u8;
        if len > 0x3FFF {
            out.push(b | 0x80);
            out.push(((len >> 14) & 0xFF) as u8);
            return;
        }
    }
    out.push(b);
}

pub fn read_compact_len<R: Read + ?Sized>(r: &mut R) -> io::Result<usize> {
    let b0 = r.read_u8()? as usize;
    let mut len = b0 & 0x7F;
    if b0 & 0x80 != 0 {
        let b1 = r.read_u8()? as usize;
        len |= (b1 & 0x7F) << 7;
        if b1 & 0x80 != 0 {
            let b2 = r.read_u8()? as usize;
            len |= b2 << 14;
        }
    }
    Ok(len)
}

/// Latin-1 <-> UTF-8 for standard (non-extended) cut text.
pub fn latin1_to_string(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}
pub fn string_to_latin1(s: &str) -> Vec<u8> {
    s.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).collect()
}
