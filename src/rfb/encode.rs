//! Server-side framebuffer encoders: Raw, Hextile, ZRLE and Tight (+JPEG).
//! Source pixels are always 32-bit BGRX rows as delivered by screen capture.

use super::{put_compact_len, put_rect_header, PixelFormat, PutExt, Rect, ENC_HEXTILE, ENC_RAW, ENC_TIGHT, ENC_ZRLE};
use flate2::{Compress, Compression, FlushCompress};

/// A captured frame in BGRX byte order, tightly packed (stride = width * 4).
#[derive(Clone)]
pub struct Frame {
    pub width: usize,
    pub height: usize,
    pub data: Vec<u8>,
}

impl Frame {
    #[inline]
    pub fn rgb(&self, x: usize, y: usize) -> (u8, u8, u8) {
        let o = (y * self.width + x) * 4;
        (self.data[o + 2], self.data[o + 1], self.data[o])
    }
    #[inline]
    pub fn bgrx_u32(&self, x: usize, y: usize) -> u32 {
        let o = (y * self.width + x) * 4;
        u32::from_le_bytes([self.data[o], self.data[o + 1], self.data[o + 2], 0])
    }
    pub fn row(&self, y: usize, x: usize, w: usize) -> &[u8] {
        let o = (y * self.width + x) * 4;
        &self.data[o..o + w * 4]
    }
}

/// Per-connection encoder state (zlib streams must persist across updates).
pub struct EncoderState {
    zrle: Compress,
    tight: [Compress; 4],
    pub tight_zlib_level: u32,
}

impl EncoderState {
    pub fn new(tight_level: u32) -> Self {
        let lvl = tight_level.clamp(1, 9);
        EncoderState {
            zrle: Compress::new(Compression::new(6), true),
            tight: [
                Compress::new(Compression::new(lvl), true),
                Compress::new(Compression::new(lvl), true),
                Compress::new(Compression::new(lvl), true),
                Compress::new(Compression::new(lvl), true),
            ],
            tight_zlib_level: lvl,
        }
    }
}

/// Compress `input` into one sync-flushed zlib block on a persistent stream.
fn zlib_sync(c: &mut Compress, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 8 + 256);
    let start = c.total_in();
    loop {
        let consumed = (c.total_in() - start) as usize;
        if out.capacity() - out.len() < 256 {
            out.reserve(out.capacity().max(4096));
        }
        if c.compress_vec(&input[consumed..], &mut out, FlushCompress::Sync).is_err() {
            break;
        }
        let consumed = (c.total_in() - start) as usize;
        if consumed >= input.len() && out.len() < out.capacity() {
            break;
        }
    }
    out
}

#[inline]
fn pix_value(frame: &Frame, x: usize, y: usize, pf: &PixelFormat) -> u32 {
    let (r, g, b) = frame.rgb(x, y);
    pf.pack(r, g, b)
}

// ---- Raw ------------------------------------------------------------------

pub fn put_raw_pixels(frame: &Frame, r: Rect, pf: &PixelFormat, out: &mut Vec<u8>) {
    let (x0, y0, w, h) = (r.x as usize, r.y as usize, r.w as usize, r.h as usize);
    out.reserve(w * h * pf.bytes_per_pixel());
    if *pf == PixelFormat::bgrx() {
        for y in y0..y0 + h {
            out.extend_from_slice(frame.row(y, x0, w));
        }
        return;
    }
    for y in y0..y0 + h {
        for x in x0..x0 + w {
            pf.put_value(out, pix_value(frame, x, y, pf));
        }
    }
}

pub fn encode_raw(frame: &Frame, r: Rect, pf: &PixelFormat, out: &mut Vec<u8>) -> u16 {
    put_rect_header(out, r, ENC_RAW);
    put_raw_pixels(frame, r, pf, out);
    1
}

// ---- Hextile (solid tiles + raw tiles; always valid, cheap to produce) ------

pub fn encode_hextile(frame: &Frame, r: Rect, pf: &PixelFormat, out: &mut Vec<u8>) -> u16 {
    put_rect_header(out, r, ENC_HEXTILE);
    let (x0, y0, w, h) = (r.x as usize, r.y as usize, r.w as usize, r.h as usize);
    let mut ty = y0;
    while ty < y0 + h {
        let th = 16.min(y0 + h - ty);
        let mut tx = x0;
        while tx < x0 + w {
            let tw = 16.min(x0 + w - tx);
            let first = frame.bgrx_u32(tx, ty);
            let solid = (ty..ty + th).all(|y| (tx..tx + tw).all(|x| frame.bgrx_u32(x, y) == first));
            if solid {
                out.push(0x02); // background specified, no subrects
                pf.put_value(out, pix_value(frame, tx, ty, pf));
            } else {
                out.push(0x01); // raw
                for y in ty..ty + th {
                    for x in tx..tx + tw {
                        pf.put_value(out, pix_value(frame, x, y, pf));
                    }
                }
            }
            tx += 16;
        }
        ty += 16;
    }
    1
}

// ---- ZRLE -----------------------------------------------------------------

pub fn encode_zrle(st: &mut EncoderState, frame: &Frame, r: Rect, pf: &PixelFormat, out: &mut Vec<u8>) -> u16 {
    let (x0, y0, w, h) = (r.x as usize, r.y as usize, r.w as usize, r.h as usize);
    let mut raw = Vec::with_capacity(w * h * pf.cpixel_len() + 1024);
    let mut palette: Vec<u32> = Vec::with_capacity(16);
    let mut ty = y0;
    while ty < y0 + h {
        let th = 64.min(y0 + h - ty);
        let mut tx = x0;
        while tx < x0 + w {
            let tw = 64.min(x0 + w - tx);
            // gather palette (up to 16 colours)
            palette.clear();
            let mut many = false;
            'outer: for y in ty..ty + th {
                for x in tx..tx + tw {
                    let v = frame.bgrx_u32(x, y);
                    if !palette.contains(&v) {
                        if palette.len() == 16 {
                            many = true;
                            break 'outer;
                        }
                        palette.push(v);
                    }
                }
            }
            let to_pf = |v: u32| pf.pack((v >> 16) as u8, (v >> 8) as u8, v as u8);
            if !many && palette.len() == 1 {
                raw.push(1);
                pf.put_cpixel(&mut raw, to_pf(palette[0]));
            } else if !many {
                let n = palette.len();
                raw.push(n as u8);
                for &c in &palette {
                    pf.put_cpixel(&mut raw, to_pf(c));
                }
                let bits = if n <= 2 { 1 } else if n <= 4 { 2 } else { 4 };
                for y in ty..ty + th {
                    let mut acc: u8 = 0;
                    let mut nbits = 0;
                    for x in tx..tx + tw {
                        let v = frame.bgrx_u32(x, y);
                        let idx = palette.iter().position(|&c| c == v).unwrap_or(0) as u8;
                        acc = (acc << bits) | idx;
                        nbits += bits;
                        if nbits == 8 {
                            raw.push(acc);
                            acc = 0;
                            nbits = 0;
                        }
                    }
                    if nbits > 0 {
                        raw.push(acc << (8 - nbits));
                    }
                }
            } else {
                raw.push(0);
                for y in ty..ty + th {
                    for x in tx..tx + tw {
                        pf.put_cpixel(&mut raw, pix_value(frame, x, y, pf));
                    }
                }
            }
            tx += 64;
        }
        ty += 64;
    }
    let z = zlib_sync(&mut st.zrle, &raw);
    put_rect_header(out, r, ENC_ZRLE);
    out.put_u32(z.len() as u32);
    out.extend_from_slice(&z);
    1
}

// ---- Tight ----------------------------------------------------------------

fn put_tpixel(out: &mut Vec<u8>, pf: &PixelFormat, r: u8, g: u8, b: u8) {
    if pf.tight_rgb() {
        out.extend_from_slice(&[r, g, b]);
    } else {
        pf.put_value(out, pf.pack(r, g, b));
    }
}

/// Encode one rectangle with Tight. Large rects are split to respect Tight's
/// limits. Returns the number of rectangles written.
pub fn encode_tight(st: &mut EncoderState, frame: &Frame, r: Rect, pf: &PixelFormat, jpeg_quality: Option<u8>, out: &mut Vec<u8>) -> u16 {
    let jpeg_ok = jpeg_quality.is_some() && pf.bpp == 32 && pf.true_color;
    let max_w: u16 = 2048;
    let max_area: usize = if jpeg_ok { 1 << 20 } else { 65536 };
    let max_h = ((max_area / r.w.min(max_w).max(1) as usize).max(1)).min(u16::MAX as usize) as u16;
    let mut count = 0u16;
    let mut y = r.y;
    while y < r.y + r.h {
        let h = max_h.min(r.y + r.h - y);
        let mut x = r.x;
        while x < r.x + r.w {
            let w = max_w.min(r.x + r.w - x);
            tight_one(st, frame, Rect::new(x, y, w, h), pf, if jpeg_ok { jpeg_quality } else { None }, out);
            count += 1;
            x += w;
        }
        y += h;
    }
    count
}

fn tight_one(st: &mut EncoderState, frame: &Frame, r: Rect, pf: &PixelFormat, jpeg_quality: Option<u8>, out: &mut Vec<u8>) {
    let (x0, y0, w, h) = (r.x as usize, r.y as usize, r.w as usize, r.h as usize);
    put_rect_header(out, r, ENC_TIGHT);

    // palette analysis (up to 16 colours)
    let mut palette: Vec<u32> = Vec::with_capacity(16);
    let mut many = false;
    'outer: for y in y0..y0 + h {
        for x in x0..x0 + w {
            let v = frame.bgrx_u32(x, y);
            if !palette.contains(&v) {
                if palette.len() == 16 {
                    many = true;
                    break 'outer;
                }
                palette.push(v);
            }
        }
    }

    if !many && palette.len() == 1 {
        let v = palette[0];
        out.push(0x80); // fill
        put_tpixel(out, pf, (v >> 16) as u8, (v >> 8) as u8, v as u8);
        return;
    }

    if many {
        if let Some(q) = jpeg_quality {
            if w >= 8 && h >= 8 {
                let mut bgra = Vec::with_capacity(w * h * 4);
                for y in y0..y0 + h {
                    bgra.extend_from_slice(frame.row(y, x0, w));
                }
                let mut jpg = Vec::with_capacity(w * h / 4 + 1024);
                let mut enc = jpeg_encoder::Encoder::new(&mut jpg, q);
                if q >= 90 {
                    enc.set_sampling_factor(jpeg_encoder::SamplingFactor::F_1_1);
                }
                if enc.encode(&bgra, w as u16, h as u16, jpeg_encoder::ColorType::Bgra).is_ok() {
                    out.push(0x90);
                    put_compact_len(out, jpg.len());
                    out.extend_from_slice(&jpg);
                    return;
                }
            }
        }
        // basic compression, copy filter, stream 0
        let mut data = Vec::with_capacity(w * h * 3);
        for y in y0..y0 + h {
            for x in x0..x0 + w {
                let (rr, gg, bb) = frame.rgb(x, y);
                put_tpixel(&mut data, pf, rr, gg, bb);
            }
        }
        out.push(0x00);
        put_tight_data(st, 0, &data, out);
        return;
    }

    // palette filter on stream 1
    let n = palette.len();
    out.push(0x40 | (1 << 4)); // explicit filter, stream 1
    out.push(1); // palette filter
    out.push((n - 1) as u8);
    for &v in &palette {
        put_tpixel(out, pf, (v >> 16) as u8, (v >> 8) as u8, v as u8);
    }
    let mut data = Vec::with_capacity(if n == 2 { (w + 7) / 8 * h } else { w * h });
    for y in y0..y0 + h {
        if n == 2 {
            let mut acc = 0u8;
            let mut nb = 0;
            for x in x0..x0 + w {
                let bit = (frame.bgrx_u32(x, y) == palette[1]) as u8;
                acc = (acc << 1) | bit;
                nb += 1;
                if nb == 8 {
                    data.push(acc);
                    acc = 0;
                    nb = 0;
                }
            }
            if nb > 0 {
                data.push(acc << (8 - nb));
            }
        } else {
            for x in x0..x0 + w {
                let v = frame.bgrx_u32(x, y);
                data.push(palette.iter().position(|&c| c == v).unwrap_or(0) as u8);
            }
        }
    }
    put_tight_data(st, 1, &data, out);
}

fn put_tight_data(st: &mut EncoderState, stream: usize, data: &[u8], out: &mut Vec<u8>) {
    if data.len() < 12 {
        out.extend_from_slice(data);
        return;
    }
    let z = zlib_sync(&mut st.tight[stream], data);
    put_compact_len(out, z.len());
    out.extend_from_slice(&z);
}

// ---- change detection -----------------------------------------------------

pub const TILE: usize = 64;

/// Compare two frames tile-by-tile and return merged dirty rectangles.
pub fn diff_rects(prev: Option<&Frame>, cur: &Frame) -> Vec<Rect> {
    let (w, h) = (cur.width, cur.height);
    let full = || vec![Rect::new(0, 0, w as u16, h as u16)];
    let prev = match prev {
        Some(p) if p.width == w && p.height == h => p,
        _ => return full(),
    };
    let tw = (w + TILE - 1) / TILE;
    let th = (h + TILE - 1) / TILE;
    let mut dirty = vec![false; tw * th];
    for ty in 0..th {
        let y0 = ty * TILE;
        let y1 = (y0 + TILE).min(h);
        for tx in 0..tw {
            let x0 = tx * TILE;
            let x1 = (x0 + TILE).min(w);
            let mut d = false;
            for y in y0..y1 {
                let o0 = (y * w + x0) * 4;
                let o1 = (y * w + x1) * 4;
                if prev.data[o0..o1] != cur.data[o0..o1] {
                    d = true;
                    break;
                }
            }
            dirty[ty * tw + tx] = d;
        }
    }
    // merge: horizontal runs per tile-row, then extend identical runs downwards
    let mut rects = Vec::new();
    let mut used = vec![false; tw * th];
    for ty in 0..th {
        let mut tx = 0;
        while tx < tw {
            if !dirty[ty * tw + tx] || used[ty * tw + tx] {
                tx += 1;
                continue;
            }
            let start = tx;
            while tx < tw && dirty[ty * tw + tx] && !used[ty * tw + tx] {
                tx += 1;
            }
            let end = tx;
            let mut ty_end = ty + 1;
            while ty_end < th && (start..end).all(|i| dirty[ty_end * tw + i] && !used[ty_end * tw + i]) {
                ty_end += 1;
            }
            for yy in ty..ty_end {
                for i in start..end {
                    used[yy * tw + i] = true;
                }
            }
            let x0 = start * TILE;
            let y0 = ty * TILE;
            let x1 = (end * TILE).min(w);
            let y1 = (ty_end * TILE).min(h);
            rects.push(Rect::new(x0 as u16, y0 as u16, (x1 - x0) as u16, (y1 - y0) as u16));
        }
    }
    rects
}
