//! Viewer-side decoders: Raw, CopyRect, Hextile, ZRLE, Tight (+JPEG) and the
//! common pseudo-encodings. Output is an RGBA (u32, little-endian) framebuffer.

use super::*;
use flate2::{Decompress, FlushDecompress};
use std::io::{self, Read};

pub struct FrameBuffer {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u32>,
    /// Dirty bounding box since the GUI last uploaded the texture (x0,y0,x1,y1).
    pub dirty: Option<(usize, usize, usize, usize)>,
    /// Bumped on resize so the GUI recreates its texture.
    pub generation: u64,
}

impl FrameBuffer {
    pub fn new(width: usize, height: usize) -> Self {
        FrameBuffer { width, height, pixels: vec![0xFF00_0000; width * height], dirty: Some((0, 0, width, height)), generation: 0 }
    }
    pub fn resize(&mut self, width: usize, height: usize) {
        self.width = width;
        self.height = height;
        self.pixels = vec![0xFF00_0000; width * height];
        self.dirty = Some((0, 0, width, height));
        self.generation += 1;
    }
    pub fn mark(&mut self, x: usize, y: usize, w: usize, h: usize) {
        let (x1, y1) = ((x + w).min(self.width), (y + h).min(self.height));
        self.dirty = Some(match self.dirty {
            None => (x, y, x1, y1),
            Some((a, b, c, d)) => (a.min(x), b.min(y), c.max(x1), d.max(y1)),
        });
    }
    #[inline]
    fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, c: u32) {
        for yy in y..(y + h).min(self.height) {
            let row = yy * self.width;
            let x1 = (x + w).min(self.width);
            if x < x1 {
                self.pixels[row + x..row + x1].fill(c);
            }
        }
    }
    #[inline]
    fn set(&mut self, x: usize, y: usize, c: u32) {
        if x < self.width && y < self.height {
            self.pixels[y * self.width + x] = c;
        }
    }
}

#[derive(Clone)]
pub struct RemoteCursor {
    pub width: usize,
    pub height: usize,
    pub hot_x: usize,
    pub hot_y: usize,
    pub rgba: Vec<u32>,
}

pub enum RectResult {
    Pixels,
    DesktopSize(usize, usize),
    Cursor(RemoteCursor),
    LastRect,
    PortlessAck(u16),
    QemuKeyAck,
    Ignored,
}

pub struct DecoderState {
    pub pf: PixelFormat,
    zrle: Decompress,
    tight: [Decompress; 4],
}

impl DecoderState {
    pub fn new(pf: PixelFormat) -> Self {
        DecoderState {
            pf,
            zrle: Decompress::new(true),
            tight: [Decompress::new(true), Decompress::new(true), Decompress::new(true), Decompress::new(true)],
        }
    }

    #[inline]
    fn to_rgba(&self, v: u32) -> u32 {
        if self.pf == PixelFormat::rgbx() {
            v | 0xFF00_0000
        } else {
            let (r, g, b) = self.pf.unpack(v);
            rgba(r, g, b)
        }
    }

    fn read_pixel<R: Read + ?Sized>(&self, rd: &mut R) -> io::Result<u32> {
        let mut b = [0u8; 4];
        let n = self.pf.bytes_per_pixel();
        rd.read_exact(&mut b[..n])?;
        Ok(self.to_rgba(self.pf.read_value(&b)))
    }
}

#[inline]
pub fn rgba(r: u8, g: u8, b: u8) -> u32 {
    r as u32 | ((g as u32) << 8) | ((b as u32) << 16) | 0xFF00_0000
}

fn inflate(d: &mut Decompress, input: &[u8], expected: Option<usize>) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(expected.unwrap_or(input.len() * 4).max(64));
    let start_in = d.total_in();
    loop {
        if out.capacity() - out.len() < 64 {
            out.reserve(out.capacity().max(4096));
        }
        let consumed = (d.total_in() - start_in) as usize;
        let before = out.len();
        d.decompress_vec(&input[consumed..], &mut out, FlushDecompress::Sync)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let consumed = (d.total_in() - start_in) as usize;
        if let Some(exp) = expected {
            if out.len() >= exp {
                out.truncate(exp);
                break;
            }
        }
        if consumed >= input.len() && out.len() == before {
            break;
        }
        if consumed >= input.len() && out.len() < out.capacity() {
            break;
        }
    }
    if let Some(exp) = expected {
        if out.len() < exp {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "zlib stream too short"));
        }
    }
    Ok(out)
}

/// Decode one rectangle body from `rd`.
pub fn decode_rect<R: Read + ?Sized>(st: &mut DecoderState, r: Rect, enc: i32, rd: &mut R, fb: &mut FrameBuffer) -> io::Result<RectResult> {
    let (x, y, w, h) = (r.x as usize, r.y as usize, r.w as usize, r.h as usize);
    match enc {
        ENC_RAW => {
            let bpp = st.pf.bytes_per_pixel();
            let mut row = vec![0u8; w * bpp];
            for yy in 0..h {
                rd.read_exact(&mut row)?;
                if y + yy >= fb.height {
                    continue;
                }
                let base = (y + yy) * fb.width;
                for xx in 0..w {
                    if x + xx < fb.width {
                        fb.pixels[base + x + xx] = st.to_rgba(st.pf.read_value(&row[xx * bpp..]));
                    }
                }
            }
            fb.mark(x, y, w, h);
            Ok(RectResult::Pixels)
        }
        ENC_COPYRECT => {
            let sx = rd.read_u16()? as usize;
            let sy = rd.read_u16()? as usize;
            let mut tmp = vec![0u32; w * h];
            for yy in 0..h {
                for xx in 0..w {
                    let (px, py) = (sx + xx, sy + yy);
                    if px < fb.width && py < fb.height {
                        tmp[yy * w + xx] = fb.pixels[py * fb.width + px];
                    }
                }
            }
            for yy in 0..h {
                for xx in 0..w {
                    fb.set(x + xx, y + yy, tmp[yy * w + xx]);
                }
            }
            fb.mark(x, y, w, h);
            Ok(RectResult::Pixels)
        }
        ENC_HEXTILE => {
            decode_hextile(st, x, y, w, h, rd, fb)?;
            fb.mark(x, y, w, h);
            Ok(RectResult::Pixels)
        }
        ENC_ZRLE => {
            let len = rd.read_u32()? as usize;
            let z = rd.read_vec(len)?;
            let data = inflate(&mut st.zrle, &z, None)?;
            decode_zrle(st, x, y, w, h, &data, fb)?;
            fb.mark(x, y, w, h);
            Ok(RectResult::Pixels)
        }
        ENC_TIGHT => {
            decode_tight(st, x, y, w, h, rd, fb)?;
            fb.mark(x, y, w, h);
            Ok(RectResult::Pixels)
        }
        ENC_DESKTOP_SIZE => Ok(RectResult::DesktopSize(w, h)),
        ENC_EXT_DESKTOP_SIZE => {
            let n = rd.read_u8()? as usize;
            rd.skip(3)?;
            rd.skip(n * 16)?;
            Ok(RectResult::DesktopSize(w, h))
        }
        ENC_LAST_RECT => Ok(RectResult::LastRect),
        ENC_CURSOR => {
            let bpp = st.pf.bytes_per_pixel();
            let pix = rd.read_vec(w * h * bpp)?;
            let mask_row = (w + 7) / 8;
            let mask = rd.read_vec(mask_row * h)?;
            let mut img = vec![0u32; w * h];
            for yy in 0..h {
                for xx in 0..w {
                    let visible = mask[yy * mask_row + xx / 8] & (0x80 >> (xx % 8)) != 0;
                    if visible {
                        let i = yy * w + xx;
                        img[i] = st.to_rgba(st.pf.read_value(&pix[i * bpp..]));
                    }
                }
            }
            Ok(RectResult::Cursor(RemoteCursor { width: w, height: h, hot_x: x, hot_y: y, rgba: img }))
        }
        ENC_PORTLESS_EXT => Ok(RectResult::PortlessAck(r.x)),
        ENC_QEMU_EXT_KEY => Ok(RectResult::QemuKeyAck),
        other => Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported encoding {other}"))),
    }
}

fn decode_hextile<R: Read + ?Sized>(st: &DecoderState, x0: usize, y0: usize, w: usize, h: usize, rd: &mut R, fb: &mut FrameBuffer) -> io::Result<()> {
    let mut bg = 0xFF00_0000u32;
    let mut fg = 0xFFFF_FFFFu32;
    let mut ty = y0;
    while ty < y0 + h {
        let th = 16.min(y0 + h - ty);
        let mut tx = x0;
        while tx < x0 + w {
            let tw = 16.min(x0 + w - tx);
            let sub = rd.read_u8()?;
            if sub & 1 != 0 {
                for yy in 0..th {
                    for xx in 0..tw {
                        let p = st.read_pixel(rd)?;
                        fb.set(tx + xx, ty + yy, p);
                    }
                }
            } else {
                if sub & 2 != 0 {
                    bg = st.read_pixel(rd)?;
                }
                fb.fill(tx, ty, tw, th, bg);
                if sub & 4 != 0 {
                    fg = st.read_pixel(rd)?;
                }
                if sub & 8 != 0 {
                    let n = rd.read_u8()?;
                    for _ in 0..n {
                        let c = if sub & 16 != 0 { st.read_pixel(rd)? } else { fg };
                        let xy = rd.read_u8()?;
                        let wh = rd.read_u8()?;
                        let (sx, sy) = ((xy >> 4) as usize, (xy & 15) as usize);
                        let (sw, sh) = ((wh >> 4) as usize + 1, (wh & 15) as usize + 1);
                        fb.fill(tx + sx, ty + sy, sw, sh, c);
                    }
                }
            }
            tx += 16;
        }
        ty += 16;
    }
    Ok(())
}

fn decode_zrle(st: &DecoderState, x0: usize, y0: usize, w: usize, h: usize, data: &[u8], fb: &mut FrameBuffer) -> io::Result<()> {
    let mut c = Cur::new(data);
    let cp = st.pf.cpixel_len();
    let read_cp = |c: &mut Cur| -> io::Result<u32> { Ok(st.to_rgba(st.pf.read_cpixel(c.take(cp)?))) };
    let mut palette = [0u32; 128];
    let mut ty = y0;
    while ty < y0 + h {
        let th = 64.min(y0 + h - ty);
        let mut tx = x0;
        while tx < x0 + w {
            let tw = 64.min(x0 + w - tx);
            let sub = c.u8()?;
            match sub {
                0 => {
                    for yy in 0..th {
                        for xx in 0..tw {
                            let p = read_cp(&mut c)?;
                            fb.set(tx + xx, ty + yy, p);
                        }
                    }
                }
                1 => {
                    let p = read_cp(&mut c)?;
                    fb.fill(tx, ty, tw, th, p);
                }
                2..=16 => {
                    let n = sub as usize;
                    for i in 0..n {
                        palette[i] = read_cp(&mut c)?;
                    }
                    let bits = if n <= 2 { 1 } else if n <= 4 { 2 } else { 4 };
                    let mask = (1u8 << bits) - 1;
                    for yy in 0..th {
                        let row_bytes = (tw * bits + 7) / 8;
                        let row = c.take(row_bytes)?;
                        for xx in 0..tw {
                            let bit = xx * bits;
                            let byte = row[bit / 8];
                            let shift = 8 - bits - (bit % 8);
                            let idx = ((byte >> shift) & mask) as usize;
                            fb.set(tx + xx, ty + yy, palette[idx.min(n - 1)]);
                        }
                    }
                }
                128 => {
                    let mut i = 0usize;
                    let total = tw * th;
                    while i < total {
                        let p = read_cp(&mut c)?;
                        let mut len = 1usize;
                        loop {
                            let b = c.u8()? as usize;
                            len += b;
                            if b != 255 {
                                break;
                            }
                        }
                        for _ in 0..len {
                            if i >= total {
                                break;
                            }
                            fb.set(tx + i % tw, ty + i / tw, p);
                            i += 1;
                        }
                    }
                }
                130..=255 => {
                    let n = (sub - 128) as usize;
                    for i in 0..n {
                        palette[i] = read_cp(&mut c)?;
                    }
                    let mut i = 0usize;
                    let total = tw * th;
                    while i < total {
                        let b = c.u8()?;
                        let p = palette[(b & 0x7F) as usize];
                        let mut len = 1usize;
                        if b & 0x80 != 0 {
                            loop {
                                let l = c.u8()? as usize;
                                len += l;
                                if l != 255 {
                                    break;
                                }
                            }
                        }
                        for _ in 0..len {
                            if i >= total {
                                break;
                            }
                            fb.set(tx + i % tw, ty + i / tw, p);
                            i += 1;
                        }
                    }
                }
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad ZRLE subencoding")),
            }
            tx += 64;
        }
        ty += 64;
    }
    Ok(())
}

fn read_tpixel<R: Read + ?Sized>(st: &DecoderState, rd: &mut R) -> io::Result<u32> {
    if st.pf.tight_rgb() {
        let mut b = [0u8; 3];
        rd.read_exact(&mut b)?;
        Ok(rgba(b[0], b[1], b[2]))
    } else {
        st.read_pixel(rd)
    }
}

fn decode_tight<R: Read + ?Sized>(st: &mut DecoderState, x0: usize, y0: usize, w: usize, h: usize, rd: &mut R, fb: &mut FrameBuffer) -> io::Result<()> {
    let ctl = rd.read_u8()?;
    for i in 0..4 {
        if ctl & (1 << i) != 0 {
            st.tight[i] = Decompress::new(true);
        }
    }
    let comp = ctl >> 4;
    if comp == 0x08 {
        let p = read_tpixel(st, rd)?;
        fb.fill(x0, y0, w, h, p);
        return Ok(());
    }
    if comp == 0x09 {
        let len = read_compact_len(rd)?;
        let jpg = rd.read_vec(len)?;
        let mut dec = zune_jpeg::JpegDecoder::new(&jpg);
        let rgb = dec.decode().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("jpeg: {e:?}")))?;
        let (jw, jh) = dec.dimensions().unwrap_or((w, h));
        let chans = if jw * jh > 0 { rgb.len() / (jw * jh) } else { 3 };
        for yy in 0..h.min(jh) {
            for xx in 0..w.min(jw) {
                let i = (yy * jw + xx) * chans;
                let p = if chans >= 3 { rgba(rgb[i], rgb[i + 1], rgb[i + 2]) } else { rgba(rgb[i], rgb[i], rgb[i]) };
                fb.set(x0 + xx, y0 + yy, p);
            }
        }
        return Ok(());
    }
    if comp > 0x07 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported tight compression {comp:#x}")));
    }
    let stream = (comp & 3) as usize;
    let filter = if comp & 4 != 0 { rd.read_u8()? } else { 0 };
    let tp = if st.pf.tight_rgb() { 3 } else { st.pf.bytes_per_pixel() };
    let mut palette: Vec<u32> = Vec::new();
    let data_len = match filter {
        0 => w * h * tp,
        1 => {
            let n = rd.read_u8()? as usize + 1;
            for _ in 0..n {
                palette.push(read_tpixel(st, rd)?);
            }
            if n == 2 { (w + 7) / 8 * h } else { w * h }
        }
        2 => w * h * tp,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad tight filter")),
    };
    let data = if data_len < 12 {
        rd.read_vec(data_len)?
    } else {
        let len = read_compact_len(rd)?;
        let z = rd.read_vec(len)?;
        inflate(&mut st.tight[stream], &z, Some(data_len))?
    };
    match filter {
        0 => {
            for yy in 0..h {
                for xx in 0..w {
                    let i = (yy * w + xx) * tp;
                    let p = if tp == 3 { rgba(data[i], data[i + 1], data[i + 2]) } else { st.to_rgba(st.pf.read_value(&data[i..])) };
                    fb.set(x0 + xx, y0 + yy, p);
                }
            }
        }
        1 => {
            let n = palette.len();
            if n == 2 {
                let rb = (w + 7) / 8;
                for yy in 0..h {
                    for xx in 0..w {
                        let bit = (data[yy * rb + xx / 8] >> (7 - (xx % 8))) & 1;
                        fb.set(x0 + xx, y0 + yy, palette[bit as usize]);
                    }
                }
            } else {
                for yy in 0..h {
                    for xx in 0..w {
                        let idx = data[yy * w + xx] as usize;
                        fb.set(x0 + xx, y0 + yy, *palette.get(idx).unwrap_or(&0xFF00_0000));
                    }
                }
            }
        }
        _ => {
            // gradient filter (only defined for 3-byte TPIXELs in practice)
            let mut prev_row = vec![[0i32; 3]; w];
            let mut cur_row = vec![[0i32; 3]; w];
            for yy in 0..h {
                for xx in 0..w {
                    let i = (yy * w + xx) * tp;
                    let mut px = [0i32; 3];
                    for c in 0..3 {
                        let left = if xx > 0 { cur_row[xx - 1][c] } else { 0 };
                        let up = prev_row[xx][c];
                        let ul = if xx > 0 { prev_row[xx - 1][c] } else { 0 };
                        let pred = (left + up - ul).clamp(0, 255);
                        px[c] = (pred + data[i + c.min(tp - 1)] as i32) & 0xFF;
                    }
                    cur_row[xx] = px;
                    fb.set(x0 + xx, y0 + yy, rgba(px[0] as u8, px[1] as u8, px[2] as u8));
                }
                std::mem::swap(&mut prev_row, &mut cur_row);
            }
        }
    }
    Ok(())
}
