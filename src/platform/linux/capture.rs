//! X11 screen capture: MIT-SHM GetImage (fast, local display) with a plain
//! GetImage fallback, RandR monitor list, and XFixes cursor shapes.

use crate::rfb::encode::Frame;
use crate::server::CursorShape;
use anyhow::{anyhow, Context, Result};
use x11rb::connection::Connection;
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::protocol::xfixes::ConnectionExt as _;
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat};
use x11rb::rust_connection::RustConnection;

#[derive(Clone, Debug)]
pub struct MonitorInfo {
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

fn connect() -> Result<(RustConnection, usize)> {
    x11rb::connect(None).map_err(|e| anyhow!("cannot open the X11 display ({e}); PortlessVNC hosting needs an X11 (Xorg) session"))
}

/// Monitors with the primary one first (index 0 = primary).
pub fn monitors() -> Vec<MonitorInfo> {
    let Ok((conn, screen)) = connect() else { return Vec::new() };
    let root = conn.setup().roots[screen].root;
    let mut list = Vec::new();
    if let Ok(reply) = conn.randr_get_monitors(root, true).map_err(|_| ()).and_then(|c| c.reply().map_err(|_| ())) {
        for m in reply.monitors {
            let name = conn.get_atom_name(m.name).ok().and_then(|c| c.reply().ok()).map(|r| String::from_utf8_lossy(&r.name).into_owned()).unwrap_or_else(|| "monitor".into());
            list.push(MonitorInfo { name, x: m.x as i32, y: m.y as i32, width: m.width as u32, height: m.height as u32, primary: m.primary });
        }
    }
    list.sort_by_key(|m| (!m.primary, m.x, m.y));
    list
}

struct Shm {
    seg: u32,
    id: i32,
    ptr: *mut u8,
    size: usize,
}

pub struct Capturer {
    conn: RustConnection,
    root: u32,
    origin: (i32, i32),
    size: (u32, u32),
    shm: Option<Shm>,
    xfixes: bool,
    last_cursor: u32,
}

// the SHM pointer is only used by the capture thread that owns the Capturer
unsafe impl Send for Capturer {}

impl Capturer {
    /// `monitor` indexes `monitors()`; an index past the end means "all monitors".
    pub fn new(monitor: usize) -> Result<Self> {
        let (conn, screen) = connect()?;
        let scr = &conn.setup().roots[screen];
        let root = scr.root;
        if scr.root_depth < 24 {
            return Err(anyhow!("X11 screen depth {} is not supported (needs 24/32-bit colour)", scr.root_depth));
        }
        let (origin, size) = match monitors().get(monitor) {
            Some(m) => ((m.x, m.y), (m.width, m.height)),
            None => ((0, 0), (scr.width_in_pixels as u32, scr.height_in_pixels as u32)),
        };
        let xfixes = conn.xfixes_query_version(5, 0).ok().and_then(|c| c.reply().ok()).is_some();
        let mut c = Capturer { conn, root, origin, size, shm: None, xfixes, last_cursor: 0 };
        match c.setup_shm() {
            Ok(()) => log::info!("Screen capture: X11 MIT-SHM {}x{} at {},{}", size.0, size.1, origin.0, origin.1),
            Err(e) => log::info!("Screen capture: X11 GetImage {}x{} (shared memory unavailable: {e})", size.0, size.1),
        }
        Ok(c)
    }

    fn setup_shm(&mut self) -> Result<()> {
        self.conn.shm_query_version().context("MIT-SHM")?.reply().context("MIT-SHM")?;
        let size = (self.size.0 * self.size.1 * 4) as usize;
        unsafe {
            let id = libc::shmget(libc::IPC_PRIVATE, size, libc::IPC_CREAT | 0o600);
            if id < 0 {
                return Err(anyhow!("shmget failed"));
            }
            let ptr = libc::shmat(id, std::ptr::null(), 0);
            if ptr as isize == -1 {
                libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
                return Err(anyhow!("shmat failed"));
            }
            let seg = self.conn.generate_id()?;
            let attached = match self.conn.shm_attach(seg, id as u32, true) {
                Ok(cookie) => cookie.check().is_ok(),
                Err(_) => false,
            };
            // mark for deletion now: it disappears once both sides detach
            libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
            if !attached {
                libc::shmdt(ptr);
                return Err(anyhow!("X server cannot attach shared memory (remote display?)"));
            }
            self.shm = Some(Shm { seg, id, ptr: ptr as *mut u8, size });
        }
        Ok(())
    }

    pub fn origin(&self) -> (i32, i32) {
        self.origin
    }

    pub fn size(&self) -> (u32, u32) {
        self.size
    }

    /// Grab the current screen (X11 has no cheap "changed?" query; the
    /// encoder's tile diff skips unchanged areas).
    pub fn capture(&mut self, timeout_ms: u32) -> Result<Option<Frame>> {
        std::thread::sleep(std::time::Duration::from_millis((timeout_ms / 2).min(25) as u64));
        let (w, h) = (self.size.0 as usize, self.size.1 as usize);
        let (x, y) = (self.origin.0 as i16, self.origin.1 as i16);
        if let Some(shm) = &self.shm {
            let r = self.conn.shm_get_image(self.root, x, y, w as u16, h as u16, !0, ImageFormat::Z_PIXMAP.into(), shm.seg, 0)?.reply();
            if r.is_ok() {
                let mut data = vec![0u8; w * h * 4];
                unsafe { std::ptr::copy_nonoverlapping(shm.ptr, data.as_mut_ptr(), (w * h * 4).min(shm.size)) };
                return Ok(Some(Frame { width: w, height: h, data }));
            }
        }
        let r = self.conn.get_image(ImageFormat::Z_PIXMAP, self.root, x, y, w as u16, h as u16, !0)?.reply()?;
        if r.data.len() < w * h * 4 {
            return Err(anyhow!("unexpected X11 image format"));
        }
        Ok(Some(Frame { width: w, height: h, data: r.data[..w * h * 4].to_vec() }))
    }

    /// The cursor shape when it changed since the last call (XFixes).
    pub fn cursor(&mut self) -> Option<CursorShape> {
        if !self.xfixes {
            return None;
        }
        let img = self.conn.xfixes_get_cursor_image().ok()?.reply().ok()?;
        if img.cursor_serial == self.last_cursor {
            return None;
        }
        self.last_cursor = img.cursor_serial;
        let (w, h) = (img.width as usize, img.height as usize);
        if w == 0 || h == 0 || w > 256 || h > 256 {
            return None;
        }
        // ARGB (premultiplied) u32 -> BGRA bytes
        let mut bgra = Vec::with_capacity(w * h * 4);
        for p in img.cursor_image.iter().take(w * h) {
            bgra.extend_from_slice(&p.to_le_bytes());
        }
        Some(CursorShape { width: w, height: h, hot_x: img.xhot as usize, hot_y: img.yhot as usize, bgra })
    }
}

impl Drop for Capturer {
    fn drop(&mut self) {
        if let Some(shm) = self.shm.take() {
            let _ = self.conn.shm_detach(shm.seg);
            let _ = self.conn.flush();
            unsafe { libc::shmdt(shm.ptr as *const _) };
            let _ = shm.id;
        }
    }
}
