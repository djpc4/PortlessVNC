//! Screen capture: DXGI Desktop Duplication (fast, GPU-side) with a GDI BitBlt
//! fallback (works in RDP sessions, VMs without a GPU, and for "all monitors").

use crate::rfb::encode::Frame;
use crate::server::CursorShape;
use anyhow::{anyhow, Context, Result};
use windows::core::Interface;
use windows::Win32::Foundation::{BOOL, HMODULE, HWND, LPARAM, RECT};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_9_1};
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_B8G8R8A8_UNORM;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::WindowsAndMessaging::{GetCursorInfo, GetIconInfo, GetSystemMetrics, CURSORINFO, CURSOR_SHOWING, HICON, ICONINFO, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN};

#[derive(Clone, Debug)]
pub struct MonitorInfo {
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

unsafe extern "system" fn enum_proc(hmon: HMONITOR, _hdc: HDC, _rc: *mut RECT, data: LPARAM) -> BOOL {
    let list = &mut *(data.0 as *mut Vec<MonitorInfo>);
    let mut mi = MONITORINFOEXW::default();
    mi.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
    if GetMonitorInfoW(hmon, &mut mi.monitorInfo as *mut MONITORINFO).as_bool() {
        let r = mi.monitorInfo.rcMonitor;
        let end = mi.szDevice.iter().position(|&c| c == 0).unwrap_or(mi.szDevice.len());
        list.push(MonitorInfo {
            name: String::from_utf16_lossy(&mi.szDevice[..end]),
            x: r.left,
            y: r.top,
            width: (r.right - r.left) as u32,
            height: (r.bottom - r.top) as u32,
            primary: mi.monitorInfo.dwFlags & 1 != 0,
        });
    }
    BOOL(1)
}

/// Monitors with the primary one first (index 0 = primary).
pub fn monitors() -> Vec<MonitorInfo> {
    let mut list: Vec<MonitorInfo> = Vec::new();
    unsafe {
        let _ = EnumDisplayMonitors(HDC::default(), None, Some(enum_proc), LPARAM(&mut list as *mut _ as isize));
    }
    list.sort_by_key(|m| (!m.primary, m.x, m.y));
    list
}

fn virtual_screen() -> (i32, i32, u32, u32) {
    unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1) as u32,
            GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1) as u32,
        )
    }
}

// ---------------------------------------------------------------------------

struct DxgiCap {
    device: ID3D11Device,
    ctx: ID3D11DeviceContext,
    dup: IDXGIOutputDuplication,
    staging: Option<ID3D11Texture2D>,
    origin: (i32, i32),
    size: (u32, u32),
    last: Option<Frame>,
}

impl DxgiCap {
    fn new(mon: &MonitorInfo) -> Result<Self> {
        unsafe {
            let factory: IDXGIFactory1 = CreateDXGIFactory1().context("CreateDXGIFactory1")?;
            let mut i = 0;
            loop {
                let adapter = match factory.EnumAdapters1(i) {
                    Ok(a) => a,
                    Err(_) => break,
                };
                i += 1;
                let mut j = 0;
                while let Ok(output) = adapter.EnumOutputs(j) {
                    j += 1;
                    let desc = output.GetDesc()?;
                    let r = desc.DesktopCoordinates;
                    if r.left != mon.x || r.top != mon.y {
                        continue;
                    }
                    let mut device = None;
                    let mut ctx = None;
                    let levels = [D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_9_1];
                    D3D11CreateDevice(
                        &adapter,
                        D3D_DRIVER_TYPE_UNKNOWN,
                        HMODULE::default(),
                        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                        Some(&levels),
                        D3D11_SDK_VERSION,
                        Some(&mut device),
                        None,
                        Some(&mut ctx),
                    )
                    .context("D3D11CreateDevice")?;
                    let device = device.ok_or_else(|| anyhow!("no d3d device"))?;
                    let ctx = ctx.ok_or_else(|| anyhow!("no d3d context"))?;
                    let output1: IDXGIOutput1 = output.cast()?;
                    let dup = output1.DuplicateOutput(&device).context("DuplicateOutput")?;
                    let dd = dup.GetDesc();
                    if dd.ModeDesc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
                        return Err(anyhow!("unsupported desktop format (HDR?)"));
                    }
                    return Ok(DxgiCap {
                        device,
                        ctx,
                        dup,
                        staging: None,
                        origin: (r.left, r.top),
                        size: ((r.right - r.left) as u32, (r.bottom - r.top) as u32),
                        last: None,
                    });
                }
            }
            Err(anyhow!("no DXGI output for monitor {}", mon.name))
        }
    }

    fn capture(&mut self, timeout_ms: u32) -> Result<Option<Frame>> {
        unsafe {
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut res: Option<IDXGIResource> = None;
            if let Err(e) = self.dup.AcquireNextFrame(timeout_ms, &mut info, &mut res) {
                if e.code() == DXGI_ERROR_WAIT_TIMEOUT {
                    return Ok(None);
                }
                return Err(anyhow!("AcquireNextFrame: {e}"));
            }
            let result = (|| -> Result<Option<Frame>> {
                if info.LastPresentTime == 0 {
                    if self.last.is_some() {
                        return Ok(None); // pointer-only update
                    }
                    // The first duplicated frame can be blank until something
                    // presents; grab the initial image with GDI instead.
                    let mut g = GdiCap::new(self.origin.0, self.origin.1, self.size.0, self.size.1)?;
                    return g.capture();
                }
                let tex: ID3D11Texture2D = res.as_ref().ok_or_else(|| anyhow!("no resource"))?.cast()?;
                let mut desc = D3D11_TEXTURE2D_DESC::default();
                tex.GetDesc(&mut desc);
                let need_new = match &self.staging {
                    Some(s) => {
                        let mut sd = D3D11_TEXTURE2D_DESC::default();
                        s.GetDesc(&mut sd);
                        sd.Width != desc.Width || sd.Height != desc.Height
                    }
                    None => true,
                };
                if need_new {
                    let mut sd = desc;
                    sd.Usage = D3D11_USAGE_STAGING;
                    sd.BindFlags = 0;
                    sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
                    sd.MiscFlags = 0;
                    sd.MipLevels = 1;
                    sd.ArraySize = 1;
                    sd.SampleDesc.Count = 1;
                    sd.SampleDesc.Quality = 0;
                    let mut st = None;
                    self.device.CreateTexture2D(&sd, None, Some(&mut st))?;
                    self.staging = st;
                }
                let staging = self.staging.as_ref().unwrap();
                self.ctx.CopyResource(staging, &tex);
                let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                self.ctx.Map(staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
                let (w, h) = (desc.Width as usize, desc.Height as usize);
                let mut data = vec![0u8; w * h * 4];
                let src = mapped.pData as *const u8;
                for y in 0..h {
                    std::ptr::copy_nonoverlapping(src.add(y * mapped.RowPitch as usize), data.as_mut_ptr().add(y * w * 4), w * 4);
                }
                self.ctx.Unmap(staging, 0);
                self.size = (w as u32, h as u32);
                Ok(Some(Frame { width: w, height: h, data }))
            })();
            let _ = self.dup.ReleaseFrame();
            let r = result?;
            if let Some(f) = &r {
                self.last = Some(f.clone());
            }
            Ok(r)
        }
    }
}

// ---------------------------------------------------------------------------

struct GdiCap {
    origin: (i32, i32),
    size: (u32, u32),
    screen_dc: HDC,
    mem_dc: HDC,
    bmp: HBITMAP,
    old: HGDIOBJ,
    bits: *mut u8,
}

unsafe impl Send for GdiCap {}

impl GdiCap {
    fn new(x: i32, y: i32, w: u32, h: u32) -> Result<Self> {
        unsafe {
            let screen_dc = GetDC(HWND::default());
            let mem_dc = CreateCompatibleDC(screen_dc);
            let mut bmi = BITMAPINFO::default();
            bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
            bmi.bmiHeader.biWidth = w as i32;
            bmi.bmiHeader.biHeight = -(h as i32);
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;
            bmi.bmiHeader.biCompression = BI_RGB.0;
            let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
            let bmp = CreateDIBSection(mem_dc, &bmi, DIB_RGB_COLORS, &mut bits, None, 0).context("CreateDIBSection")?;
            let old = SelectObject(mem_dc, bmp);
            Ok(GdiCap { origin: (x, y), size: (w, h), screen_dc, mem_dc, bmp, old, bits: bits as *mut u8 })
        }
    }

    fn capture(&mut self) -> Result<Option<Frame>> {
        let (w, h) = (self.size.0 as usize, self.size.1 as usize);
        unsafe {
            BitBlt(self.mem_dc, 0, 0, w as i32, h as i32, self.screen_dc, self.origin.0, self.origin.1, SRCCOPY | CAPTUREBLT).context("BitBlt")?;
            let _ = GdiFlush();
            let mut data = vec![0u8; w * h * 4];
            std::ptr::copy_nonoverlapping(self.bits, data.as_mut_ptr(), w * h * 4);
            Ok(Some(Frame { width: w, height: h, data }))
        }
    }
}

impl Drop for GdiCap {
    fn drop(&mut self) {
        unsafe {
            SelectObject(self.mem_dc, self.old);
            let _ = DeleteObject(self.bmp);
            let _ = DeleteDC(self.mem_dc);
            ReleaseDC(HWND::default(), self.screen_dc);
        }
    }
}

// ---------------------------------------------------------------------------

enum Backend {
    Dxgi(DxgiCap),
    Gdi(GdiCap),
}

pub struct Capturer {
    backend: Backend,
    monitor: usize,
    last_cursor: isize,
    dxgi_failures: u32,
}

impl Capturer {
    /// `monitor` indexes `monitors()`; an index past the end means "all monitors".
    pub fn new(monitor: usize) -> Result<Self> {
        let backend = Self::make_backend(monitor, true)?;
        Ok(Capturer { backend, monitor, last_cursor: 0, dxgi_failures: 0 })
    }

    fn make_backend(monitor: usize, try_dxgi: bool) -> Result<Backend> {
        let mons = monitors();
        if let Some(m) = mons.get(monitor) {
            if try_dxgi {
                match DxgiCap::new(m) {
                    Ok(d) => {
                        log::info!("Screen capture: DXGI desktop duplication on {} ({}x{})", m.name, m.width, m.height);
                        return Ok(Backend::Dxgi(d));
                    }
                    Err(e) => log::info!("DXGI capture unavailable ({e}); using GDI"),
                }
            }
            return Ok(Backend::Gdi(GdiCap::new(m.x, m.y, m.width, m.height)?));
        }
        let (x, y, w, h) = virtual_screen();
        log::info!("Screen capture: GDI, all monitors ({w}x{h})");
        Ok(Backend::Gdi(GdiCap::new(x, y, w, h)?))
    }

    pub fn origin(&self) -> (i32, i32) {
        match &self.backend {
            Backend::Dxgi(d) => d.origin,
            Backend::Gdi(g) => g.origin,
        }
    }

    pub fn size(&self) -> (u32, u32) {
        match &self.backend {
            Backend::Dxgi(d) => d.size,
            Backend::Gdi(g) => g.size,
        }
    }

    /// Returns a new frame, or None when nothing changed.
    pub fn capture(&mut self, timeout_ms: u32) -> Result<Option<Frame>> {
        match &mut self.backend {
            Backend::Dxgi(d) => match d.capture(timeout_ms) {
                Ok(f) => {
                    self.dxgi_failures = 0;
                    Ok(f)
                }
                Err(e) => {
                    // Access lost (mode change, UAC/lock screen, fullscreen app): rebuild.
                    self.dxgi_failures += 1;
                    log::debug!("DXGI capture error: {e}");
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    let try_dxgi = self.dxgi_failures < 20;
                    self.backend = Self::make_backend(self.monitor, try_dxgi)?;
                    Ok(None)
                }
            },
            Backend::Gdi(g) => {
                std::thread::sleep(std::time::Duration::from_millis(timeout_ms.min(50) as u64 / 2));
                g.capture()
            }
        }
    }

    /// Returns the cursor shape when it changed since the last call.
    pub fn cursor(&mut self) -> Option<CursorShape> {
        unsafe {
            let mut ci = CURSORINFO { cbSize: std::mem::size_of::<CURSORINFO>() as u32, ..Default::default() };
            if GetCursorInfo(&mut ci).is_err() {
                return None;
            }
            let handle = if ci.flags.0 & CURSOR_SHOWING.0 != 0 { ci.hCursor.0 as isize } else { -1 };
            if handle == self.last_cursor {
                return None;
            }
            self.last_cursor = handle;
            if handle == -1 {
                return Some(CursorShape { width: 1, height: 1, hot_x: 0, hot_y: 0, bgra: vec![0, 0, 0, 0] });
            }
            cursor_shape(HICON(ci.hCursor.0))
        }
    }
}

unsafe fn bitmap_bits(dc: HDC, bmp: HBITMAP, w: i32, h: i32) -> Option<Vec<u8>> {
    let mut bmi = BITMAPINFO::default();
    bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    bmi.bmiHeader.biWidth = w;
    bmi.bmiHeader.biHeight = -h;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB.0;
    let mut buf = vec![0u8; (w * h * 4) as usize];
    let n = GetDIBits(dc, bmp, 0, h as u32, Some(buf.as_mut_ptr() as *mut _), &mut bmi, DIB_RGB_COLORS);
    if n == 0 { None } else { Some(buf) }
}

unsafe fn cursor_shape(icon: HICON) -> Option<CursorShape> {
    let mut ii = ICONINFO::default();
    GetIconInfo(icon, &mut ii).ok()?;
    let dc = GetDC(HWND::default());
    let mut bm = BITMAP::default();
    let shape = (|| {
        if GetObjectW(ii.hbmMask, std::mem::size_of::<BITMAP>() as i32, Some(&mut bm as *mut _ as *mut _)) == 0 {
            return None;
        }
        let w = bm.bmWidth;
        let mask_h = bm.bmHeight;
        let mono = ii.hbmColor.is_invalid();
        let h = if mono { mask_h / 2 } else { mask_h };
        if w <= 0 || h <= 0 || w > 256 || h > 256 {
            return None;
        }
        let mask = bitmap_bits(dc, ii.hbmMask, w, mask_h)?;
        let mut out = vec![0u8; (w * h * 4) as usize];
        if mono {
            for i in 0..(w * h) as usize {
                let and = mask[i * 4] != 0;
                let xor = mask[(i + (w * h) as usize) * 4] != 0;
                let (c, a) = match (and, xor) {
                    (false, false) => (0u8, 255u8),
                    (false, true) => (255, 255),
                    (true, false) => (0, 0),
                    (true, true) => (0, 255), // "invert" — draw black
                };
                out[i * 4..i * 4 + 4].copy_from_slice(&[c, c, c, a]);
            }
        } else {
            let color = bitmap_bits(dc, ii.hbmColor, w, h)?;
            let has_alpha = color.chunks(4).any(|p| p[3] != 0);
            for i in 0..(w * h) as usize {
                let a = if has_alpha { color[i * 4 + 3] } else if mask[i * 4] == 0 { 255 } else { 0 };
                out[i * 4..i * 4 + 4].copy_from_slice(&[color[i * 4], color[i * 4 + 1], color[i * 4 + 2], a]);
            }
        }
        Some(CursorShape { width: w as usize, height: h as usize, hot_x: ii.xHotspot as usize, hot_y: ii.yHotspot as usize, bgra: out })
    })();
    ReleaseDC(HWND::default(), dc);
    if !ii.hbmMask.is_invalid() {
        let _ = DeleteObject(ii.hbmMask);
    }
    if !ii.hbmColor.is_invalid() {
        let _ = DeleteObject(ii.hbmColor);
    }
    shape
}
