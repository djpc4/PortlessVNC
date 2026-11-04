//! CPU-drawn window for graphics too old for the normal renderers (Intel 945
//! and similar: OpenGL below 2.0, no Direct3D 12 or Vulkan). egui's triangles
//! are rasterized into a memory buffer and copied to the window with GDI.
//! Everything shows in one window: a session fills it until it is closed.

use eframe::egui::{self, epaint, Color32, ViewportCommand, ViewportId, ViewportInfo};
use egui_winit::winit;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{FreeLibrary, HWND};
use windows::Win32::Graphics::Gdi::{GetDC, ReleaseDC, SetDIBitsToDevice, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS};
use windows::Win32::Graphics::OpenGL::{glGetString, wglCreateContext, wglDeleteContext, wglMakeCurrent, ChoosePixelFormat, SetPixelFormat, GL_VERSION, PFD_DOUBLEBUFFER, PFD_DRAW_TO_WINDOW, PFD_SUPPORT_OPENGL, PFD_TYPE_RGBA, PIXELFORMATDESCRIPTOR};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::UI::WindowsAndMessaging::{CreateWindowExW, DestroyWindow, WINDOW_EX_STYLE, WS_POPUP};
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
use winit::window::{Window, WindowId};

// ---- do the normal renderers have anything to work with? -------------------

fn has_library(name: PCWSTR) -> bool {
    unsafe {
        match LoadLibraryW(name) {
            Ok(m) => {
                let _ = FreeLibrary(m);
                true
            }
            Err(_) => false,
        }
    }
}

/// The OpenGL version of the default adapter, e.g. (1, 4).
fn opengl_version() -> Option<(u32, u32)> {
    unsafe {
        let hwnd = CreateWindowExW(WINDOW_EX_STYLE(0), w!("STATIC"), w!("PortlessVNC GL check"), WS_POPUP, 0, 0, 16, 16, None, None, None, None).ok()?;
        let hdc = GetDC(hwnd);
        let pfd = PIXELFORMATDESCRIPTOR {
            nSize: std::mem::size_of::<PIXELFORMATDESCRIPTOR>() as u16,
            nVersion: 1,
            dwFlags: PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER,
            iPixelType: PFD_TYPE_RGBA,
            cColorBits: 32,
            ..Default::default()
        };
        let mut version = None;
        let format = ChoosePixelFormat(hdc, &pfd);
        if format != 0 && SetPixelFormat(hdc, format, &pfd).is_ok() {
            if let Ok(gl) = wglCreateContext(hdc) {
                if wglMakeCurrent(hdc, gl).is_ok() {
                    let s = glGetString(GL_VERSION);
                    if !s.is_null() {
                        let text = std::ffi::CStr::from_ptr(s as *const _).to_string_lossy().into_owned();
                        log::info!("OpenGL version: {text}");
                        let mut parts = text.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty());
                        if let (Some(a), Some(b)) = (parts.next(), parts.next()) {
                            version = a.parse().ok().zip(b.parse().ok());
                        }
                    }
                    let _ = wglMakeCurrent(None, None);
                }
                let _ = wglDeleteContext(gl);
            }
        }
        ReleaseDC(hwnd, hdc);
        let _ = DestroyWindow(hwnd);
        version
    }
}

/// True when neither normal renderer can work here. Machines with Direct3D 12
/// or Vulkan always take the normal path.
pub fn needed() -> bool {
    if has_library(w!("d3d12.dll")) || has_library(w!("vulkan-1.dll")) {
        return false;
    }
    !matches!(opengl_version(), Some((major, _)) if major >= 2)
}

// ---- rasterizer ---------------------------------------------------------------

struct Tex {
    w: usize,
    h: usize,
    px: Vec<Color32>,
    linear: bool,
}

#[derive(Clone, Copy)]
struct Clip {
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
}

#[inline]
fn bgra(c: Color32) -> u32 {
    let [r, g, b, a] = c.to_array();
    u32::from_le_bytes([b, g, r, a])
}

/// Premultiplied "source over" on one 32-bit pixel.
#[inline]
fn over(dst: &mut u32, src: u32) {
    let sa = src >> 24;
    if sa == 255 {
        *dst = src;
    } else if src != 0 {
        let inv = 255 - sa;
        let d = *dst;
        let rb = ((d & 0x00ff_00ff) * inv + 0x0080_0080) >> 8 & 0x00ff_00ff;
        let ag = ((d >> 8 & 0x00ff_00ff) * inv + 0x0080_0080) & 0xff00_ff00;
        *dst = src.wrapping_add(rb | ag);
    }
}

#[inline]
fn tint(c: Color32, t: Color32) -> Color32 {
    let m = |a: u8, b: u8| ((a as u32 * b as u32 + 127) / 255) as u8;
    Color32::from_rgba_premultiplied(m(c.r(), t.r()), m(c.g(), t.g()), m(c.b(), t.b()), m(c.a(), t.a()))
}

#[derive(Default)]
struct Raster {
    w: usize,
    h: usize,
    buf: Vec<u32>,
    tex: HashMap<egui::TextureId, Tex>,
}

impl Raster {
    fn resize(&mut self, w: usize, h: usize) {
        if (w, h) != (self.w, self.h) {
            self.w = w;
            self.h = h;
            self.buf = vec![0; w * h];
        }
    }

    fn set_textures(&mut self, delta: &epaint::textures::TexturesDelta) {
        for (id, d) in &delta.set {
            let [w, h] = d.image.size();
            let px: Vec<Color32> = match &d.image {
                egui::ImageData::Color(c) => c.pixels.clone(),
                egui::ImageData::Font(f) => f.srgba_pixels(None).collect(),
            };
            let linear = d.options.magnification == egui::TextureFilter::Linear;
            match d.pos {
                Some([x0, y0]) => {
                    if let Some(t) = self.tex.get_mut(id) {
                        for y in 0..h.min(t.h.saturating_sub(y0)) {
                            let n = w.min(t.w.saturating_sub(x0));
                            let start = (y0 + y) * t.w + x0;
                            t.px[start..start + n].copy_from_slice(&px[y * w..y * w + n]);
                        }
                    }
                }
                None => {
                    self.tex.insert(*id, Tex { w, h, px, linear });
                }
            }
        }
    }

    fn free_textures(&mut self, delta: &epaint::textures::TexturesDelta) {
        for id in &delta.free {
            self.tex.remove(id);
        }
    }

    fn render(&mut self, prims: &[epaint::ClippedPrimitive], ppp: f32) {
        self.buf.fill(0xff1b_1b1b);
        let (w, h) = (self.w as i32, self.h as i32);
        let mut tex = std::mem::take(&mut self.tex);
        for p in prims {
            let epaint::Primitive::Mesh(mesh) = &p.primitive else { continue };
            let Some(t) = tex.get(&mesh.texture_id) else { continue };
            let clip = Clip {
                x0: ((p.clip_rect.min.x * ppp).round() as i32).clamp(0, w),
                y0: ((p.clip_rect.min.y * ppp).round() as i32).clamp(0, h),
                x1: ((p.clip_rect.max.x * ppp).round() as i32).clamp(0, w),
                y1: ((p.clip_rect.max.y * ppp).round() as i32).clamp(0, h),
            };
            if clip.x0 >= clip.x1 || clip.y0 >= clip.y1 {
                continue;
            }
            if !self.quad(mesh, t, clip, ppp) {
                for tri in mesh.indices.chunks_exact(3) {
                    let v = |i: u32| &mesh.vertices[i as usize];
                    self.triangle(v(tri[0]), v(tri[1]), v(tri[2]), t, clip, ppp);
                }
            }
        }
        std::mem::swap(&mut self.tex, &mut tex);
    }

    /// Fast path for one large axis-aligned image: the remote screen.
    fn quad(&mut self, m: &epaint::Mesh, t: &Tex, clip: Clip, ppp: f32) -> bool {
        if m.vertices.len() != 4 || m.indices.len() != 6 {
            return false;
        }
        // egui's order: top left, top right, bottom left, bottom right
        let (a, c) = (&m.vertices[0], &m.vertices[3]);
        let (b, d) = (&m.vertices[1], &m.vertices[2]);
        let axis = (a.pos.y - b.pos.y).abs() < 0.01 && (d.pos.y - c.pos.y).abs() < 0.01 && (a.pos.x - d.pos.x).abs() < 0.01 && (b.pos.x - c.pos.x).abs() < 0.01;
        if !axis || (a.uv.x - c.uv.x).abs() < 1e-6 || a.color != Color32::WHITE || b.color != a.color || c.color != a.color || d.color != a.color {
            return false;
        }
        let (px0, py0, px1, py1) = (a.pos.x * ppp, a.pos.y * ppp, c.pos.x * ppp, c.pos.y * ppp);
        if px1 <= px0 || py1 <= py0 {
            return false;
        }
        let (x0, x1) = ((px0.round() as i32).max(clip.x0), (px1.round() as i32).min(clip.x1));
        let (y0, y1) = ((py0.round() as i32).max(clip.y0), (py1.round() as i32).min(clip.y1));
        // texels per output pixel, in 16.16 fixed point
        let tw = (c.uv.x - a.uv.x) * t.w as f32;
        let th = (c.uv.y - a.uv.y) * t.h as f32;
        let sx = tw / (px1 - px0);
        let sy = th / (py1 - py0);
        let same_size = (sx - 1.0).abs() < 0.001 && (sy - 1.0).abs() < 0.001;
        let bilinear = t.linear && !same_size;
        let (dx, dy) = ((sx * 65536.0) as i64, (sy * 65536.0) as i64);
        let origin_x = ((a.uv.x * t.w as f32 + (x0 as f32 + 0.5 - px0) * sx - if bilinear { 0.5 } else { 0.0 }) * 65536.0) as i64;
        let origin_y = ((a.uv.y * t.h as f32 + (y0 as f32 + 0.5 - py0) * sy - if bilinear { 0.5 } else { 0.0 }) * 65536.0) as i64;
        let (tw_i, th_i) = (t.w as i64 - 1, t.h as i64 - 1);
        for y in y0..y1 {
            let v = origin_y + dy * (y - y0) as i64;
            let row = &mut self.buf[y as usize * self.w + x0 as usize..y as usize * self.w + x1 as usize];
            let mut u = origin_x;
            if bilinear {
                let ty = (v >> 16).clamp(0, th_i);
                let ty1 = (ty + 1).min(th_i);
                let fy = ((v >> 8) & 0xff) as u32;
                for d in row.iter_mut() {
                    let tx = (u >> 16).clamp(0, tw_i);
                    let tx1 = (tx + 1).min(tw_i);
                    let fx = ((u >> 8) & 0xff) as u32;
                    let p = |x: i64, y: i64| t.px[(y * t.w as i64 + x) as usize];
                    let (c00, c10, c01, c11) = (p(tx, ty), p(tx1, ty), p(tx, ty1), p(tx1, ty1));
                    let mix = |a: u8, b: u8, c: u8, d: u8| -> u32 {
                        let top = a as u32 * (256 - fx) + b as u32 * fx;
                        let bot = c as u32 * (256 - fx) + d as u32 * fx;
                        (top * (256 - fy) + bot * fy) >> 16
                    };
                    let s = mix(c00.b(), c10.b(), c01.b(), c11.b()) | mix(c00.g(), c10.g(), c01.g(), c11.g()) << 8 | mix(c00.r(), c10.r(), c01.r(), c11.r()) << 16 | mix(c00.a(), c10.a(), c01.a(), c11.a()) << 24;
                    over(d, s);
                    u += dx;
                }
            } else {
                let ty = (v >> 16).clamp(0, th_i) as usize;
                for d in row.iter_mut() {
                    let tx = (u >> 16).clamp(0, tw_i) as usize;
                    over(d, bgra(t.px[ty * t.w + tx]));
                    u += dx;
                }
            }
        }
        true
    }

    fn triangle(&mut self, a: &epaint::Vertex, b: &epaint::Vertex, c: &epaint::Vertex, t: &Tex, clip: Clip, ppp: f32) {
        let (mut a, mut b) = (a, b);
        let (ax, ay) = (a.pos.x * ppp, a.pos.y * ppp);
        let (bx, by) = (b.pos.x * ppp, b.pos.y * ppp);
        let (cx, cy) = (c.pos.x * ppp, c.pos.y * ppp);
        let area = (bx - ax) * (cy - ay) - (by - ay) * (cx - ax);
        if area == 0.0 {
            return;
        }
        // same winding for every triangle
        let ((ax, ay), (bx, by)) = if area < 0.0 {
            std::mem::swap(&mut a, &mut b);
            ((bx, by), (ax, ay))
        } else {
            ((ax, ay), (bx, by))
        };
        let area = area.abs();
        let x0 = (ax.min(bx).min(cx).floor() as i32).max(clip.x0);
        let x1 = (ax.max(bx).max(cx).ceil() as i32).min(clip.x1);
        let y0 = (ay.min(by).min(cy).floor() as i32).max(clip.y0);
        let y1 = (ay.max(by).max(cy).ceil() as i32).min(clip.y1);
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        // an edge shared by two triangles belongs to exactly one of them
        let owned = |dx: f32, dy: f32| dy > 0.0 || (dy == 0.0 && dx > 0.0);
        let (o0, o1, o2) = (owned(cx - bx, cy - by), owned(ax - cx, ay - cy), owned(bx - ax, by - ay));
        let edge = |px: f32, py: f32, sx: f32, sy: f32, ex: f32, ey: f32| (ex - sx) * (py - sy) - (ey - sy) * (px - sx);
        let flat = a.color == b.color && b.color == c.color && a.uv == b.uv && b.uv == c.uv;
        let flat_px = if flat {
            let tx = ((a.uv.x * t.w as f32) as usize).min(t.w - 1);
            let ty = ((a.uv.y * t.h as f32) as usize).min(t.h - 1);
            bgra(tint(t.px[ty * t.w + tx], a.color))
        } else {
            0
        };
        let (s0x, s1x, s2x) = (-(cy - by), -(ay - cy), -(by - ay));
        for y in y0..y1 {
            let py = y as f32 + 0.5;
            let px = x0 as f32 + 0.5;
            let mut w0 = edge(px, py, bx, by, cx, cy);
            let mut w1 = edge(px, py, cx, cy, ax, ay);
            let mut w2 = edge(px, py, ax, ay, bx, by);
            let row = &mut self.buf[y as usize * self.w + x0 as usize..y as usize * self.w + x1 as usize];
            for d in row.iter_mut() {
                let inside = (w0 > 0.0 || (w0 == 0.0 && o0)) && (w1 > 0.0 || (w1 == 0.0 && o1)) && (w2 > 0.0 || (w2 == 0.0 && o2));
                if inside {
                    if flat {
                        over(d, flat_px);
                    } else {
                        let (l0, l1, l2) = (w0 / area, w1 / area, w2 / area);
                        let u = l0 * a.uv.x + l1 * b.uv.x + l2 * c.uv.x;
                        let v = l0 * a.uv.y + l1 * b.uv.y + l2 * c.uv.y;
                        let tx = ((u * t.w as f32) as usize).min(t.w - 1);
                        let ty = ((v * t.h as f32) as usize).min(t.h - 1);
                        let mix = |p: u8, q: u8, r: u8| (l0 * p as f32 + l1 * q as f32 + l2 * r as f32 + 0.5) as u8;
                        let col = Color32::from_rgba_premultiplied(mix(a.color.r(), b.color.r(), c.color.r()), mix(a.color.g(), b.color.g(), c.color.g()), mix(a.color.b(), b.color.b(), c.color.b()), mix(a.color.a(), b.color.a(), c.color.a()));
                        over(d, bgra(tint(t.px[ty * t.w + tx], col)));
                    }
                }
                w0 += s0x;
                w1 += s1x;
                w2 += s2x;
            }
        }
    }

    fn present(&self, hwnd: HWND) {
        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: self.w as i32,
                biHeight: -(self.h as i32), // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        unsafe {
            let hdc = GetDC(hwnd);
            SetDIBitsToDevice(hdc, 0, 0, self.w as u32, self.h as u32, 0, 0, 0, self.h as u32, self.buf.as_ptr().cast(), &bmi, DIB_RGB_COLORS);
            ReleaseDC(hwnd, hdc);
        }
    }
}

// ---- window and event loop ----------------------------------------------------

type MakeApp = Box<dyn FnOnce(&egui::Context) -> super::App>;

struct Runner {
    title: String,
    make: Option<MakeApp>,
    ctx: egui::Context,
    next_repaint: Arc<Mutex<Option<Instant>>>,
    live: Option<Live>,
}

struct Live {
    window: Arc<Window>,
    hwnd: HWND,
    state: egui_winit::State,
    info: ViewportInfo,
    actions: egui::ahash::HashSet<egui_winit::ActionRequested>,
    app: super::App,
    raster: Raster,
}

impl Runner {
    fn frame(&mut self, event_loop: &ActiveEventLoop) {
        let Some(l) = self.live.as_mut() else { return };
        egui_winit::update_viewport_info(&mut l.info, &self.ctx, &l.window, false);
        let mut raw = l.state.take_egui_input(&l.window);
        raw.viewports.insert(ViewportId::ROOT, l.info.clone());
        let closing = l.info.close_requested();
        l.info.events.clear();
        let app = &mut l.app;
        let mut out = self.ctx.run(raw, |ctx| app.frame(ctx));
        l.state.handle_platform_output(&l.window, std::mem::take(&mut out.platform_output));

        let size = l.window.inner_size();
        if size.width > 0 && size.height > 0 {
            l.raster.resize(size.width as usize, size.height as usize);
            l.raster.set_textures(&out.textures_delta);
            let prims = self.ctx.tessellate(std::mem::take(&mut out.shapes), out.pixels_per_point);
            l.raster.render(&prims, out.pixels_per_point);
            l.raster.free_textures(&out.textures_delta);
            l.raster.present(l.hwnd);
        } else {
            l.raster.set_textures(&out.textures_delta);
            l.raster.free_textures(&out.textures_delta);
        }

        let mut cancel = false;
        if let Some(v) = out.viewport_output.remove(&ViewportId::ROOT) {
            cancel = v.commands.iter().any(|c| matches!(c, ViewportCommand::CancelClose));
            egui_winit::process_viewport_commands(&self.ctx, &mut l.info, v.commands, &l.window, &mut l.actions);
        }
        if closing && !cancel {
            l.app.shutdown();
            event_loop.exit();
        }
        if l.info.close_requested() {
            l.window.request_redraw(); // a Close command: one more frame, then exit
        }
    }
}

impl ApplicationHandler<()> for Runner {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.live.is_some() {
            return;
        }
        let attrs = Window::default_attributes().with_title(self.title.clone()).with_inner_size(winit::dpi::LogicalSize::new(980.0, 660.0)).with_min_inner_size(winit::dpi::LogicalSize::new(640.0, 480.0));
        let window = match event_loop.create_window(attrs) {
            Ok(w) => Arc::new(w),
            Err(e) => {
                log::error!("could not create the window: {e}");
                super::show_startup_error(&format!("{e}"));
                event_loop.exit();
                return;
            }
        };
        let hwnd = match window.window_handle().map(|h| h.as_raw()) {
            Ok(RawWindowHandle::Win32(h)) => HWND(h.hwnd.get() as *mut _),
            _ => {
                event_loop.exit();
                return;
            }
        };
        let state = egui_winit::State::new(self.ctx.clone(), ViewportId::ROOT, &*window, Some(window.scale_factor() as f32), window.theme(), Some(16384));
        let mut info = ViewportInfo::default();
        egui_winit::update_viewport_info(&mut info, &self.ctx, &window, true);
        let app = (self.make.take().expect("created once"))(&self.ctx);
        self.live = Some(Live { window: window.clone(), hwnd, state, info, actions: Default::default(), app, raster: Raster::default() });
        log::info!("Drawing with the CPU (software rendering)");
        window.request_redraw();
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, _event: ()) {}

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        if matches!(event, WindowEvent::RedrawRequested) {
            self.frame(event_loop);
            return;
        }
        let Some(l) = self.live.as_mut() else { return };
        if matches!(event, WindowEvent::CloseRequested) {
            l.info.events.push(egui::ViewportEvent::Close);
            l.window.request_redraw();
            return;
        }
        let response = l.state.on_window_event(&l.window, &event);
        if response.repaint {
            l.window.request_redraw();
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        let Some(l) = self.live.as_ref() else { return };
        let mut next = self.next_repaint.lock();
        match *next {
            Some(t) if t <= Instant::now() => {
                *next = None;
                l.window.request_redraw();
                event_loop.set_control_flow(ControlFlow::Wait);
            }
            Some(t) => event_loop.set_control_flow(ControlFlow::WaitUntil(t)),
            None => event_loop.set_control_flow(ControlFlow::Wait),
        }
    }
}

/// Open the program's window drawn with the CPU; returns when it closes.
pub fn run(title: &str, make: MakeApp) -> Result<(), String> {
    let event_loop = EventLoop::<()>::with_user_event().build().map_err(|e| e.to_string())?;
    let ctx = egui::Context::default();
    ctx.set_embed_viewports(true); // one window: sessions draw inside it
    let next_repaint: Arc<Mutex<Option<Instant>>> = Arc::default();
    {
        let proxy = event_loop.create_proxy();
        let next = next_repaint.clone();
        ctx.set_request_repaint_callback(move |info| {
            // at most about 30 frames per second: the CPU does all the drawing
            let at = Instant::now() + info.delay.max(Duration::from_millis(33));
            let mut n = next.lock();
            if n.map(|t| at < t).unwrap_or(true) {
                *n = Some(at);
            }
            let _ = proxy.send_event(());
        });
    }
    let mut runner = Runner { title: title.to_string(), make: Some(make), ctx, next_repaint, live: None };
    event_loop.run_app(&mut runner).map_err(|e| e.to_string())
}
