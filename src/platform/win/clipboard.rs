//! Windows clipboard integration.
//!
//! * Text: CF_UNICODETEXT is mirrored both ways.
//! * Files: copying files in Explorer offers them to the remote side. Remote
//!   files are announced with *delayed rendering* of CF_HDROP: nothing is
//!   transferred until the user actually pastes, at which point the files are
//!   downloaded to a staging folder and handed to Explorer.

use crate::hub::{ClipCmd, Hub};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use windows::core::w;
use windows::Win32::Foundation::{BOOL, HANDLE, HGLOBAL, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::DataExchange::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::{CF_HDROP, CF_UNICODETEXT};
use windows::Win32::UI::Shell::{DragQueryFileW, DROPFILES, HDROP};
use windows::Win32::UI::WindowsAndMessaging::*;

const WM_APP_CMD: u32 = WM_APP + 1;

static HUB: OnceLock<Arc<Hub>> = OnceLock::new();
static QUEUE: OnceLock<Mutex<VecDeque<ClipCmd>>> = OnceLock::new();
static HWND_VAL: OnceLock<isize> = OnceLock::new();

fn queue() -> &'static Mutex<VecDeque<ClipCmd>> {
    QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Start the clipboard thread and connect it to the hub.
pub fn start(hub: Arc<Hub>) {
    let _ = HUB.set(hub.clone());
    std::thread::Builder::new()
        .name("clipboard".into())
        .spawn(|| unsafe { run() })
        .ok();
    hub.set_clipboard_backend(Box::new(|cmd| {
        queue().lock().push_back(cmd);
        if let Some(&h) = HWND_VAL.get() {
            unsafe {
                let _ = PostMessageW(HWND(h as *mut _), WM_APP_CMD, WPARAM(0), LPARAM(0));
            }
        }
    }));
}

unsafe fn run() {
    let hinst = GetModuleHandleW(None).unwrap_or_default();
    let class = w!("PortlessVNCClipboard");
    let wc = WNDCLASSW { lpfnWndProc: Some(wndproc), hInstance: hinst.into(), lpszClassName: class, ..Default::default() };
    RegisterClassW(&wc);
    let hwnd = match CreateWindowExW(WINDOW_EX_STYLE(0), class, w!("PortlessVNC clipboard"), WINDOW_STYLE(0), 0, 0, 0, 0, HWND_MESSAGE, None, hinst, None) {
        Ok(h) => h,
        Err(e) => {
            log::warn!("Clipboard window failed: {e}");
            return;
        }
    };
    let _ = HWND_VAL.set(hwnd.0 as isize);
    if AddClipboardFormatListener(hwnd).is_err() {
        log::warn!("Clipboard listener failed; clipboard sync disabled");
    }
    let mut msg = MSG::default();
    while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

unsafe fn open_clipboard(hwnd: HWND) -> bool {
    for _ in 0..10 {
        if OpenClipboard(hwnd).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

enum LocalContent {
    Text(String),
    Files(Vec<PathBuf>),
}

unsafe fn read_clipboard(hwnd: HWND) -> Option<LocalContent> {
    if !open_clipboard(hwnd) {
        return None;
    }
    let result = (|| {
        if IsClipboardFormatAvailable(CF_HDROP.0 as u32).is_ok() {
            let h = GetClipboardData(CF_HDROP.0 as u32).ok()?;
            let hdrop = HDROP(h.0);
            let n = DragQueryFileW(hdrop, 0xFFFF_FFFF, None);
            let mut files = Vec::new();
            for i in 0..n {
                let len = DragQueryFileW(hdrop, i, None) as usize;
                let mut buf = vec![0u16; len + 1];
                DragQueryFileW(hdrop, i, Some(&mut buf));
                files.push(PathBuf::from(String::from_utf16_lossy(&buf[..len])));
            }
            return Some(LocalContent::Files(files));
        }
        if IsClipboardFormatAvailable(CF_UNICODETEXT.0 as u32).is_ok() {
            let h = GetClipboardData(CF_UNICODETEXT.0 as u32).ok()?;
            let g = HGLOBAL(h.0);
            let p = GlobalLock(g) as *const u16;
            if p.is_null() {
                return None;
            }
            let max = GlobalSize(g) / 2;
            let mut len = 0;
            while len < max && *p.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            let _ = GlobalUnlock(g);
            return Some(LocalContent::Text(s));
        }
        None
    })();
    let _ = CloseClipboard();
    result
}

unsafe fn global_from_bytes(bytes: &[u8]) -> Option<HGLOBAL> {
    let g = GlobalAlloc(GMEM_MOVEABLE, bytes.len()).ok()?;
    let p = GlobalLock(g) as *mut u8;
    if p.is_null() {
        return None;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
    let _ = GlobalUnlock(g);
    Some(g)
}

pub(crate) unsafe fn set_text(hwnd: HWND, text: &str) {
    let normalized = text.replace("\r\n", "\n").replace('\n', "\r\n");
    let wide: Vec<u16> = normalized.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
    if !open_clipboard(hwnd) {
        return;
    }
    let _ = EmptyClipboard();
    if let Some(g) = global_from_bytes(bytes) {
        let _ = SetClipboardData(CF_UNICODETEXT.0 as u32, HANDLE(g.0));
    }
    let _ = CloseClipboard();
}

unsafe fn set_files_delayed(hwnd: HWND) {
    if !open_clipboard(hwnd) {
        return;
    }
    let _ = EmptyClipboard();
    // NULL handle = delayed rendering; Windows sends WM_RENDERFORMAT on paste.
    let _ = SetClipboardData(CF_HDROP.0 as u32, HANDLE::default());
    let effect_fmt = RegisterClipboardFormatW(w!("Preferred DropEffect"));
    if let Some(g) = global_from_bytes(&1u32.to_le_bytes()) {
        let _ = SetClipboardData(effect_fmt, HANDLE(g.0)); // DROPEFFECT_COPY
    }
    let _ = CloseClipboard();
}

unsafe fn hdrop_global(paths: &[PathBuf]) -> Option<HGLOBAL> {
    let header = std::mem::size_of::<DROPFILES>();
    let mut list: Vec<u16> = Vec::new();
    for p in paths {
        list.extend(p.as_os_str().to_string_lossy().encode_utf16());
        list.push(0);
    }
    list.push(0);
    let df = DROPFILES { pFiles: header as u32, pt: POINT::default(), fNC: BOOL(0), fWide: BOOL(1) };
    let mut bytes = Vec::with_capacity(header + list.len() * 2);
    bytes.extend_from_slice(std::slice::from_raw_parts(&df as *const DROPFILES as *const u8, header));
    bytes.extend_from_slice(std::slice::from_raw_parts(list.as_ptr() as *const u8, list.len() * 2));
    global_from_bytes(&bytes)
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CLIPBOARDUPDATE => {
            if GetClipboardOwner().map(|h| h == hwnd).unwrap_or(false) {
                return LRESULT(0); // our own change
            }
            if let (Some(content), Some(hub)) = (read_clipboard(hwnd), HUB.get()) {
                let hub = hub.clone();
                // never block the clipboard thread on network I/O
                std::thread::spawn(move || match content {
                    LocalContent::Text(t) => hub.local_text_changed(t),
                    LocalContent::Files(f) => hub.local_files_changed(f),
                });
            }
            LRESULT(0)
        }
        WM_APP_CMD => {
            let cmds: Vec<ClipCmd> = queue().lock().drain(..).collect();
            for c in cmds {
                match c {
                    ClipCmd::SetText(t) => set_text(hwnd, &t),
                    ClipCmd::SetFilesDelayed => set_files_delayed(hwnd),
                }
            }
            LRESULT(0)
        }
        WM_RENDERFORMAT => {
            if wparam.0 as u32 == CF_HDROP.0 as u32 {
                if let Some(hub) = HUB.get() {
                    if let Some(paths) = hub.render_remote_files() {
                        if let Some(g) = hdrop_global(&paths) {
                            let _ = SetClipboardData(CF_HDROP.0 as u32, HANDLE(g.0));
                        }
                    }
                }
            }
            LRESULT(0)
        }
        WM_RENDERALLFORMATS => {
            // We are exiting and cannot download later: drop the pending offer.
            if open_clipboard(hwnd) {
                if GetClipboardOwner().map(|h| h == hwnd).unwrap_or(false) {
                    let _ = EmptyClipboard();
                }
                let _ = CloseClipboard();
            }
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}
