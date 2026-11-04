//! Small shared helpers: UI log sink, formatting, randomness.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::OnceLock;

pub struct LogLine {
    pub level: log::Level,
    pub text: String,
}

static UI_LOG: OnceLock<Mutex<VecDeque<LogLine>>> = OnceLock::new();
static REPAINT: OnceLock<Mutex<Option<eframe::egui::Context>>> = OnceLock::new();

fn ui_log() -> &'static Mutex<VecDeque<LogLine>> {
    UI_LOG.get_or_init(|| Mutex::new(VecDeque::new()))
}

pub fn set_repaint_ctx(ctx: eframe::egui::Context) {
    *REPAINT.get_or_init(|| Mutex::new(None)).lock() = Some(ctx);
}

/// Ask the GUI to redraw soon (safe to call from any thread).
pub fn request_repaint() {
    if let Some(m) = REPAINT.get() {
        if let Some(ctx) = m.lock().as_ref() {
            ctx.request_repaint();
        }
    }
}

pub fn with_log<R>(f: impl FnOnce(&VecDeque<LogLine>) -> R) -> R {
    f(&ui_log().lock())
}

struct Logger {
    inner: env_logger::Logger,
}

impl log::Log for Logger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info || self.inner.enabled(m)
    }
    fn log(&self, record: &log::Record) {
        let ours = record.target().starts_with("portless") || record.target().starts_with("PortlessVNC");
        if self.inner.enabled(record.metadata()) {
            self.inner.log(record);
        }
        if ours && record.level() <= log::Level::Info {
            let mut q = ui_log().lock();
            q.push_back(LogLine { level: record.level(), text: format!("{}", record.args()) });
            while q.len() > 400 {
                q.pop_front();
            }
            drop(q);
            request_repaint();
        }
    }
    fn flush(&self) {}
}

pub fn init_logging() {
    init_logging_to(None)
}

/// Log to stderr, or to a file (service mode has no console).
pub fn init_logging_to(file: Option<std::path::PathBuf>) {
    let mut b = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn,PortlessVNC=info"));
    if let Some(p) = file {
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        // keep the log small: start fresh when it grows past 2 MB
        if std::fs::metadata(&p).map(|m| m.len() > 2 << 20).unwrap_or(false) {
            let _ = std::fs::remove_file(&p);
        }
        if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
            b.target(env_logger::Target::Pipe(Box::new(f)));
        }
    }
    let inner = b.build();
    let max = inner.filter().max(log::LevelFilter::Info);
    if log::set_boxed_logger(Box::new(Logger { inner })).is_ok() {
        log::set_max_level(max);
    }
}

pub fn random_password(len: usize) -> String {
    use rand::Rng;
    // avoid look-alike characters
    const CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..len).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

pub fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}

/// Format a SHA-256 fingerprint for humans: first 16 bytes as xx-xx groups.
pub fn short_fingerprint(hex_fp: &str) -> String {
    hex_fp
        .as_bytes()
        .chunks(4)
        .take(8)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

/// Make a path component safe: no separators, no parent refs, no drive letters.
pub fn sanitize_rel_path(p: &str) -> Option<std::path::PathBuf> {
    let mut out = std::path::PathBuf::new();
    for part in p.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains(':') {
            return None;
        }
        let clean: String = part.chars().map(|c| if "<>\"|?*".contains(c) || (c as u32) < 32 { '_' } else { c }).collect();
        out.push(clean);
    }
    if out.as_os_str().is_empty() { None } else { Some(out) }
}

/// Find a non-existing path by appending " (n)" before the extension.
pub fn unique_path(p: std::path::PathBuf) -> std::path::PathBuf {
    if !p.exists() {
        return p;
    }
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = p.extension().map(|s| format!(".{}", s.to_string_lossy())).unwrap_or_default();
    let dir = p.parent().map(|d| d.to_path_buf()).unwrap_or_default();
    for i in 1..10000 {
        let c = dir.join(format!("{stem} ({i}){ext}"));
        if !c.exists() {
            return c;
        }
    }
    p
}
