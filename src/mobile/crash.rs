//! Crash reports without adb: the last log lines are kept in memory and
//! written to crash.txt on a panic or a fatal signal; the next start shows
//! the report (with a Copy button) instead of the app.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

static LINES: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
static FILE: OnceLock<PathBuf> = OnceLock::new();

struct Logger {
    inner: android_logger::AndroidLogger,
}

impl log::Log for Logger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        // ours at info; libraries (wgpu is chatty) only warnings
        let ours = m.target().starts_with("portless");
        let max = if ours { log::Level::Info } else { log::Level::Warn };
        m.level() <= max && !m.target().starts_with("wgpu_hal::vulkan::conv")
    }
    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        log::Log::log(&self.inner, r);
        if let Some(mut q) = LINES.try_lock() {
            q.push_back(format!("{} {}: {}", r.level(), r.target(), r.args()));
            while q.len() > 150 {
                q.pop_front();
            }
        }
    }
    fn flush(&self) {}
}

pub fn path() -> Option<&'static PathBuf> {
    FILE.get()
}

pub fn write_report(reason: &str) {
    let Some(p) = FILE.get() else { return };
    let Ok(mut f) = std::fs::File::create(p) else { return };
    let _ = writeln!(f, "PortlessVNC {} crashed: {reason}\n\nLast log lines:", env!("CARGO_PKG_VERSION"));
    if let Some(q) = LINES.try_lock() {
        for l in q.iter() {
            let _ = writeln!(f, "{l}");
        }
    }
}

extern "C" fn on_signal(sig: libc::c_int) {
    write_report(&format!("native signal {sig}"));
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

pub fn install(dir: &std::path::Path) {
    let _ = FILE.set(dir.join("crash.txt"));
    let inner = android_logger::AndroidLogger::new(android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("PortlessVNC"));
    if log::set_boxed_logger(Box::new(Logger { inner })).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
    std::panic::set_hook(Box::new(|p| {
        let bt = std::backtrace::Backtrace::force_capture();
        log::error!("panic: {p}");
        write_report(&format!("{p}\n\n{bt}"));
    }));
    unsafe {
        for s in [libc::SIGSEGV, libc::SIGABRT, libc::SIGBUS, libc::SIGILL, libc::SIGFPE] {
            libc::signal(s, on_signal as usize);
        }
    }
}
