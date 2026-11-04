//! Text clipboard sync on Linux (X11 CLIPBOARD selection via arboard).
//! Copying files through the clipboard is Windows-only; use "Send files".

use crate::hub::{ClipCmd, Hub};
use std::sync::Arc;
use std::time::Duration;

pub fn start(hub: Arc<Hub>) {
    let (tx, rx) = crossbeam_channel::unbounded::<ClipCmd>();
    hub.set_clipboard_backend(Box::new(move |c| {
        let _ = tx.send(c);
    }));
    std::thread::Builder::new()
        .name("clipboard".into())
        .spawn(move || {
            let mut cb = match arboard::Clipboard::new() {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("Clipboard unavailable ({e}); clipboard sync disabled");
                    return;
                }
            };
            let mut last = cb.get_text().unwrap_or_default();
            loop {
                // remote -> local
                while let Ok(cmd) = rx.try_recv() {
                    match cmd {
                        ClipCmd::SetText(t) => {
                            if cb.set_text(t.clone()).is_ok() {
                                last = t;
                            }
                        }
                        ClipCmd::SetFilesDelayed => log::info!("Files were copied on the remote computer; on Linux use \"Send files\" to transfer them"),
                    }
                }
                // local -> remote (X11 has no change notification without XFixes events; poll)
                if let Ok(t) = cb.get_text() {
                    if t != last {
                        last = t.clone();
                        let hub = hub.clone();
                        std::thread::spawn(move || hub.local_text_changed(t));
                    }
                }
                std::thread::sleep(Duration::from_millis(400));
            }
        })
        .ok();
}
