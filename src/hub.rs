//! The hub connects every live session (inbound server clients and outbound
//! viewer sessions) with clipboard sync and file transfer.

use crate::ext::{self, OfferEntry};
use crate::rfb::{Cur, PutExt};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

/// Anything we can talk to: a client connected to our server, or a server we
/// are viewing.
pub trait Peer: Send + Sync {
    fn id(&self) -> u64;
    fn label(&self) -> String;
    /// True once both sides negotiated the PortlessVNC extension.
    fn is_native(&self) -> bool;
    fn send_ext(&self, sub: u8, payload: &[u8]) -> std::io::Result<()>;
    /// Send clipboard text (extension for native peers, standard cut-text otherwise).
    fn send_clip_text(&self, text: &str);
    fn clipboard_enabled(&self) -> bool;
    fn files_enabled(&self) -> bool;
}

static NEXT_PEER_ID: AtomicU64 = AtomicU64::new(1);
pub fn new_peer_id() -> u64 {
    NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    Upload,
    Download,
}

#[derive(Clone, Debug, PartialEq)]
pub enum XferState {
    Running,
    Done,
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct TransferInfo {
    pub key: (u64, u32),
    pub name: String,
    pub peer: String,
    pub direction: Direction,
    pub total: u64,
    pub done: u64,
    pub state: XferState,
    pub started: Instant,
}

struct Incoming {
    file: Option<File>,
    path: PathBuf,
    written: u64,
    done_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
}

struct LocalOffer {
    peer_filter: Option<u64>,
    entries: Vec<(PathBuf, OfferEntry)>,
}

struct RemoteOffer {
    peer: Weak<dyn Peer>,
    offer_id: u32,
    entries: Vec<OfferEntry>,
}

pub enum ClipCmd {
    SetText(String),
    SetFilesDelayed,
}

pub struct Hub {
    peers: Mutex<Vec<Weak<dyn Peer>>>,
    clip_tx: Mutex<Option<Box<dyn Fn(ClipCmd) + Send + Sync>>>,
    last_remote_text: Mutex<String>,
    next_offer: AtomicU32,
    next_xfer: AtomicU32,
    local_offers: Mutex<HashMap<u32, LocalOffer>>,
    remote_offer: Mutex<Option<RemoteOffer>>,
    incoming: Mutex<HashMap<(u64, u32), Incoming>>,
    cancels: Mutex<HashMap<(u64, u32), Arc<AtomicBool>>>,
    pub transfers: Mutex<Vec<TransferInfo>>,
    pub download_dir: RwLock<PathBuf>,
    note: Mutex<Note>,
    /// UI: is the shared-text window open (toggled from any window)
    pub note_window: AtomicBool,
}

#[derive(Default)]
struct Note {
    text: String,
    version: u64,
    unread: bool,
}

impl Hub {
    pub fn new(download_dir: PathBuf) -> Arc<Hub> {
        Arc::new(Hub {
            peers: Mutex::new(Vec::new()),
            clip_tx: Mutex::new(None),
            last_remote_text: Mutex::new(String::new()),
            next_offer: AtomicU32::new(1),
            next_xfer: AtomicU32::new(1),
            local_offers: Mutex::new(HashMap::new()),
            remote_offer: Mutex::new(None),
            incoming: Mutex::new(HashMap::new()),
            cancels: Mutex::new(HashMap::new()),
            transfers: Mutex::new(Vec::new()),
            download_dir: RwLock::new(download_dir),
            note: Mutex::new(Note::default()),
            note_window: AtomicBool::new(false),
        })
    }

    pub fn set_clipboard_backend(&self, f: Box<dyn Fn(ClipCmd) + Send + Sync>) {
        *self.clip_tx.lock() = Some(f);
    }

    fn clip_cmd(&self, c: ClipCmd) {
        if let Some(f) = self.clip_tx.lock().as_ref() {
            f(c)
        }
    }

    pub fn register(&self, p: &Arc<dyn Peer>) {
        let mut v = self.peers.lock();
        v.retain(|w| w.strong_count() > 0);
        v.push(Arc::downgrade(p));
    }

    pub fn unregister(&self, id: u64) {
        self.peers.lock().retain(|w| w.upgrade().map(|p| p.id() != id).unwrap_or(false));
        // fail any transfers belonging to this peer
        let keys: Vec<_> = self.incoming.lock().keys().filter(|k| k.0 == id).cloned().collect();
        for k in keys {
            self.finish_incoming(k, Err("connection closed".into()));
        }
    }

    fn live_peers(&self) -> Vec<Arc<dyn Peer>> {
        self.peers.lock().iter().filter_map(|w| w.upgrade()).collect()
    }

    // ---- shared notepad ----------------------------------------------------

    pub fn note_text(&self) -> String {
        self.note.lock().text.clone()
    }

    pub fn note_unread(&self) -> bool {
        self.note.lock().unread
    }

    pub fn note_mark_read(&self) {
        self.note.lock().unread = false;
    }

    fn note_payload(n: &Note) -> Vec<u8> {
        let mut p = Vec::with_capacity(n.text.len() + 8);
        p.put_u64(n.version);
        p.extend_from_slice(n.text.as_bytes());
        p
    }

    fn note_broadcast(&self, payload: &[u8], except: Option<u64>) {
        for p in self.live_peers() {
            if p.is_native() && Some(p.id()) != except {
                let _ = p.send_ext(ext::NOTE_TEXT, payload);
            }
        }
    }

    /// The local user edited the notepad.
    pub fn note_local_edit(&self, text: String) {
        let payload = {
            let mut n = self.note.lock();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
            n.version = now.max(n.version + 1);
            n.text = text;
            n.unread = false;
            Self::note_payload(&n)
        };
        self.note_broadcast(&payload, None);
    }

    /// (version, text) of the shared text, for the service bridge.
    pub fn note_snapshot(&self) -> (u64, String) {
        let n = self.note.lock();
        (n.version, n.text.clone())
    }

    /// Apply shared text coming from the background service (this window is
    /// not itself connected to the service's viewers, so no rebroadcast).
    pub fn note_from_service(&self, version: u64, text: String) {
        let mut n = self.note.lock();
        if version <= n.version && n.text == text {
            return;
        }
        n.unread = n.text != text;
        if n.unread {
            self.note_window.store(true, Ordering::Relaxed);
        }
        n.version = n.version.max(version);
        n.text = text;
        drop(n);
        crate::util::request_repaint();
    }

    /// A peer just negotiated the extension: share our notepad if we have one.
    pub fn note_sync_peer(&self, peer: &Arc<dyn Peer>) {
        let payload = {
            let n = self.note.lock();
            if n.version == 0 {
                return;
            }
            Self::note_payload(&n)
        };
        let _ = peer.send_ext(ext::NOTE_TEXT, &payload);
    }

    fn note_remote(&self, from: u64, version: u64, text: String) {
        let payload = {
            let mut n = self.note.lock();
            if version <= n.version {
                return;
            }
            n.version = version;
            n.unread = n.text != text;
            if n.unread {
                self.note_window.store(true, Ordering::Relaxed); // pop it open for the user
            }
            n.text = text;
            Self::note_payload(&n)
        };
        // a host relays to its other viewers so everyone shares one pad
        self.note_broadcast(&payload, Some(from));
        crate::util::request_repaint();
    }

    // ---- clipboard: local -> remote --------------------------------------

    pub fn local_text_changed(&self, text: String) {
        if *self.last_remote_text.lock() == text {
            return; // echo of what a peer just sent us
        }
        for p in self.live_peers() {
            if p.clipboard_enabled() {
                p.send_clip_text(&text);
            }
        }
    }

    pub fn local_files_changed(&self, paths: Vec<PathBuf>) {
        let peers: Vec<_> = self.live_peers().into_iter().filter(|p| p.is_native() && p.files_enabled() && p.clipboard_enabled()).collect();
        if peers.is_empty() {
            return;
        }
        let entries = collect_entries(&paths);
        if entries.is_empty() {
            return;
        }
        let id = self.next_offer.fetch_add(1, Ordering::Relaxed);
        let list: Vec<OfferEntry> = entries.iter().map(|(_, e)| e.clone()).collect();
        let payload = ext::encode_offer(id, &list);
        {
            let mut offers = self.local_offers.lock();
            offers.retain(|k, _| *k + 16 > id); // keep a few recent offers
            offers.insert(id, LocalOffer { peer_filter: None, entries });
        }
        for p in peers {
            let _ = p.send_ext(ext::FILES_OFFER, &payload);
        }
        log::info!("Clipboard: offered {} file(s)/folder(s) to remote side", list.len());
    }

    // ---- clipboard: remote -> local --------------------------------------

    pub fn remote_text(&self, text: String) {
        *self.last_remote_text.lock() = text.clone();
        self.clip_cmd(ClipCmd::SetText(text));
    }

    fn remote_offer(&self, peer: &Arc<dyn Peer>, payload: &[u8]) {
        if let Ok((offer_id, entries)) = ext::decode_offer(payload) {
            log::info!("Clipboard: {} copied {} file item(s) - paste them in Explorer", peer.label(), entries.len());
            *self.remote_offer.lock() = Some(RemoteOffer { peer: Arc::downgrade(peer), offer_id, entries });
            self.clip_cmd(ClipCmd::SetFilesDelayed);
        }
    }

    /// Called from the clipboard thread when the user pastes remote files:
    /// downloads everything into a staging folder and returns the top-level
    /// paths to put on the clipboard. Blocks until done.
    pub fn render_remote_files(&self) -> Option<Vec<PathBuf>> {
        let (peer, offer_id, entries) = {
            let g = self.remote_offer.lock();
            let o = g.as_ref()?;
            (o.peer.upgrade()?, o.offer_id, o.entries.clone())
        };
        let staging = std::env::temp_dir().join("PortlessVNC").join(format!("clip-{}-{offer_id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(&staging).ok()?;
        let mut tops: Vec<PathBuf> = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            let rel = crate::util::sanitize_rel_path(&e.rel_path)?;
            let dest = staging.join(&rel);
            if let Some(first) = rel.components().next() {
                let top = staging.join(first.as_os_str());
                if !tops.contains(&top) {
                    tops.push(top);
                }
            }
            if e.is_dir {
                std::fs::create_dir_all(&dest).ok()?;
                continue;
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).ok()?;
            }
            let xfer = self.next_xfer.fetch_add(1, Ordering::Relaxed) & 0x7FFF_FFFF;
            let (tx, rx) = crossbeam_channel::bounded(1);
            let file = File::create(&dest).ok()?;
            let key = (peer.id(), xfer);
            self.incoming.lock().insert(key, Incoming { file: Some(file), path: dest.clone(), written: 0, done_tx: Some(tx) });
            self.add_transfer(key, &e.rel_path, &peer.label(), Direction::Download, e.size);
            let mut p = Vec::new();
            p.put_u32(offer_id);
            p.put_u32(i as u32);
            p.put_u32(xfer);
            if peer.send_ext(ext::FILE_REQ, &p).is_err() {
                return None;
            }
            // wait, allowing long transfers as long as data keeps flowing
            let mut last_progress = (Instant::now(), 0u64);
            loop {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(Ok(())) => break,
                    Ok(Err(e)) => {
                        log::warn!("Paste failed: {e}");
                        return None;
                    }
                    Err(_) => {
                        let done = self.transfer_done(key);
                        if done != last_progress.1 {
                            last_progress = (Instant::now(), done);
                        } else if last_progress.0.elapsed() > Duration::from_secs(30) {
                            self.finish_incoming(key, Err("timed out".into()));
                            return None;
                        }
                    }
                }
            }
        }
        Some(tops)
    }

    // ---- push transfers ("Send files...") --------------------------------

    pub fn send_paths(self: &Arc<Self>, peer: Arc<dyn Peer>, paths: Vec<PathBuf>) {
        let hub = self.clone();
        std::thread::Builder::new()
            .name("send-files".into())
            .spawn(move || {
                let entries = collect_entries(&paths);
                for (abs, e) in entries {
                    let xfer = 0x8000_0000 | (hub.next_xfer.fetch_add(1, Ordering::Relaxed) & 0x7FFF_FFFF);
                    let mut p = Vec::new();
                    p.put_u32(xfer);
                    p.put_u64(e.size);
                    p.put_u8(e.is_dir as u8);
                    p.put_str16(&e.rel_path);
                    if peer.send_ext(ext::SEND_BEGIN, &p).is_err() {
                        return;
                    }
                    if e.is_dir {
                        continue;
                    }
                    let key = (peer.id(), xfer);
                    hub.add_transfer(key, &e.rel_path, &peer.label(), Direction::Upload, e.size);
                    let res = hub.stream_file(&peer, xfer, &abs, key);
                    hub.set_state(key, match res {
                        Ok(()) => XferState::Done,
                        Err(e) => XferState::Failed(e),
                    });
                }
            })
            .ok();
    }

    fn stream_file(&self, peer: &Arc<dyn Peer>, xfer: u32, path: &Path, ui_key: (u64, u32)) -> Result<(), String> {
        let key = (peer.id(), xfer);
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancels.lock().insert(key, cancel.clone());
        let res = (|| {
            let mut f = File::open(path).map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 60 * 1024];
            let mut sent = 0u64;
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return Err("cancelled".to_string());
                }
                let n = f.read(&mut buf[4..]).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                buf[..4].copy_from_slice(&xfer.to_be_bytes());
                peer.send_ext(ext::FILE_DATA, &buf[..4 + n]).map_err(|e| e.to_string())?;
                sent += n as u64;
                self.set_progress(ui_key, sent);
            }
            peer.send_ext(ext::FILE_END, &xfer.to_be_bytes()).map_err(|e| e.to_string())?;
            Ok(())
        })();
        if let Err(e) = &res {
            let mut p = xfer.to_be_bytes().to_vec();
            p.put_str16(e);
            let _ = peer.send_ext(ext::FILE_ERR, &p);
        }
        self.cancels.lock().remove(&key);
        res
    }

    pub fn cancel_transfer(&self, key: (u64, u32)) {
        if let Some(c) = self.cancels.lock().get(&key) {
            c.store(true, Ordering::Relaxed);
        }
        if self.incoming.lock().contains_key(&key) {
            if let Some(p) = self.live_peers().into_iter().find(|p| p.id() == key.0) {
                let _ = p.send_ext(ext::CANCEL, &key.1.to_be_bytes());
            }
            self.finish_incoming(key, Err("cancelled".into()));
        }
    }

    // ---- extension message dispatch (called by connection readers) -------

    pub fn handle_ext(self: &Arc<Self>, peer: &Arc<dyn Peer>, sub: u8, payload: &[u8]) {
        let mut c = Cur::new(payload);
        match sub {
            ext::CLIP_TEXT => {
                if peer.clipboard_enabled() {
                    self.remote_text(String::from_utf8_lossy(payload).into_owned());
                }
            }
            ext::NOTE_TEXT => {
                if let Ok(v) = c.u64() {
                    let text = String::from_utf8_lossy(c.rest()).into_owned();
                    self.note_remote(peer.id(), v, text);
                }
            }
            ext::FILES_OFFER => {
                if peer.clipboard_enabled() && peer.files_enabled() {
                    self.remote_offer(peer, payload);
                }
            }
            ext::FILE_REQ => {
                let (Ok(offer), Ok(index), Ok(xfer)) = (c.u32(), c.u32(), c.u32()) else { return };
                if !peer.files_enabled() {
                    return;
                }
                let entry = self.local_offers.lock().get(&offer).and_then(|o| {
                    if o.peer_filter.map(|f| f == peer.id()).unwrap_or(true) {
                        o.entries.get(index as usize).cloned()
                    } else {
                        None
                    }
                });
                let hub = self.clone();
                let peer = peer.clone();
                std::thread::spawn(move || match entry {
                    Some((abs, e)) if !e.is_dir => {
                        let key = (peer.id(), xfer | 0x4000_0000);
                        hub.add_transfer(key, &e.rel_path, &peer.label(), Direction::Upload, e.size);
                        let r = hub.stream_file(&peer, xfer, &abs, key);
                        hub.set_state(key, if r.is_ok() { XferState::Done } else { XferState::Failed(r.unwrap_err()) });
                    }
                    _ => {
                        let mut p = xfer.to_be_bytes().to_vec();
                        p.put_str16("file no longer offered");
                        let _ = peer.send_ext(ext::FILE_ERR, &p);
                    }
                });
            }
            ext::SEND_BEGIN => {
                let (Ok(xfer), Ok(size), Ok(is_dir), Ok(rel)) = (c.u32(), c.u64(), c.u8(), c.str16()) else { return };
                if !peer.files_enabled() {
                    let mut p = xfer.to_be_bytes().to_vec();
                    p.put_str16("file transfer disabled on the receiving side");
                    let _ = peer.send_ext(ext::FILE_ERR, &p);
                    return;
                }
                let Some(relp) = crate::util::sanitize_rel_path(&rel) else { return };
                let base = self.download_dir.read().clone();
                let mut dest = base.join(&relp);
                if is_dir != 0 {
                    let _ = std::fs::create_dir_all(&dest);
                    return;
                }
                if relp.components().count() == 1 {
                    dest = crate::util::unique_path(dest);
                }
                if let Some(parent) = dest.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let key = (peer.id(), xfer);
                match File::create(&dest) {
                    Ok(f) => {
                        log::info!("Receiving {} ({}) from {}", rel, crate::util::human_bytes(size), peer.label());
                        self.incoming.lock().insert(key, Incoming { file: Some(f), path: dest, written: 0, done_tx: None });
                        self.add_transfer(key, &rel, &peer.label(), Direction::Download, size);
                    }
                    Err(e) => {
                        let mut p = xfer.to_be_bytes().to_vec();
                        p.put_str16(&e.to_string());
                        let _ = peer.send_ext(ext::FILE_ERR, &p);
                    }
                }
            }
            ext::FILE_DATA => {
                let Ok(xfer) = c.u32() else { return };
                let data = c.rest();
                let key = (peer.id(), xfer);
                let mut inc = self.incoming.lock();
                if let Some(i) = inc.get_mut(&key) {
                    if let Some(f) = i.file.as_mut() {
                        if f.write_all(data).is_err() {
                            drop(inc);
                            self.finish_incoming(key, Err("write failed".into()));
                            return;
                        }
                    }
                    i.written += data.len() as u64;
                    let w = i.written;
                    drop(inc);
                    self.set_progress(key, w);
                }
            }
            ext::FILE_END => {
                if let Ok(xfer) = c.u32() {
                    self.finish_incoming((peer.id(), xfer), Ok(()));
                }
            }
            ext::FILE_ERR => {
                if let Ok(xfer) = c.u32() {
                    let msg = c.str16().unwrap_or_default();
                    self.finish_incoming((peer.id(), xfer), Err(msg));
                }
            }
            ext::CANCEL => {
                if let Ok(xfer) = c.u32() {
                    for k in [(peer.id(), xfer), (peer.id(), xfer | 0x4000_0000)] {
                        if let Some(c) = self.cancels.lock().get(&k) {
                            c.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn finish_incoming(&self, key: (u64, u32), res: Result<(), String>) {
        let inc = self.incoming.lock().remove(&key);
        if let Some(mut i) = inc {
            if let Some(f) = i.file.take() {
                let _ = f.sync_all();
            }
            if res.is_err() {
                let _ = std::fs::remove_file(&i.path);
            } else if i.done_tx.is_none() {
                log::info!("Saved {}", i.path.display());
            }
            if let Some(tx) = i.done_tx.take() {
                let _ = tx.send(res.clone());
            }
            self.set_state(key, match res {
                Ok(()) => XferState::Done,
                Err(e) => XferState::Failed(e),
            });
        }
    }

    // ---- transfer bookkeeping for the UI ---------------------------------

    fn add_transfer(&self, key: (u64, u32), name: &str, peer: &str, direction: Direction, total: u64) {
        let mut t = self.transfers.lock();
        t.push(TransferInfo { key, name: name.to_string(), peer: peer.to_string(), direction, total, done: 0, state: XferState::Running, started: Instant::now() });
        let n = t.len();
        if n > 30 {
            // drop the oldest finished entries
            let mut removed = 0;
            t.retain(|x| {
                if removed < n - 30 && x.state != XferState::Running {
                    removed += 1;
                    false
                } else {
                    true
                }
            });
        }
        crate::util::request_repaint();
    }

    fn set_progress(&self, key: (u64, u32), done: u64) {
        if let Some(t) = self.transfers.lock().iter_mut().rev().find(|t| t.key == key) {
            t.done = done;
        }
    }

    fn transfer_done(&self, key: (u64, u32)) -> u64 {
        self.transfers.lock().iter().rev().find(|t| t.key == key).map(|t| t.done).unwrap_or(0)
    }

    fn set_state(&self, key: (u64, u32), s: XferState) {
        if let Some(t) = self.transfers.lock().iter_mut().rev().find(|t| t.key == key) {
            if t.state == XferState::Running {
                t.state = s;
            }
        }
        crate::util::request_repaint();
    }

    pub fn clear_finished(&self) {
        self.transfers.lock().retain(|t| t.state == XferState::Running);
    }
}

/// Expand files/folders into offer entries with '/'-separated relative paths.
fn collect_entries(paths: &[PathBuf]) -> Vec<(PathBuf, OfferEntry)> {
    let mut out = Vec::new();
    for p in paths {
        let Some(name) = p.file_name().map(|n| n.to_string_lossy().into_owned()) else { continue };
        walk(p, &name, &mut out);
    }
    out
}

fn walk(path: &Path, rel: &str, out: &mut Vec<(PathBuf, OfferEntry)>) {
    if out.len() > 50_000 {
        return;
    }
    let Ok(md) = std::fs::metadata(path) else { return };
    if md.is_dir() {
        out.push((path.to_path_buf(), OfferEntry { rel_path: rel.to_string(), size: 0, is_dir: true }));
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                walk(&e.path(), &format!("{rel}/{name}"), out);
            }
        }
    } else {
        out.push((path.to_path_buf(), OfferEntry { rel_path: rel.to_string(), size: md.len(), is_dir: false }));
    }
}
