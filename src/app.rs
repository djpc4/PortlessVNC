//! Shared application core: config, server, VPN, hub, sessions.

use crate::audio::AudioHub;
use crate::config::Config;
use crate::hub::Hub;
use crate::server::Server;
use crate::viewer::Session;
use crate::vpn::VpnManager;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

pub struct Core {
    pub dir: PathBuf,
    pub cfg: Arc<RwLock<Config>>,
    pub hub: Arc<Hub>,
    pub audio: Arc<AudioHub>,
    pub server: Arc<Server>,
    pub vpn: Arc<VpnManager>,
    pub sessions: Mutex<Vec<Arc<Session>>>,
    /// Guest VPNs (by profile name), separate from the home VPN above.
    pub guests: Mutex<HashMap<String, Arc<VpnManager>>>,
}

impl Core {
    pub fn new() -> anyhow::Result<Arc<Core>> {
        let dir = crate::config::config_dir();
        std::fs::create_dir_all(&dir)?;
        let cfg = Config::load(&dir);
        let _ = cfg.save(&dir);
        let download = PathBuf::from(&cfg.download_dir);
        let cfg = Arc::new(RwLock::new(cfg));
        let hub = Hub::new(download);
        let audio = AudioHub::new();
        *audio.source.lock() = Some(cfg.read().server.audio_source.clone());
        let identity = crate::tls::load_or_create_identity(&dir)?;
        let server = Server::new(cfg.clone(), hub.clone(), audio.clone(), identity)?;
        let vpn = VpnManager::new(cfg.clone(), server.clone());
        Ok(Arc::new(Core { dir, cfg, hub, audio, server, vpn, sessions: Mutex::new(Vec::new()), guests: Mutex::new(HashMap::new()) }))
    }

    /// The connection for a guest VPN (it starts disconnected).
    #[allow(dead_code)] // desktop window only
    pub fn guest_vpn(&self, name: &str) -> Arc<VpnManager> {
        self.guests.lock().entry(name.to_string()).or_insert_with(|| VpnManager::new_guest(self.cfg.clone(), self.server.clone())).clone()
    }

    pub fn save_config(&self) {
        let c = self.cfg.read().clone();
        if let Err(e) = c.save(&self.dir) {
            log::warn!("Could not save settings: {e}");
        }
        *self.hub.download_dir.write() = PathBuf::from(&c.download_dir);
        *self.audio.source.lock() = Some(c.server.audio_source.clone());
    }
}
