//! Host -> viewer audio.
//!
//! Host: system output is captured with WASAPI loopback (via cpal, no driver,
//! no admin), resampled to 48 kHz stereo and cut into 20 ms frames. Every
//! viewer gets its own Opus encoder so each can run at its own bitrate
//! (fixed, or adapted to the connection by the server's quality controller).
//!
//! Viewer: Opus decode -> small jitter buffer -> default output device.

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const RATE: u32 = 48_000;
pub const FRAME: usize = 960; // 20 ms @ 48 kHz
pub type PcmFrame = Arc<Vec<f32>>; // interleaved stereo, FRAME*2 samples

/// Streaming linear resampler for interleaved stereo.
struct Resampler {
    step: f64,
    pos: f64,
    prev: [f32; 2],
}

impl Resampler {
    fn new(from: u32, to: u32) -> Self {
        Resampler { step: from as f64 / to as f64, pos: 0.0, prev: [0.0; 2] }
    }
    fn process(&mut self, input: &[f32], out: &mut Vec<f32>) {
        if (self.step - 1.0).abs() < 1e-9 {
            out.extend_from_slice(input);
            return;
        }
        let frames = input.len() / 2;
        let get = |i: isize, c: usize, prev: &[f32; 2]| -> f32 {
            if i < 0 { prev[c] } else { input[i as usize * 2 + c] }
        };
        while self.pos < frames as f64 {
            let i = self.pos.floor() as isize;
            let t = (self.pos - i as f64) as f32;
            for c in 0..2 {
                let a = get(i - 1, c, &self.prev);
                let b = get(i, c, &self.prev);
                out.push(a + (b - a) * t);
            }
            self.pos += self.step;
        }
        self.pos -= frames as f64;
        if frames > 0 {
            self.prev = [input[(frames - 1) * 2], input[(frames - 1) * 2 + 1]];
        }
    }
}

fn to_stereo(data: &[f32], channels: usize, out: &mut Vec<f32>) {
    match channels {
        0 => {}
        1 => {
            for &s in data {
                out.push(s);
                out.push(s);
            }
        }
        _ => {
            for f in data.chunks(channels) {
                out.push(f[0]);
                out.push(f[1]);
            }
        }
    }
}

// ---- capture (host side) ---------------------------------------------------

pub struct AudioHub {
    subs: Mutex<Vec<(Sender<PcmFrame>, std::sync::Weak<()>)>>,
    running: AtomicBool,
    /// Linux: PulseAudio/PipeWire source to record (None = default output's monitor)
    pub source: Mutex<Option<String>>,
}

impl AudioHub {
    pub fn new() -> Arc<AudioHub> {
        Arc::new(AudioHub { subs: Mutex::new(Vec::new()), running: AtomicBool::new(false), source: Mutex::new(None) })
    }

    /// Subscribe to 20 ms PCM frames; capture runs while any subscription lives.
    pub fn subscribe(self: &Arc<Self>) -> AudioSub {
        let (tx, rx) = bounded(25);
        let guard = Arc::new(());
        self.subs.lock().push((tx, Arc::downgrade(&guard)));
        if !self.running.swap(true, Ordering::SeqCst) {
            let hub = self.clone();
            std::thread::Builder::new().name("audio-capture".into()).spawn(move || hub.capture_loop()).ok();
        }
        AudioSub { rx, _guard: guard }
    }

    fn broadcast(&self, f: PcmFrame) {
        self.subs.lock().retain(|(s, g)| g.strong_count() > 0 && match s.try_send(f.clone()) {
            Ok(()) | Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Disconnected(_)) => false,
        });
    }

    fn has_subs(&self) -> bool {
        let mut s = self.subs.lock();
        s.retain(|(_, g)| g.strong_count() > 0);
        !s.is_empty()
    }

    fn capture_loop(self: Arc<Self>) {
        log::info!("Audio capture starting (system output loopback)");
        while self.has_subs() {
            match self.run_stream() {
                Ok(()) => {}
                Err(e) => {
                    log::warn!("Audio capture error: {e}; retrying");
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }
        self.running.store(false, Ordering::SeqCst);
        // a subscriber may have raced in after we decided to stop
        if self.has_subs() && !self.running.swap(true, Ordering::SeqCst) {
            let hub = self.clone();
            std::thread::spawn(move || hub.capture_loop());
        } else {
            log::info!("Audio capture stopped");
        }
    }

    /// Linux: record the default output's *monitor* source through PulseAudio /
    /// PipeWire (pipewire-pulse) with `parec` - already 48 kHz stereo float.
    #[cfg(target_os = "linux")]
    fn run_stream(self: &Arc<Self>) -> anyhow::Result<()> {
        use std::io::Read;
        let device = format!("--device={}", self.source.lock().clone().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "@DEFAULT_MONITOR@".into()));
        let parec_args = [device.as_str(), "--format=float32le", "--rate=48000", "--channels=2", "--raw", "--latency-msec=20"];
        // as a root service, record from the signed-in user's sound server
        let mut cmd = match (std::env::var("PVNC_SESSION_USER"), std::env::var("PVNC_SESSION_UID")) {
            (Ok(user), Ok(uid)) if unsafe { libc::geteuid() } == 0 => {
                let mut c = std::process::Command::new("runuser");
                c.args(["-u", &user, "--", "env", &format!("XDG_RUNTIME_DIR=/run/user/{uid}"), "parec"]).args(parec_args);
                c
            }
            _ => {
                let mut c = std::process::Command::new("parec");
                c.args(parec_args);
                c
            }
        };
        let mut child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| anyhow::anyhow!("cannot run parec ({e}); install pulseaudio-utils (or pipewire-pulse) to share audio"))?;
        let mut out = child.stdout.take().ok_or_else(|| anyhow::anyhow!("parec has no output"))?;
        let mut buf = vec![0u8; FRAME * 2 * 4];
        let res = (|| -> anyhow::Result<()> {
            while self.has_subs() {
                out.read_exact(&mut buf)?;
                let frame: Vec<f32> = buf.chunks_exact(4).map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]])).collect();
                self.broadcast(Arc::new(frame));
            }
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        res
    }

    #[cfg(not(target_os = "linux"))]
    fn run_stream(self: &Arc<Self>) -> anyhow::Result<()> {
        let host = cpal::default_host();
        let dev = host.default_output_device().ok_or_else(|| anyhow::anyhow!("no output device"))?;
        let cfg = dev.default_output_config()?;
        let channels = cfg.channels() as usize;
        let rate = cfg.sample_rate().0;
        let failed = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new((Resampler::new(rate, RATE), Vec::<f32>::with_capacity(FRAME * 4), Vec::<f32>::new())));
        let hub = self.clone();
        let st = state.clone();
        let mut handle = move |data: &[f32]| {
            let mut g = st.lock();
            let (rs, acc, tmp) = &mut *g;
            tmp.clear();
            to_stereo(data, channels, tmp);
            rs.process(tmp, acc);
            while acc.len() >= FRAME * 2 {
                let frame: Vec<f32> = acc.drain(..FRAME * 2).collect();
                hub.broadcast(Arc::new(frame));
            }
        };
        let f2 = failed.clone();
        let err_fn = move |e: cpal::StreamError| {
            log::debug!("audio stream error: {e}");
            f2.store(true, Ordering::SeqCst);
        };
        let scfg: cpal::StreamConfig = cfg.config();
        let stream = match cfg.sample_format() {
            cpal::SampleFormat::F32 => dev.build_input_stream(&scfg, move |d: &[f32], _: &_| handle(d), err_fn, None)?,
            cpal::SampleFormat::I16 => {
                let mut buf = Vec::new();
                dev.build_input_stream(
                    &scfg,
                    move |d: &[i16], _: &_| {
                        buf.clear();
                        buf.extend(d.iter().map(|&s| s as f32 / 32768.0));
                        handle(&buf)
                    },
                    err_fn,
                    None,
                )?
            }
            cpal::SampleFormat::I32 => {
                let mut buf = Vec::new();
                dev.build_input_stream(
                    &scfg,
                    move |d: &[i32], _: &_| {
                        buf.clear();
                        buf.extend(d.iter().map(|&s| s as f32 / 2147483648.0));
                        handle(&buf)
                    },
                    err_fn,
                    None,
                )?
            }
            f => anyhow::bail!("unsupported sample format {f:?}"),
        };
        stream.play()?;
        // WASAPI loopback delivers nothing while the device is silent; feed
        // silence-free gaps implicitly (viewers treat gaps as silence).
        while self.has_subs() && !failed.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(250));
        }
        drop(stream);
        Ok(())
    }
}

pub struct AudioSub {
    pub rx: Receiver<PcmFrame>,
    _guard: Arc<()>,
}

/// Per-viewer Opus encoder.
pub struct Encoder {
    enc: opus::Encoder,
    bitrate: u32,
    silent_frames: u32,
}

impl Encoder {
    pub fn new(bitrate: u32) -> anyhow::Result<Self> {
        let mut enc = opus::Encoder::new(RATE, opus::Channels::Stereo, opus::Application::Audio)?;
        enc.set_bitrate(opus::Bitrate::Bits(bitrate as i32))?;
        Ok(Encoder { enc, bitrate, silent_frames: 0 })
    }
    pub fn set_bitrate(&mut self, b: u32) {
        if b != self.bitrate {
            if self.enc.set_bitrate(opus::Bitrate::Bits(b as i32)).is_ok() {
                self.bitrate = b;
            }
        }
    }
    pub fn bitrate(&self) -> u32 {
        self.bitrate
    }
    /// Encode one 20 ms frame. Returns None for (sustained) silence.
    pub fn encode(&mut self, pcm: &[f32]) -> Option<Vec<u8>> {
        let silent = pcm.iter().all(|s| s.abs() < 1e-4);
        if silent {
            self.silent_frames += 1;
            if self.silent_frames > 5 {
                return None;
            }
        } else {
            self.silent_frames = 0;
        }
        self.enc.encode_vec_float(pcm, 4000).ok()
    }
}

// ---- playback (viewer side) ----------------------------------------------

pub struct Player {
    tx: Sender<Vec<u8>>,
}

impl Player {
    pub fn start() -> Player {
        let (tx, rx) = bounded::<Vec<u8>>(100);
        std::thread::Builder::new()
            .name("audio-play".into())
            .spawn(move || {
                if let Err(e) = play_loop(rx) {
                    log::warn!("Audio playback unavailable: {e}");
                }
            })
            .ok();
        Player { tx }
    }
    pub fn push(&self, opus_packet: Vec<u8>) {
        let _ = self.tx.try_send(opus_packet);
    }
}

fn play_loop(rx: Receiver<Vec<u8>>) -> anyhow::Result<()> {
    let host = cpal::default_host();
    let dev = host.default_output_device().ok_or_else(|| anyhow::anyhow!("no output device"))?;
    let cfg = dev.default_output_config()?;
    let out_ch = cfg.channels() as usize;
    let out_rate = cfg.sample_rate().0;
    let ring: Arc<Mutex<VecDeque<f32>>> = Arc::new(Mutex::new(VecDeque::with_capacity(out_rate as usize)));
    let primed = Arc::new(AtomicBool::new(false));
    let target = (out_rate as usize * 2) * 60 / 1000; // ~60 ms of stereo samples
    let r2 = ring.clone();
    let p2 = primed.clone();
    let fill = move |out: &mut [f32]| {
        let mut q = r2.lock();
        if !p2.load(Ordering::Relaxed) {
            if q.len() >= target {
                p2.store(true, Ordering::Relaxed);
            } else {
                out.fill(0.0);
                return;
            }
        }
        for f in out.chunks_mut(out_ch) {
            let (l, r) = match (q.pop_front(), q.pop_front()) {
                (Some(l), Some(r)) => (l, r),
                _ => {
                    p2.store(false, Ordering::Relaxed); // underrun: re-buffer
                    (0.0, 0.0)
                }
            };
            match out_ch {
                1 => f[0] = (l + r) * 0.5,
                _ => {
                    f[0] = l;
                    f[1] = r;
                    for x in f.iter_mut().skip(2) {
                        *x = 0.0;
                    }
                }
            }
        }
    };
    let scfg: cpal::StreamConfig = cfg.config();
    let err_fn = |e: cpal::StreamError| log::debug!("audio out error: {e}");
    let stream = match cfg.sample_format() {
        cpal::SampleFormat::F32 => {
            let mut fill = fill;
            dev.build_output_stream(&scfg, move |d: &mut [f32], _: &_| fill(d), err_fn, None)?
        }
        cpal::SampleFormat::I16 => {
            let mut fill = fill;
            let mut buf = Vec::new();
            dev.build_output_stream(
                &scfg,
                move |d: &mut [i16], _: &_| {
                    buf.resize(d.len(), 0.0);
                    fill(&mut buf);
                    for (o, s) in d.iter_mut().zip(&buf) {
                        *o = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
                    }
                },
                err_fn,
                None,
            )?
        }
        f => anyhow::bail!("unsupported output format {f:?}"),
    };
    stream.play()?;
    let mut dec = opus::Decoder::new(RATE, opus::Channels::Stereo)?;
    let mut rs = Resampler::new(RATE, out_rate);
    let mut pcm = vec![0f32; FRAME * 2 * 6];
    let mut res = Vec::with_capacity(FRAME * 4);
    let max_buffer = (out_rate as usize * 2) * 250 / 1000; // cap latency at ~250 ms
    for pkt in rx {
        let n = match dec.decode_float(&pkt, &mut pcm, false) {
            Ok(n) => n,
            Err(_) => continue,
        };
        res.clear();
        rs.process(&pcm[..n * 2], &mut res);
        let mut q = ring.lock();
        q.extend(res.iter().copied());
        while q.len() > max_buffer {
            q.pop_front();
        }
    }
    drop(stream);
    Ok(())
}
