//! Android client: the viewer and the built-in OpenVPN client, with a touch
//! UI. Built as libportlessvnc.so and started by MainActivity (NativeActivity).
//! On other platforms this library is empty.
#![cfg(target_os = "android")]
#![allow(dead_code)]

mod app;
mod audio;
mod config;
mod ext;
mod hub;
mod keys;
mod mobile;
mod platform;
mod rfb;
mod server;
mod servicectl;
mod tls;
mod util;
mod viewer;
mod vpn;

use android_activity::AndroidApp;

#[no_mangle]
fn android_main(app: AndroidApp) {
    // settings in the app's private storage; received files staged next to it
    let data = app.internal_data_path().unwrap_or_else(|| "/data/local/tmp/portlessvnc".into());
    mobile::crash::install(&data);
    platform::java::set_activity(app.activity_as_ptr());
    // the last run crashed: show its report instead of starting (Copy / Try again)
    if let Some(report) = mobile::crash::path().and_then(|p| std::fs::read_to_string(p).ok()) {
        if let Some(p) = mobile::crash::path() {
            let _ = std::fs::rename(p, p.with_file_name("crash-last.txt"));
        }
        platform::java::show_crash_report(&report);
        loop {
            let mut quit = false;
            app.poll_events(Some(std::time::Duration::from_millis(500)), |e| quit |= matches!(e, android_activity::PollEvent::Main(android_activity::MainEvent::Destroy)));
            if quit {
                return;
            }
        }
    }
    log::info!("start: data folder {}", data.display());
    std::env::set_var("PORTLESS_CONFIG_DIR", &data);
    let first_run = !data.join("config.json").exists();
    log::info!("start: creating core");
    let core = match app::Core::new() {
        Ok(c) => c,
        Err(e) => {
            log::error!("startup failed: {e:#}");
            mobile::crash::write_report(&format!("startup failed: {e:#}"));
            return;
        }
    };
    {
        let mut c = core.cfg.write();
        let staging = app.external_data_path().unwrap_or_else(|| data.clone()).join("incoming");
        c.download_dir = staging.to_string_lossy().into_owned();
        c.server.enabled = false; // client only
        if first_run {
            c.viewer.audio = config::AudioMode::Off; // opt-in on phones (data use)
        }
    }
    core.save_config();
    log::info!("PortlessVNC {} (Android client) started", env!("CARGO_PKG_VERSION"));

    log::info!("start: opening the window (wgpu)");
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Wgpu,
        event_loop_builder: Some(Box::new(move |b| {
            use winit::platform::android::EventLoopBuilderExtAndroid;
            b.with_android_app(app);
        })),
        ..Default::default()
    };
    if let Err(e) = eframe::run_native("PortlessVNC", options, Box::new(move |cc| {
        log::info!("start: window ready, building the UI");
        Ok(Box::new(mobile::MobileApp::new(cc, core)))
    })) {
        log::error!("could not start the UI: {e}");
        mobile::crash::write_report(&format!("could not start the UI: {e}"));
    }
}
