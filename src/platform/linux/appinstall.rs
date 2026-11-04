//! Per-user install on Linux: ~/.local/bin/portlessvnc plus a menu entry
//! (~/.local/share/applications/portlessvnc.desktop). No root needed.

use std::path::PathBuf;

pub fn app_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".local").join("bin")
}

pub fn installed_exe() -> PathBuf {
    app_dir().join("portlessvnc")
}

fn desktop_file() -> PathBuf {
    dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("applications").join("portlessvnc.desktop")
}

pub fn is_installed() -> bool {
    installed_exe().exists()
}

pub fn running_installed() -> bool {
    std::env::current_exe().map(|e| e == installed_exe()).unwrap_or(false)
}

/// `--install-app`
pub fn install() -> i32 {
    let target = installed_exe();
    let res = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(app_dir())?;
        let me = std::env::current_exe()?;
        if me != target {
            // replace atomically so a running copy keeps working
            let tmp = target.with_extension("new");
            std::fs::copy(&me, &tmp)?;
            std::fs::rename(&tmp, &target)?;
        }
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
        }
        let df = desktop_file();
        std::fs::create_dir_all(df.parent().unwrap())?;
        std::fs::write(
            &df,
            format!(
                "[Desktop Entry]\nType=Application\nName=PortlessVNC\nComment=Remote access over your VPN, no port forwarding\nExec=\"{}\"\nIcon=preferences-desktop-remote-desktop\nTerminal=false\nCategories=Network;RemoteAccess;\n",
                target.display()
            ),
        )?;
        Ok(())
    })();
    match res {
        Ok(()) => {
            log::info!("Installed to {} (menu entry added)", target.display());
            if std::env::current_exe().map(|e| e != target).unwrap_or(true) {
                let _ = std::process::Command::new(&target).spawn();
            }
            0
        }
        Err(e) => {
            log::warn!("Install failed: {e}");
            1
        }
    }
}

/// `--uninstall-app` (keeps settings in ~/.config/PortlessVNC)
pub fn uninstall() -> i32 {
    let _ = std::fs::remove_file(desktop_file());
    let _ = crate::platform::set_autostart(false);
    let _ = std::fs::remove_file(installed_exe());
    log::info!("PortlessVNC was uninstalled (settings kept in {})", crate::config::user_config_dir().display());
    0
}
