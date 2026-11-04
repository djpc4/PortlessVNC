# PortlessVNC

A single program that is both a **VNC server** (share this computer) and a **VNC
viewer** (control others), with a **built-in OpenVPN client** so machines on the
same VPN can reach each other **without port forwarding**. No drivers, no admin
rights, nothing to install: one file.

| Platform | What |
|----------|------|
| Windows 10/11 (x64) | Server + viewer, optional background service with tray icon |
| Windows 7 / 8 / 8.1 (x64) | Same program, built for Windows 7 (`-win7.exe`); works even on very old graphics (below) |
| Linux x86_64, X11 (Ubuntu 20.04+ / Debian 11+ / Mint 20+) | Server + viewer, optional root service with tray icon |
| Android 8+ (arm64) | Viewer only: saved computers grouped by VPN, touch controls |

## How the "port-forwardless" part works

1. Import a normal `.ovpn` profile (pfSense / OPNsense / OpenVPN server exports
   work; inline `<ca>/<cert>/<key>/<tls-auth>` profiles are easiest).
2. Click **Connect VPN**. The app logs in (asking for username/password and
   OTP/challenge if the profile needs them) and gets a VPN address, shown large
   in the green **VPN ADDRESS** card.
3. Anyone else on that VPN connects to that address. The VPN server must let
   clients reach each other: `client-to-client` (standalone OpenVPN), or
   "Inter-client communication" / an allow rule on the OpenVPN interface
   (pfSense/OPNsense). Hosts on the VPN server's LAN can reach it too.

There is no virtual network adapter: the app runs its own small TCP/IP stack
(smoltcp) on the VPN address, so only PortlessVNC traffic uses the tunnel and
the rest of the PC's networking is untouched. This also means Windows Firewall
does not block connections arriving through the VPN.

Direct (LAN / public IP) addresses are listed below the VPN card, as in any VNC
server. Those may need port forwarding and a Windows Firewall rule.

## Background service (optional)

Settings -> Background service -> **Install as a service** (admin, once). The
service starts with Windows, keeps its own VPN connected and allows control of
the sign-in screen, UAC prompts and lock screen. A tray icon shows its status.

The service has its **own** settings (in `C:\ProgramData\PortlessVNC`,
SYSTEM/Administrators only), separate from the normal window's: its VPN
profile, username and (optionally saved, machine-encrypted) password are set on
the service card in the main window and are what it uses at every boot.
Reinstalling/updating keeps them. Note: any user signed in on the computer can
change the service's VPN profile/login from that card.

## Compatibility

| Peer | What works |
|------|-----------|
| PortlessVNC <-> PortlessVNC | TLS (fingerprint check on first connect), Tight+JPEG with adaptive quality, audio, UTF-8 clipboard, file copy/paste, send files |
| Standard viewers (TigerVNC, RealVNC, UltraVNC, TightVNC, noVNC...) -> PortlessVNC | Screen, keyboard, mouse, text clipboard; Tight / ZRLE / Hextile / Raw; VNC password or VeNCrypt TLS |
| PortlessVNC -> standard servers | Same as above. RealVNC servers need "VNC password" auth (its proprietary encryption is not supported) |

## Features

* **Video**: DXGI desktop duplication (GDI fallback for RDP/VMs/"all
  monitors"), tile-based change detection, Tight (JPEG/palette/zlib), ZRLE,
  Hextile, Raw. Local cursor rendering. Quality: Auto (adapts to the link),
  High, Medium, Low, Lossless.
* **Audio** (host -> viewer): system output via WASAPI loopback (polled on Windows before 10), Opus at 20 ms
  frames. Off / Auto (adapts to the link) / 32 / 64 / 96 / 128 kbps, per viewer.
* **Clipboard**: text both ways. Files: copy in Explorer on one side, paste in
  Explorer on the other (downloaded when you paste). Plus "Send files..." in
  both directions; received files go to the folder set in Settings (default
  `Downloads\PortlessVNC`).
* **Keyboard**: normal typing is sent while the session window is focused; a
  **Keys** menu sends Ctrl+Alt+Del, Ctrl+Shift+Esc, Alt+Tab, Alt+F4, Win
  combos and PrintScreen.
* **Shared text**: a pop-out window both sides can type/paste into (a fallback
  for the clipboard, or a quick chat). Opens by itself when the other side
  writes.
* **Address box**: grey autocomplete, Tab accepts. Without a dot it offers
  recent/address-book entries; after a dot it offers the VPN network prefix,
  then the LAN one (e.g. `10.8.0.x`).
* **Auth**: a **one-time password** (on by default, TeamViewer/RustDesk style:
  shown next to the VPN address, works for one login, then changes), plus an
  optional permanent VNC password (8 chars max, like every VNC server), or
  Windows-account login (TLS only), or none. Either password can be switched
  off. Brute-force lockout after 5 failures/minute.

## VPN client support

UDP and TCP, HTTP/SOCKS proxy (TCP), certificate and/or username+password,
static-challenge (OTP) and dynamic CRV1 challenges, `tls-auth` (with
key-direction), `tls-crypt`, `tls-crypt-v2`, AES-128/256-GCM,
CHACHA20-POLY1305, AES-128/192/256-CBC with SHA1/256/384/512, TLS key export
(OpenVPN 2.6) and the legacy PRF, DATA_V2/peer-id, `verify-x509-name`,
`remote-cert-tls`, keepalive, renegotiation, auth-token, reconnect with backoff.

Not supported (the app shows a clear error): PKCS#12 / smartcard / Windows cert
store keys, password-protected private keys, `dev tap`, static-key mode, and
actually compressed packets (framing-only `compress`/`comp-lzo no` is fine).

## Android client

Opens to **My computers**: computers that share a VPN are grouped under it (the
heading shows this phone's VPN address, for firewall rules); tap one to bring up
its VPN and connect. **New connection** / **Edit** open a setup page per computer:
address, optional saved password, VPN profile (import `.ovpn`, login saved per
profile), sound, quality, touch style, rotation, nickname. Nothing connects at
start. In a session a tab at the top offers Rotate, Mouse / Keyboard / View,
Mute and More (key combos, quality, shared text, disconnect); a Left/Right
mouse-button bar can be hidden; Back disconnects. Sound is off by default.

## Linux

X11 sessions (Wayland is not supported yet). Capture via MIT-SHM, input via
XTest, text clipboard, audio from `parec` (the capture source is configurable).
The optional root service follows the active X display (including the login
screen) and has a tray icon (StatusNotifier: Cinnamon, KDE, XFCE, MATE; GNOME
needs the AppIndicator extension).

## Old graphics

The window normally draws through Direct3D 12, Vulkan or OpenGL. On a machine with
none of those and OpenGL below 2.0 (Intel 945 and similar) it automatically draws
with the CPU instead, at up to about 30 frames per second. A session then fills the
main window rather than opening its own; disconnect to return. Start with
`--software-render` to force this mode anywhere.

## Antivirus warnings

The programs are not code-signed, and remote-control tools inject input and hook the
keyboard, so security software may flag them: an earlier Windows 7 build was flagged by
Windows Defender's machine-learning detection (`Bearfoos.A!ml`). Only download from this
repository's Releases page, or build from source. False positives can be reported at
https://www.microsoft.com/wdsi/filesubmission.

## Known limits

* Without the service, Windows blocks control of UAC prompts, the sign-in
  screen and elevated windows (install the service for those).
* Pasting a very large copied folder blocks Explorer's paste until downloaded.
* File copy/paste between clipboards is Windows-only; elsewhere use Send files.
* The main Windows build needs 10/11; use the `-win7.exe` on 7 / 8 / 8.1. An XP (32-bit) build is planned.

## Command line

```
PortlessVNC.exe [--minimized] [--host-only] [--connect ADDRESS] [--software-render]
PortlessVNC.exe --selftest                      # loopback end-to-end test
PortlessVNC.exe --vpntest profile.ovpn          # VPN test (PVNC_VPN_USER/PVNC_VPN_PASS)
PortlessVNC.exe --vpnpair profile.ovpn          # two instances on the VPN, A views B
PortlessVNC.exe --remote ADDRESS out.bmp [ops]  # troubleshooting: drive a VNC server (see tools/remote.ps1)
```

Addresses: `host` (port 5900), `host:1` (display 1 = 5901), `host::5901` (port).

Settings live in `%APPDATA%\PortlessVNC`. Put an empty `portable.txt` next to
the exe to keep them in `PortlessVNC-data` beside it instead.

## Building

All builds run on Windows with a per-user GNU Rust toolchain (no admin):

| Script | Needs | Output |
|--------|-------|--------|
| `build.ps1` | portable WinLibs MinGW (CMake, Ninja) | Windows `.exe` |
| `build-win7.ps1` | nightly Rust + `rust-src`, WinLibs MinGW (MSVCRT edition) | Windows 7+ `-win7.exe` |
| `build-linux.ps1` | `cargo-zigbuild` + zig, Debian ALSA/Opus dev libs | Linux binary |
| `build-android.ps1` | JDK 17, Android SDK (platform 34, build-tools 34), NDK 27 | signed `.apk` |

```
powershell -ExecutionPolicy Bypass -File build.ps1
```

Builds go to `%USERPROFILE%\pvnc-target` (kept short because libopus' CMake
build fails on long paths); the scripts copy the results to `dist\`.

The Android script needs no Gradle: Rust builds `libportlessvnc.so`, `javac` +
`d8` compile the small Java helper (`android/`), and `aapt2` / `zipalign` /
`apksigner` package it. On first use it creates a signing key in
`%USERPROFILE%\toolchains` - keep that key private and backed up, since Android
only installs updates signed with the same key.

`vendor/winit` is winit 0.30.13 with one line changed so Android's Back button
reaches the app.

## Source map

| Path | What |
|------|------|
| `src/rfb/` | RFB protocol, encoders (server), decoders (viewer), VNC auth |
| `src/server/` | listener, capture service, per-client handshake/update loop, adaptive quality |
| `src/viewer.rs` | viewer session (handshake, decoding, input) |
| `src/ext.rs`, `src/hub.rs` | PortlessVNC extension messages, clipboard + file transfer |
| `src/audio.rs` | loopback capture, Opus, jitter-buffered playback |
| `src/vpn/` | OpenVPN client: `.ovpn` parser, crypto, protocol engine, userspace netstack |
| `src/platform/win/` | DXGI/GDI capture, SendInput, keyboard hook, clipboard, DPAPI, service, tray |
| `src/platform/linux/` | X11 capture/input, clipboard, systemd service, tray |
| `src/platform/android/`, `android/` | Android bridge (keyboard, file picker, clipboard, Downloads) |
| `src/gui/` | egui main window and session windows (desktop) |
| `src/mobile/` | Android UI: computer list, setup pages, touch session view |
| `src/agent.rs`, `src/servicectl.rs` | background service host and its control files |

## License

BSD 2-Clause - see [LICENSE](LICENSE). `vendor/winit` keeps its own license.
