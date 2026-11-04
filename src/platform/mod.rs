//! Platform layer: Windows and Linux (X11) are implemented; Android is a
//! client only; other platforms get stubs so the rest of the program (VPN,
//! protocol, viewer) stays portable.

#[cfg(windows)]
pub mod win;
#[cfg(windows)]
pub use win::*;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(any(windows, target_os = "linux")))]
pub mod stub;
#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
pub use stub::*;

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "android")]
pub use android::*;
