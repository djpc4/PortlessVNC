# Cross-compiles the Linux (x86_64, glibc 2.31+ e.g. Ubuntu 20.04+/Debian 11+/Mint 20+) build
# from Windows with cargo-zigbuild + zig. Output: dist\portlessvnc-linux-x86_64
$tc = Join-Path $env:USERPROFILE "toolchains"
$env:PATH = "$env:USERPROFILE\.cargo\bin;$tc\zig-windows-x86_64-0.13.0;$tc\mingw64\bin;$env:PATH"
$env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE "pvnc-target"
# ALSA (cpal) and Opus are linked against Debian's shared libraries via a pkg-config stand-in
$env:PKG_CONFIG = "$tc\linux-libs\pkg-config.cmd"
$env:PKG_CONFIG_ALLOW_CROSS = "1"
$env:LIBOPUS_NO_STATIC = "1"
# keep this machine's paths (user name) out of the binary
$env:RUSTFLAGS = "--remap-path-prefix=$env:USERPROFILE=~"
Set-Location $PSScriptRoot
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.31
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
New-Item -ItemType Directory -Force dist | Out-Null
Copy-Item "$env:CARGO_TARGET_DIR\x86_64-unknown-linux-gnu\release\PortlessVNC" dist\portlessvnc-linux-x86_64 -Force
"built dist\portlessvnc-linux-x86_64"
