# Builds PortlessVNC for Windows 7 and later (x64) with Rust's win7 target.
# That target is tier 3, so it uses nightly Rust and rebuilds the standard
# library for it (rust-src component). Output: dist\PortlessVNC-<version>-win7.exe
$ErrorActionPreference = "Stop"
# the MSVCRT edition of MinGW: msvcrt.dll is on every Windows (UCRT is not on 7/8.1)
$mingw = Join-Path $env:USERPROFILE "toolchains\mingw64-msvcrt\bin"
$cargo = Join-Path $env:USERPROFILE ".cargo\bin"
$env:PATH = "$cargo;$mingw;$env:PATH"
$env:CMAKE_GENERATOR = "Ninja"
$env:CMAKE_POLICY_VERSION_MINIMUM = "3.5"
# own build folder: its C libraries are built against a different C runtime
$env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE "pvnc-w7"
$target = "x86_64-win7-windows-gnu"
$t = $target -replace '-', '_'
# C code (libopus, ring) is built by MinGW for this target
Set-Item "env:CC_$t" "gcc"
Set-Item "env:CXX_$t" "g++"
Set-Item "env:AR_$t" "ar"
Set-Item "env:CARGO_TARGET_$($t.ToUpper())_LINKER" "gcc"
# keep this machine's paths (user name) out of the binary
$env:RUSTFLAGS = "--remap-path-prefix=$env:USERPROFILE=~"
# older windows-targets releases (0.42/0.48) only link their import library for
# the standard x86_64-pc-windows-gnu name: point the linker at those libraries
$reg = Join-Path $env:USERPROFILE ".cargo\registry\src"
Get-ChildItem $reg -Directory | ForEach-Object { Get-ChildItem $_.FullName -Directory -Filter "windows_x86_64_gnu-0.4*" } | ForEach-Object {
    $env:RUSTFLAGS += " -L native=$($_.FullName)\lib"
}
$env:CFLAGS = "-ffile-prefix-map=$(($env:USERPROFILE) -replace '\\','/')=~ -ffile-prefix-map=$env:USERPROFILE=~"

Set-Location $PSScriptRoot
cargo +nightly-x86_64-pc-windows-gnu build --release --bin PortlessVNC --target $target -Z build-std=std,panic_unwind
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$ver = (Select-String Cargo.toml -Pattern '^version = "([^"]+)"').Matches[0].Groups[1].Value
New-Item -ItemType Directory -Force dist | Out-Null
Copy-Item "$env:CARGO_TARGET_DIR\$target\release\PortlessVNC.exe" "dist\PortlessVNC-$ver-win7.exe" -Force
"built dist\PortlessVNC-$ver-win7.exe"
