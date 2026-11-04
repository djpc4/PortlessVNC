# Builds PortlessVNC with the per-user GNU Rust toolchain + portable WinLibs MinGW.
# Usage:  .\build.ps1            (release build)
#         .\build.ps1 -Debug     (debug build)
param([switch]$Debug)

$mingw = Join-Path $env:USERPROFILE "toolchains\mingw64\bin"
$cargo = Join-Path $env:USERPROFILE ".cargo\bin"
$env:PATH = "$cargo;$mingw;$env:PATH"

# libopus is built from source via CMake; WinLibs ships CMake 4.x which needs this
# for libopus' old cmake_minimum_required().
$env:CMAKE_GENERATOR = "Ninja"
$env:CMAKE_POLICY_VERSION_MINIMUM = "3.5"

# Keep build paths short: CMake (libopus) fails beyond Windows' 260-char path limit.
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE "pvnc-target" }

# keep this machine's paths (user name) out of the binary
$env:RUSTFLAGS = "--remap-path-prefix=$env:USERPROFILE=~"
$env:CFLAGS = "-ffile-prefix-map=$(($env:USERPROFILE) -replace '\\','/')=~ -ffile-prefix-map=$env:USERPROFILE=~"
Set-Location $PSScriptRoot
if ($Debug) { cargo build } else { cargo build --release }
exit $LASTEXITCODE
