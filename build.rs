//! Windows builds: embed the program's version details and manifest, so the
//! .exe says what it is (Explorer's Details tab, installers, security software).

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let nums: Vec<&str> = version.split('.').collect();
    let (a, b, c) = (nums[0], nums[1], nums[2]);

    let manifest = out.join("portlessvnc.manifest");
    std::fs::write(
        &manifest,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="PortlessVNC" version="{a}.{b}.{c}.0" processorArchitecture="*"/>
  <description>PortlessVNC remote desktop</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{{35138b9a-5d96-4fbd-8e2d-a2440225f93a}}"/>
      <supportedOS Id="{{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}}"/>
      <supportedOS Id="{{1f676c76-80e1-4239-95bb-83d0f6d0da78}}"/>
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
    </application>
  </compatibility>
</assembly>
"#
        ),
    )
    .unwrap();

    let rc = out.join("portlessvnc.rc");
    let manifest_path = manifest.display().to_string().replace('\\', "/");
    std::fs::write(
        &rc,
        format!(
            r#"1 24 "{manifest_path}"
1 VERSIONINFO
FILEVERSION {a},{b},{c},0
PRODUCTVERSION {a},{b},{c},0
FILEOS 0x40004
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "The PortlessVNC contributors"
      VALUE "FileDescription", "PortlessVNC remote desktop"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "PortlessVNC"
      VALUE "LegalCopyright", "Copyright (c) 2026, The PortlessVNC contributors. BSD 2-Clause License."
      VALUE "OriginalFilename", "PortlessVNC.exe"
      VALUE "ProductName", "PortlessVNC"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#
        ),
    )
    .unwrap();

    let obj = out.join("portlessvnc-res.o");
    let mut windres = Command::new("windres");
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86") {
        windres.arg("--target=pe-i386");
    }
    let ok = windres.arg("-i").arg(&rc).arg("-o").arg(&obj).status().map(|s| s.success()).unwrap_or(false);
    if ok {
        println!("cargo:rustc-link-arg-bins={}", obj.display());
    } else {
        println!("cargo:warning=windres failed: building without version details");
    }
}
