# Builds the Android client APK (arm64, Android 8+) without Gradle:
# Rust -> libportlessvnc.so (NDK clang), Java helper -> classes.dex (javac + d8),
# then aapt2 link, zipalign and apksigner. Output: dist\PortlessVNC-<version>.apk
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$tc = Join-Path $env:USERPROFILE "toolchains"
$sdk = "$tc\android-sdk"
$ndk = "$sdk\ndk\27.2.12479018"
$bt = "$sdk\build-tools\34.0.0"
$jar = "$sdk\platforms\android-34\android.jar"
$env:JAVA_HOME = "$tc\jdk17"
$env:PATH = "$env:USERPROFILE\.cargo\bin;$tc\mingw64\bin;$tc\jdk17\bin;$env:PATH"
$api = 26
$llvm = "$ndk\toolchains\llvm\prebuilt\windows-x86_64\bin"

# ---- Rust ------------------------------------------------------------------
$env:ANDROID_NDK_HOME = $ndk
$env:ANDROID_NDK_ROOT = $ndk
$env:CC_aarch64_linux_android = "$llvm\aarch64-linux-android$api-clang.cmd"
$env:CXX_aarch64_linux_android = "$llvm\aarch64-linux-android$api-clang++.cmd"
$env:AR_aarch64_linux_android = "$llvm\llvm-ar.exe"
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "$llvm\aarch64-linux-android$api-clang.cmd"
# the audio library (oboe) is C++: link its runtime into our .so
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS = "-C link-arg=-lc++_static -C link-arg=-lc++abi --remap-path-prefix=$env:USERPROFILE=~"
# libopus via CMake: the NDK toolchain, for arm64 and our minimum API level
$tcfile = "$tc\android-arm64.cmake"
Set-Content $tcfile -Encoding ascii -Value @"
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-$api)
include("$($ndk -replace '\\','/')/build/cmake/android.toolchain.cmake")
"@
$env:CMAKE_TOOLCHAIN_FILE_aarch64_linux_android = $tcfile
# keep this machine's paths (user name) out of the C and C++ libraries too
$map = "-ffile-prefix-map=$(($env:USERPROFILE) -replace '\\','/')=~ -ffile-prefix-map=$env:USERPROFILE=~"
$env:CFLAGS_aarch64_linux_android = $map
$env:CXXFLAGS_aarch64_linux_android = $map
$env:CFLAGS = $map
$env:CXXFLAGS = $map
$env:CMAKE_GENERATOR = "Ninja"
$env:CMAKE_POLICY_VERSION_MINIMUM = "3.5"
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE "pvnc-target" }

cargo build --release --lib --target aarch64-linux-android
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$so = "$env:CARGO_TARGET_DIR\aarch64-linux-android\release\libportlessvnc.so"

# ---- Java helper -------------------------------------------------------------
$out = "$env:CARGO_TARGET_DIR\apk"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force "$out\classes", "$out\dex", "$out\res\mipmap-xxxhdpi" | Out-Null
$java = Get-ChildItem -Recurse android\java -Filter *.java | ForEach-Object { "`"$($_.FullName -replace '\\','/')`"" }
Set-Content "$out\sources.txt" $java -Encoding ascii
& javac --release 8 -encoding UTF-8 -nowarn -classpath $jar -d "$out\classes" "@$out\sources.txt"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& jar cf "$out\classes.jar" -C "$out\classes" .
& "$bt\d8.bat" --release --min-api $api --lib $jar --output "$out\dex" "$out\classes.jar"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# ---- launcher icon (drawn here: green rounded square with a white "P") --------
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 192, 192
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = "AntiAlias"; $g.TextRenderingHint = "AntiAlias"
$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$r = 44; $path.AddArc(8, 8, $r, $r, 180, 90); $path.AddArc(184 - $r, 8, $r, $r, 270, 90); $path.AddArc(184 - $r, 184 - $r, $r, $r, 0, 90); $path.AddArc(8, 184 - $r, $r, $r, 90, 90); $path.CloseFigure()
$g.FillPath((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 0x2f, 0x9e, 0x6b))), $path)
$font = New-Object System.Drawing.Font("Segoe UI", 96, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$fmt = New-Object System.Drawing.StringFormat; $fmt.Alignment = "Center"; $fmt.LineAlignment = "Center"
$g.DrawString("P", $font, [System.Drawing.Brushes]::White, (New-Object System.Drawing.RectangleF(0, 4, 192, 192)), $fmt)
$bmp.Save("$out\res\mipmap-xxxhdpi\ic_launcher.png", [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()

# ---- package -----------------------------------------------------------------
$ver = (Select-String Cargo.toml -Pattern '^version = "(\d+)\.(\d+)\.(\d+)"').Matches[0].Groups
$versionName = "$($ver[1]).$($ver[2]).$($ver[3])"
$versionCode = [int]$ver[1].Value * 10000 + [int]$ver[2].Value * 100 + [int]$ver[3].Value
& "$bt\aapt2.exe" compile --dir "$out\res" -o "$out\res.zip"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& "$bt\aapt2.exe" link -o "$out\base.apk" -I $jar --manifest android\AndroidManifest.xml --min-sdk-version $api --target-sdk-version 34 --version-code $versionCode --version-name $versionName "$out\res.zip"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open("$out\base.apk", "Update")
[void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, "$out\dex\classes.dex", "classes.dex")
[void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $so, "lib/arm64-v8a/libportlessvnc.so")
$zip.Dispose()

& "$bt\zipalign.exe" -f -p 4 "$out\base.apk" "$out\aligned.apk"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# signing key: made once, kept in the toolchains folder (keep it: updates need the same key)
$ks = "$tc\portlessvnc-android.jks"
$ksPassFile = "$tc\portlessvnc-android.pass"
if (-not (Test-Path $ks)) {
    $pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
    Set-Content $ksPassFile $pw -NoNewline -Encoding ascii
    & keytool -genkeypair -keystore $ks -alias portlessvnc -keyalg RSA -keysize 3072 -validity 20000 -storepass $pw -keypass $pw -dname "CN=PortlessVNC" | Out-Null
}
$pw = Get-Content $ksPassFile -Raw
$apk = "dist\PortlessVNC-$versionName.apk"
& "$bt\apksigner.bat" sign --ks $ks --ks-key-alias portlessvnc --ks-pass "pass:$pw" --key-pass "pass:$pw" --out $apk "$out\aligned.apk"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Remove-Item "$apk.idsig" -ErrorAction SilentlyContinue
Write-Host "built $apk"
