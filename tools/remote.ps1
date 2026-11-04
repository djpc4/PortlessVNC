# Troubleshooting helper: drive a VNC server with one connection's worth of
# actions and save a screenshot as a PNG. Wraps PortlessVNC's --remote mode.
# The server must offer plain VNC password authentication.
#
#   $env:PVNC_VNC_PASS = '<password>'
#   .\tools\remote.ps1 192.168.1.20 shot.png "key:win+r" "wait:800" "type:cmd" "key:enter"
#
# Actions: click:x,y  dbl:x,y  right:x,y  type:text  key:win+r  wait:ms
param(
    [Parameter(Mandatory = $true)][string]$Address,
    [Parameter(Mandatory = $true)][string]$Png,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Ops
)
$exe = $env:PVNC_REMOTE_EXE
if (-not $exe) { $exe = Join-Path $env:USERPROFILE "toolchains\pvnc-remote\PortlessVNC-remote.exe" }
$Png = [IO.Path]::GetFullPath((Join-Path (Get-Location) $Png))
$bmp = [IO.Path]::ChangeExtension($Png, ".bmp")
$log = [IO.Path]::ChangeExtension($Png, ".log")
$quote = [string][char]34
$a = @('--remote', $Address, "$quote$bmp$quote") + ($Ops | Where-Object { $_ } | ForEach-Object { $quote + $_.Replace($quote, "\$quote") + $quote })
$p = Start-Process $exe -ArgumentList $a -PassThru -Wait -NoNewWindow -RedirectStandardOutput $log -RedirectStandardError "$log.err"
Get-Content $log
Get-Content "$log.err" | Select-String "WARN|ERROR" | Select-Object -Last 3 | ForEach-Object { $_.Line }
Remove-Item $log, "$log.err" -ErrorAction SilentlyContinue
if (Test-Path $bmp) {
    Add-Type -AssemblyName System.Drawing
    $i = [System.Drawing.Image]::FromFile($bmp)
    $i.Save($Png, [System.Drawing.Imaging.ImageFormat]::Png)
    $i.Dispose()
    Remove-Item $bmp
}
exit $p.ExitCode
