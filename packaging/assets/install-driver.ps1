# 安装 Realtek UMDF USB 驱动（需要管理员，仅新电脑首次需要）
# 驱动来自原厂工具包 usb_driver\auto_install_driver_win7up.zip。
# 使用前请先让板子进入 USB 下载模式并插好 USB，让 Windows 看到这个未知设备。
$ErrorActionPreference = 'Stop'
$target = $PSScriptRoot
$zip = Join-Path $target 'driver\auto_install_driver_win7up.zip'
if (-not (Test-Path -LiteralPath $zip)) { throw "找不到驱动包: $zip" }

# 未提权则用 UAC 重新拉起自己
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    ) | Out-Null
    return
}

$tmp = Join-Path $env:TEMP ('rtd-driver-' + [guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force
$bat = Join-Path $tmp 'auto_install_driver\rtk_install.bat'
if (-not (Test-Path -LiteralPath $bat)) { throw "驱动包结构异常: $bat" }

Write-Host "运行驱动安装脚本: $bat"
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$bat`"" `
    -WorkingDirectory (Split-Path -LiteralPath $bat) -Wait

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show(
    "USB 驱动安装脚本已执行。`r`n`r`n如果设备仍未出现：拔插一次板子，再打开工具点「扫描设备」。",
    '驱动安装', 'OK', 'Information') | Out-Null
