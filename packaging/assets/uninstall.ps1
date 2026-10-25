# 卸载 RTD129x 线刷工具（只删除程序文件与快捷方式）
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Windows.Forms
$r = [System.Windows.Forms.MessageBox]::Show(
    "确定卸载 RTD129x 线刷工具？`r`n`r`n只会删除程序文件和快捷方式，不会动你的镜像、日志或板子。",
    '卸载', 'YesNo', 'Question')
if ($r -ne 'Yes') { exit }

$target = $PSScriptRoot
Get-Process rtd-gui -ErrorAction SilentlyContinue | Stop-Process -Force

$desk = [Environment]::GetFolderPath('Desktop')
Remove-Item -LiteralPath (Join-Path $desk 'RTD129x 线刷工具.lnk') -Force -ErrorAction SilentlyContinue

$sm = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\RTD-Flasher'
Remove-Item -LiteralPath $sm -Recurse -Force -ErrorAction SilentlyContinue

# 目录自身无法在运行时删除：交给 cmd 延迟删除
$cmd = 'ping 127.0.0.1 -n 3 >nul & rmdir /s /q "' + $target + '"'
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $cmd -WindowStyle Hidden
