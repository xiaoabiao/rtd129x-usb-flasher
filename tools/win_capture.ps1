#requires -Version 5.1
<#
    win_capture.ps1 —— USBPcap 抓包 worker（必须以管理员身份运行）

    USBPcap 的 \\.\USBPcapN 控制设备只允许管理员打开（非管理员会得到
    "Access is denied"），所以这个脚本由 win_capture_start.ps1 通过 UAC
    提权拉起，自己不要直接双击运行。

    行为：
      * 在指定根集线器上开始抓包，输出到 -Out
      * 一直抓到 -MaxSeconds 秒、或 -StopMarker 文件出现、或 USBPcapCMD 自己退出
      * 把每个阶段写进 -Status 文件（调用方轮询这个文件判断"已经抓起来了"）
      * 结束时强制结束 USBPcapCMD（pcap 是逐包写盘的，强杀不会丢已写内容）

    退出码：0 正常结束；5 不是管理员；6 启动失败；7 抓包进程没起来
#>
[CmdletBinding()]
param(
    [int]$Interface = 1,
    [string]$Out = 'C:\usbcap\capture.pcap',
    [int]$MaxSeconds = 900,
    [int]$MaxSizeMB = 0,
    [int]$Snaplen = 65535,
    [string]$StopMarker = 'C:\usbcap\STOP',
    [string]$Status = 'C:\usbcap\capture_status.txt',
    [switch]$NoAllDevices
)

$ErrorActionPreference = 'Stop'
$CMD = 'C:\Program Files\USBPcap\USBPcapCMD.exe'

function Write-Status([string]$msg) {
    $line = ('{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $msg)
    Add-Content -LiteralPath $Status -Value $line -Encoding UTF8
}

# --- 1. 必须是管理员 --------------------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Status 'ERROR not elevated (USBPcap needs administrator)'
    exit 5
}

if (-not (Test-Path -LiteralPath $CMD)) {
    Write-Status ('ERROR USBPcapCMD not found: ' + $CMD)
    exit 6
}

$outDir = Split-Path -Parent $Out
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

# 清掉上一次的残留
Remove-Item -LiteralPath $StopMarker -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $Out -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $Status -ErrorAction SilentlyContinue

# --- 2. 启动 USBPcapCMD -----------------------------------------------------
$devArg = '\\.\USBPcap' + $Interface
$argv = @(
    '-d', $devArg,
    '-o', $Out,
    '-s', $Snaplen,
    '-b', '134217728',
    '--inject-descriptors'
)
if (-not $NoAllDevices) { $argv += '-A' }

Write-Status ('STARTING ' + $CMD + ' ' + ($argv -join ' '))
Write-Status ('ADMIN yes  INTERFACE ' + $Interface + '  OUT ' + $Out)

$proc = $null
try {
    $proc = Start-Process -FilePath $CMD -ArgumentList $argv -PassThru -WindowStyle Hidden
} catch {
    Write-Status ('ERROR Start-Process failed: ' + $_.Exception.Message)
    exit 6
}
if (-not $proc) {
    Write-Status 'ERROR Start-Process returned no process'
    exit 7
}
Write-Status ('PID ' + $proc.Id)

# --- 3. 等待结束条件 --------------------------------------------------------
$t0 = Get-Date
$deadline = $t0.AddSeconds($MaxSeconds)
$sizeLimit = if ($MaxSizeMB -gt 0) { [int64]$MaxSizeMB * 1MB } else { 0 }
$reason = 'timeout'
while ($true) {
    Start-Sleep -Milliseconds 200
    if ($proc.HasExited) { $reason = ('exited:' + $proc.ExitCode); break }
    if (Test-Path -LiteralPath $StopMarker) { $reason = 'stop-marker'; break }
    if ((Get-Date) -ge $deadline) { $reason = 'timeout'; break }
    if ($sizeLimit -gt 0 -and (Test-Path -LiteralPath $Out)) {
        if ((Get-Item -LiteralPath $Out).Length -ge $sizeLimit) { $reason = 'size-limit'; break }
    }
}

if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    $n = 0
    while (-not $proc.HasExited -and $n -lt 50) { Start-Sleep -Milliseconds 100; $n++ }
}

$size = 0
if (Test-Path -LiteralPath $Out) { $size = (Get-Item -LiteralPath $Out).Length }
$dur = ((Get-Date) - $t0).TotalSeconds
Write-Status ('STOPPED reason=' + $reason + ' size=' + $size + ' duration=' + ('{0:N1}' -f $dur) + 's')
if ($reason -eq 'stop-marker') {
    Remove-Item -LiteralPath $StopMarker -ErrorAction SilentlyContinue
}
exit 0
