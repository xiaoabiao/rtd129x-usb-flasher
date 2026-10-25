#requires -Version 5.1
<#
    win_capture_start.ps1 —— 非管理员侧启动器：弹 UAC → 拉起 win_capture.ps1

    用法（在普通 PowerShell 里）：
        .\win_capture_start.ps1                       # 默认 USBPcap1，抓 15 分钟
        .\win_capture_start.ps1 -MaxSeconds 60        # 抓 1 分钟
        .\win_capture_start.ps1 -Interface 1 -Out C:\usbcap\golden.pcap

    需要停止时创建 C:\usbcap\STOP（内容随便），worker 看到就收工：
        New-Item C:\usbcap\STOP -ItemType File

    它只负责"提权 + 等 worker 报 PID"，抓包本身在 worker 里。
#>
[CmdletBinding()]
param(
    [int]$Interface = 1,
    [string]$Out = 'C:\usbcap\capture.pcap',
    [int]$MaxSeconds = 900,
    [int]$MaxSizeMB = 0,
    [int]$Snaplen = 65535,
    [string]$StopMarker = 'C:\usbcap\STOP',
    [string]$Status = 'C:\usbcap\capture_status.txt'
)

$ErrorActionPreference = 'Stop'
$worker = Join-Path $PSScriptRoot 'win_capture.ps1'
if (-not (Test-Path -LiteralPath $worker)) {
    throw "missing worker script: $worker"
}

$outDir = Split-Path -Parent $Out
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}
Remove-Item -LiteralPath $Status -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $StopMarker -ErrorAction SilentlyContinue

$argLine = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', ('"' + $worker + '"'),
    '-Interface', $Interface,
    '-Out', ('"' + $Out + '"'),
    '-MaxSeconds', $MaxSeconds,
    '-MaxSizeMB', $MaxSizeMB,
    '-Snaplen', $Snaplen,
    '-StopMarker', ('"' + $StopMarker + '"'),
    '-Status', ('"' + $Status + '"')
) -join ' '

Write-Output "launching elevated capture worker (UAC prompt should appear now) ..."
Write-Output "  interface = USBPcap$Interface"
Write-Output "  output    = $Out"
Write-Output "  max       = ${MaxSeconds}s   stop marker = $StopMarker"

try {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argLine -WindowStyle Hidden | Out-Null
} catch {
    Write-Output ('UAC 被取消或提权失败: ' + $_.Exception.Message)
    exit 3
}

# 等 worker 写出 "PID nnn" —— 这说明抓包真的起来了
$deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $Status) {
        $txt = Get-Content -LiteralPath $Status -Raw -ErrorAction SilentlyContinue
        if ($txt -match 'PID \d+') {
            $txt.Trim()
            Write-Output ''
            Write-Output 'CAPTURE RUNNING'
            exit 0
        }
        if ($txt -match 'ERROR') {
            $txt.Trim()
            exit 4
        }
    }
    Start-Sleep -Milliseconds 250
}

Write-Output 'ERROR: 120 秒内没等到抓包进程启动（UAC 没点？）'
if (Test-Path -LiteralPath $Status) { Get-Content -LiteralPath $Status }
exit 5
