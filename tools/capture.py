#!/usr/bin/env python3
"""Drive USBPcap on Windows to capture the RTD129x flash traffic.

Runs from WSL, talking to `USBPcapCMD.exe` through PowerShell. It exists because
the decisive question -- *does the board answer every chunk?* -- cannot be settled
without seeing the device's replies, and the capture has to happen on Windows
(the board is bound to a Windows UMDF driver, so it cannot be moved to Linux
without losing the original tool).

Typical use::

    python3 tools/capture.py --list          # which USBPcapN sees the board
    python3 tools/capture.py --run 10        # capture for 10 s, then analyse

Requires USBPcap (``winget install --id desowin.USBPcap``) and **one reboot**
after installing it: the driver is a filter on the USB root hubs and does not
bind until Windows restarts.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

# Under WSL interop the Windows path must be reached through /mnt, otherwise
# `subprocess` gets a literal `C:\...` and reports FileNotFoundError.
PS_CANDIDATES = [
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/pwsh.exe",
    "/mnt/c/Program Files/PowerShell/7/pwsh.exe",
]


def _find_ps() -> str:
    for c in PS_CANDIDATES:
        if os.path.exists(c):
            return c
    return PS_CANDIDATES[0]


PS = _find_ps()
USBCAP_DIR = r"C:\usbcap"
CMD = r"C:\Program Files\USBPcap\USBPcapCMD.exe"

VID = 0x0BDA
PID = 0x1195


def ps(script: str, timeout: int = 120) -> str:
    """Run a PowerShell snippet and return its stdout."""
    try:
        out = subprocess.run(
            [PS, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            timeout=timeout,
        )
        return (out.stdout or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        print("找不到 powershell.exe —— 这个脚本要在 WSL 里跑。", file=sys.stderr)
        raise SystemExit(2)


def ensure_dir() -> bool:
    out = ps(f"New-Item -ItemType Directory -Force -Path '{USBCAP_DIR}' | Out-Null; 'ok'")
    return "ok" in out


def installed() -> bool:
    out = ps(f"if (Test-Path '{CMD}') {{ 'yes' }} else {{ 'no' }}")
    return "yes" in out


def driver_bound() -> int:
    """How many USBPcap filter devices are attached to root hubs."""
    out = ps(
        "(Get-PnpDevice -ErrorAction SilentlyContinue | "
        "Where-Object InstanceId -like '*USBPcap*').Count"
    ).strip()
    try:
        return int(out.splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def device_summary() -> str:
    """Where the board is, and what its parent hub is."""
    return ps(
        "$d = Get-PnpDevice -InstanceId 'USB\\VID_0BDA&PID_1195*' "
        "-ErrorAction SilentlyContinue | Where-Object Status -eq 'OK';"
        "foreach ($x in $d) {"
        "  $loc = (Get-PnpDeviceProperty -InstanceId $x.InstanceId "
        "-KeyName 'DEVPKEY_Device_LocationInfo' -ErrorAction SilentlyContinue).Data;"
        "  $par = (Get-PnpDeviceProperty -InstanceId $x.InstanceId "
        "-KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data;"
        "  Write-Output ($x.InstanceId + ' | ' + $x.Status + ' | ' + $loc + ' | ' + $par)"
        "}"
    ).strip()


def list_interfaces() -> None:
    print("=" * 70)
    print("USBPcap 状态")
    print("=" * 70)

    if not installed():
        print("  USBPcap 没有安装。")
        print("  安装： winget install --id desowin.USBPcap --accept-package-agreements")
        print("        然后 **重启电脑**。")
        return
    print(f"  USBPcapCMD : 已安装 {CMD}")

    bound = driver_bound()
    print(f"  驱动绑定   : {bound} 个根集线器")
    if bound == 0:
        print()
        print("  ⚠ 驱动还没绑定。安装后需要 **重启一次** 才会生效。")
        print("    重启后再跑这个命令。")
        print()
        print("    如果你已经重启过还是 0，检查第三方安全软件是否拦截了驱动加载。")
        return

    print()
    print("=" * 70)
    print("板子在哪")
    print("=" * 70)
    summary = device_summary()
    if summary:
        for line in summary.splitlines():
            print(f"  {line}")
    else:
        print("  没找到 VID_0BDA&PID_1195 且状态为 OK 的设备。板子插好了吗？")

    print()
    print("=" * 70)
    print("可用接口")
    print("=" * 70)
    # Each root hub bound by USBPcap exposes \\.\USBPcapN.
    for n in range(1, 17):
        # There is no cheap "does this exist" query without opening it, which
        # would start a capture; instead report the bound count and let --run
        # probe them.
        print(f"  \\.\\USBPcap{n}   （用 --run {n} 试）")

    print()
    print("提示：板子挂在 VIA Labs 的 hub 后面时，要抓它 **上游** 的根集线器。")
    print("      --run 会依次试，找到有 0bda:1195 流量的那个。")


def start_capture(iface: int, out_name: str, seconds: int) -> Path | None:
    """Run one capture for `seconds` and return the pcap path if it has data."""
    pcap_win = f"{USBCAP_DIR}\\{out_name}"
    # Remove any previous file so "produced a file" is meaningful.
    ps(f"Remove-Item '{pcap_win}' -ErrorAction SilentlyContinue; 'ok'")

    script = (
        f"$p = Start-Process -FilePath '{CMD}' "
        f"-ArgumentList '-d','\\\\.\\USBPcap{iface}','-o','{pcap_win}','-s','65535',"
        f"'-b','134217728' "
        f"-PassThru -WindowStyle Hidden;"
        f"Start-Sleep -Seconds {seconds};"
        f"if (-not $p.HasExited) {{ Stop-Process -Id $p.Id -Force }};"
        f"Start-Sleep -Milliseconds 800;"
        f"if (Test-Path '{pcap_win}') {{ (Get-Item '{pcap_win}').Length }} else {{ 0 }}"
    )
    out = ps(script, timeout=seconds + 90).strip()
    try:
        size = int(out.splitlines()[-1])
    except (ValueError, IndexError):
        size = 0

    local = Path(f"/mnt/c/usbcap/{out_name}")
    if size > 0 and local.exists():
        return local
    return None


def analyse(pcap: Path) -> None:
    here = Path(__file__).resolve().parent
    script = here / "usbcap.py"
    if not script.exists():
        print(f"（找不到解析脚本 {script}）")
        return
    print()
    print("=" * 70)
    print("解析结果")
    print("=" * 70)
    subprocess.run([sys.executable, str(script), str(pcap)])


def run(iface: int | None, seconds: int) -> int:
    if not installed():
        print("USBPcap 没装。先跑 --list 看提示。")
        return 2
    if driver_bound() == 0:
        print("USBPcap 驱动还没绑定 —— 需要 **重启一次**。")
        return 2
    if not ensure_dir():
        print(f"无法创建 {USBCAP_DIR}")
        return 2

    candidates = [iface] if iface else list(range(1, 9))
    for n in candidates:
        print(f"--- 试 \\\\.\\USBPcap{n}（{seconds} 秒）---")
        pcap = start_capture(n, f"probe{n}.pcap", seconds)
        if pcap is None:
            print(f"    没有抓到数据（接口不存在或该根集线器没设备）")
            continue
        print(f"    抓到 {pcap.stat().st_size} 字节 -> {pcap}")
        analyse(pcap)
        return 0

    print()
    print("所有接口都没抓到数据。可能原因：")
    print("  * 驱动没绑上（重启了吗？）")
    print("  * 板子插在别的根集线器上（试 --run 更多编号）")
    print("  * 需要管理员权限运行")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true", help="列出状态和接口")
    ap.add_argument("--run", nargs="?", type=int, const=0, metavar="N",
                    help="抓包；N 是 USBPcapN 的编号，省略则自动探测")
    ap.add_argument("--seconds", type=int, default=10, help="抓多少秒（默认 10）")
    args = ap.parse_args()

    if args.list or args.run is None:
        list_interfaces()
        if args.run is None:
            return 0

    return run(args.run or None, args.seconds)


if __name__ == "__main__":
    sys.exit(main())
