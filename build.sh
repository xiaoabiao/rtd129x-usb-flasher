#!/usr/bin/env bash
# WSL/Linux 交叉编译 Windows 版（输出在 target/x86_64-pc-windows-gnu/<profile>/）。
#
# 与 CI（windows-latest 原生 MSVC 构建）等价，只是本机在 Linux 上开发时用。
# 需要 MinGW：默认 $HOME/tools/mingw，可用 MINGW_ROOT 覆盖。
#
# 用法：
#   ./build.sh            # debug
#   ./build.sh release    # release（打包用这个）
#   ./build.sh test       # 本机 Linux 上跑测试（不需要 USB 设备）
set -euo pipefail
cd "$(dirname "$0")"

MINGW="${MINGW_ROOT:-$HOME/tools/mingw}"
if [ -x "$MINGW/usr/bin/x86_64-w64-mingw32-gcc" ]; then
    export PATH="$MINGW/usr/bin:$PATH"
else
    echo "[build] MinGW 未找到（$MINGW）；设置 MINGW_ROOT 或先跑 test" >&2
fi
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/rev/rtd-flasher-target}"

case "${1:-debug}" in
    test)
        cargo test --workspace
        ;;
    release)
        cargo build --release -p rtd-cli --features usb --target x86_64-pc-windows-gnu
        cargo build --release -p rtd-gui --features usb,screenshot --target x86_64-pc-windows-gnu
        echo "[build] 完成：$CARGO_TARGET_DIR/x86_64-pc-windows-gnu/release/"
        ;;
    debug|*)
        cargo build -p rtd-cli --features usb --target x86_64-pc-windows-gnu
        cargo build -p rtd-gui --features usb,screenshot --target x86_64-pc-windows-gnu
        echo "[build] 完成：$CARGO_TARGET_DIR/x86_64-pc-windows-gnu/debug/"
        ;;
esac
