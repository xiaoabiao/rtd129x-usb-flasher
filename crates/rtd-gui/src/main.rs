//! `rtd-gui` — egui front end for the RTD129x USB download tool.
//!
//! Why egui instead of Tauri: the core is pure Rust and the UI is a thin shell,
//! so a single-language build avoids the webkit2gtk system dependency entirely
//! and cross-compiles to a self-contained Windows `.exe`.
//!
//! Build for Windows from WSL:
//!
//! ```text
//! cargo build -p rtd-gui --target x86_64-pc-windows-gnu --release
//! ```
//!
//! See `build.sh win` for the wrapped command.

#![deny(missing_debug_implementations)]
#![allow(missing_docs)]

mod app;
mod diag;
mod font;
mod state;
mod worker;

fn main() -> eframe::Result<()> {
    // `rtd-gui.exe --font-debug` reports exactly which font files were probed
    // and whether one parsed. This exists because a missing CJK font is
    // otherwise invisible: the UI still runs, it just draws tofu boxes.
    if std::env::args().any(|a| a == "--font-debug") {
        font::debug_report();
        return Ok(());
    }

    // `rtd-gui.exe --diag` prints where the tool looks for its input files.
    // "请先选择：hwsetting 文件" is unhelpful on its own: it says something is
    // missing without saying where it looked.
    if std::env::args().any(|a| a == "--diag") {
        diag::report();
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Optional positional argument: an `install.img` to preload, so a repeat
    // burn is `rtd-gui.exe D:\install.img` instead of picking the file by hand.
    let initial_image = std::env::args()
        .skip(1)
        .find(|a| !a.starts_with('-') && std::path::Path::new(a).is_file())
        .map(std::path::PathBuf::from);
    app::run(initial_image)
}
