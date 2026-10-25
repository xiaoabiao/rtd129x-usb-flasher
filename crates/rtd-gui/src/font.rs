//! CJK font loading.
//!
//! egui's built-in fonts contain **no CJK glyphs**, so Chinese text renders as
//! tofu boxes (□□□) unless a font with those glyphs is installed into the
//! context. This module finds a suitable font on the host and registers it as a
//! **fallback** for every family, so Latin text keeps egui's default look while
//! Chinese falls through to the system font.
//!
//! The candidates are the standard Windows UI fonts. `.ttc` files are font
//! *collections*; [`egui::FontData::index`] selects the face inside, and 0 is
//! the regular weight for all of the fonts listed here.
//!
//! When no font is found the UI still runs -- it just cannot draw Chinese. That
//! is reported through [`install`]'s return value and surfaced in the log rather
//! than being silent.

use std::path::PathBuf;

/// Font files to try, in preference order, with the face index inside the file.
///
/// Microsoft YaHei first (the modern Windows UI font), then SimHei (a plain
/// TTF, and the most reliable fallback), then the older serif/sans options.
const CANDIDATES: &[(&str, u32)] = &[
    ("msyh.ttc", 0),    // Microsoft YaHei 微软雅黑
    ("msyh.ttf", 0),    // older single-face packaging
    ("simhei.ttf", 0),  // SimHei 黑体, plain TTF
    ("deng.ttf", 0),    // DengXian 等线
    ("simsun.ttc", 0),  // SimSun 宋体
    ("msjh.ttc", 0),    // Microsoft JhengHei 正黑体 (Traditional)
    ("simkai.ttf", 0),  // KaiTi 楷体
    ("simfang.ttf", 0), // FangSong 仿宋
];

/// Directories that may hold the font files.
fn font_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    // `WINDIR` is set on Windows; under WSL it is usually unset, so the
    // well-known locations are probed as well.
    if let Ok(windir) = std::env::var("WINDIR") {
        dirs.push(PathBuf::from(windir).join("Fonts"));
    }
    if let Ok(root) = std::env::var("SystemRoot") {
        dirs.push(PathBuf::from(root).join("Fonts"));
    }
    dirs.push(PathBuf::from(r"C:\Windows\Fonts"));
    // WSL mount of the Windows drive, so the same code works while developing.
    dirs.push(PathBuf::from("/mnt/c/Windows/Fonts"));
    // A font shipped next to the executable wins over none at all.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.join("fonts"));
            dirs.push(dir.to_path_buf());
        }
    }
    dirs
}

/// Find a readable CJK font, returning its bytes, face index and path.
pub fn find() -> Option<(Vec<u8>, u32, PathBuf)> {
    for dir in font_dirs() {
        for (name, index) in CANDIDATES {
            let path = dir.join(name);
            match std::fs::read(&path) {
                Ok(bytes) if !bytes.is_empty() => return Some((bytes, *index, path)),
                _ => continue,
            }
        }
    }
    None
}

/// Install a CJK font into `ctx` as a fallback for every family.
///
/// Returns the path of the font used, or `None` when none was found (in which
/// case Chinese text will not render).
pub fn install(ctx: &egui::Context) -> Option<PathBuf> {
    let (bytes, index, path) = find()?;

    let mut fonts = egui::FontDefinitions::default();
    let mut data = egui::FontData::from_owned(bytes);
    // For a `.ttc` this picks the face; harmless for plain `.ttf` (always 0).
    data.index = index;
    fonts.font_data.insert("cjk".to_owned(), data);

    // Append as a *fallback*: egui walks the list in order and uses the first
    // font that has the glyph, so Latin keeps the built-in look and CJK falls
    // through to the system font.
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts.families.entry(family).or_default().push("cjk".to_owned());
    }

    ctx.set_fonts(fonts);
    Some(path)
}

/// Build the diagnostic text, for `--font-debug`.
///
/// A missing CJK font is otherwise silent -- the window opens and Chinese shows
/// as tofu -- so this is the quickest way to tell "font not found" apart from
/// "font found but the family mapping is wrong".
///
/// The report goes to `RTD_FONT_DEBUG_FILE` when set, and always to
/// `font-report.txt` next to the executable. Capturing a Windows GUI process's
/// stdout through `cmd.exe` is unreliable (and `cmd` resets its working
/// directory when launched from a UNC path), so the file sink is the dependable
/// route; stdout is written too, for the WSL/Linux case.
pub fn debug_report() {
    let text = build_report();

    // Always write next to the executable: a fixed, predictable location that
    // does not depend on the working directory or on env plumbing.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let fallback = dir.join("font-report.txt");
            match std::fs::write(&fallback, &text) {
                Ok(()) => println!("font report written to {}", fallback.display()),
                Err(e) => println!("could not write {}: {e}", fallback.display()),
            }
        }
    }

    // Optional explicit destination, for callers that want it elsewhere.
    if let Ok(path) = std::env::var("RTD_FONT_DEBUG_FILE") {
        if !path.is_empty() {
            match std::fs::write(&path, &text) {
                Ok(()) => println!("font report written to {path}"),
                Err(e) => println!("could not write {path}: {e}"),
            }
        }
    }

    print!("{text}");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
}

fn build_report() -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(o, "== font search ==");
    let _ = writeln!(o, "WINDIR      = {:?}", std::env::var("WINDIR"));
    let _ = writeln!(o, "SystemRoot  = {:?}", std::env::var("SystemRoot"));
    let _ = writeln!(o, "cwd         = {:?}", std::env::current_dir());
    let _ = writeln!(o, "exe         = {:?}", std::env::current_exe());
    let _ = writeln!(o);
    for dir in font_dirs() {
        let exists = dir.is_dir();
        let _ = writeln!(o, "dir {:<40} exists={exists}", dir.display());
        if !exists {
            continue;
        }
        for (name, index) in CANDIDATES {
            let path = dir.join(name);
            match std::fs::read(&path) {
                Ok(b) => {
                    let _ = writeln!(o, "    OK   {name:<16} {:>9} bytes  face {index}", b.len());
                }
                Err(e) => {
                    let _ = writeln!(o, "    --   {name:<16} {e}");
                }
            }
        }
    }
    let _ = writeln!(o);
    match find() {
        Some((bytes, index, path)) => {
            let _ = writeln!(
                o,
                "SELECTED {} ({} bytes, face {index})",
                path.display(),
                bytes.len()
            );
            // Parsing proves the bytes are a usable font, not merely readable.
            match ab_glyph_probe(&bytes, index) {
                Ok(n) => {
                    let _ = writeln!(o, "parsed OK, {n} glyphs");
                }
                Err(e) => {
                    let _ = writeln!(o, "PARSE FAILED: {e}");
                }
            }
            // A font can parse and still lack CJK; ask it for a real glyph.
            match has_cjk_glyph(&bytes, index) {
                Ok(true) => {
                    let _ = writeln!(o, "CJK glyph present for '线'");
                }
                Ok(false) => {
                    let _ = writeln!(o, "PARSED BUT NO CJK GLYPH -- wrong font selected");
                }
                Err(e) => {
                    let _ = writeln!(o, "CJK probe failed: {e}");
                }
            }
        }
        None => {
            let _ = writeln!(o, "NO CJK FONT FOUND -- Chinese will render as tofu");
        }
    }
    o
}

/// Whether the font actually carries a CJK glyph.
///
/// `glyph_count` alone is not enough: a Latin-only font parses fine and still
/// renders Chinese as tofu.
fn has_cjk_glyph(bytes: &[u8], index: u32) -> Result<bool, String> {
    use ab_glyph::Font as _;
    let font = ab_glyph::FontVec::try_from_vec_and_index(bytes.to_vec(), index)
        .map_err(|e| format!("{e:?}"))?;
    Ok(font.glyph_id('线').0 != 0)
}

/// Minimal sanity parse using the same crate epaint uses.
fn ab_glyph_probe(bytes: &[u8], index: u32) -> Result<usize, String> {
    // epaint pulls in ab_glyph; using its public entry point here keeps the
    // check faithful to what the renderer will do.
    let font = ab_glyph::FontVec::try_from_vec_and_index(bytes.to_vec(), index)
        .map_err(|e| format!("{e:?}"))?;
    // `glyph_count` is `u32`; a single-face CJK font has thousands.
    Ok(ab_glyph::Font::glyph_count(&font) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_list_is_non_empty_and_has_no_duplicates() {
        assert!(!CANDIDATES.is_empty());
        let mut names: Vec<&str> = CANDIDATES.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate candidate font names");
    }

    #[test]
    fn font_dirs_always_include_the_windows_location() {
        let dirs = font_dirs();
        assert!(
            dirs.iter().any(|d| d.ends_with("Fonts")),
            "expected at least one ...\\Fonts directory, got {dirs:?}"
        );
    }

    #[test]
    fn find_reports_the_path_it_used() {
        // On a machine with no CJK font this returns None, which is a valid
        // outcome; when it succeeds the bytes must be non-empty and the path
        // must exist.
        match find() {
            Some((bytes, _index, path)) => {
                assert!(!bytes.is_empty());
                assert!(path.exists(), "{} should exist", path.display());
                assert!(
                    bytes.len() > 100_000,
                    "a CJK font is large; got {} bytes from {}",
                    bytes.len(),
                    path.display()
                );
            }
            None => eprintln!("note: no CJK font found on this host"),
        }
    }

    #[test]
    fn install_never_panics() {
        // The install path needs a live egui context, so this only exercises
        // the lookup half; the context wiring is covered by the screenshot
        // check in the CI script.
        let _ = find();
    }
}
