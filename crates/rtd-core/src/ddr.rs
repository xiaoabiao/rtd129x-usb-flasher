//! DRAM configuration selection.
//!
//! The hwsetting blob is **DRAM-specific**: it trains the DDR controller PHY, so
//! the wrong blob means the board never brings memory up and nothing else can be
//! flashed. The original therefore refuses to start without a selection:
//!
//! ```text
//! Please select ddr type first!
//! ```
//!
//! # Where this comes from
//!
//! `initialization_combobox` @0x00426390 fills the dropdown in this order:
//!
//! ```text
//! 0: 2DDR4_1GB   1: 2DDR4_2GB   2: 4DDR4_1GB   3: 4DDR4_2GB
//! 4: 2DDR3_1GB   5: 2DDR3_2GB   6: 4DDR3_1GB   7: 4DDR3_2GB
//! ```
//!
//! and `dynamicSwitchUsbHwDDR` @0x00425F80 maps the selection to a hwsetting
//! file name:
//!
//! ```text
//! case 0,1,2,3:  "2DDR4_4Gb_1600_B"
//! case 4,5,6,7:  "2DDR3_4Gb_1600_B"
//! default:       ""            (empty -> the caller reports the error)
//! ```
//!
//! # The size does not change the blob
//!
//! All four DDR4 options share one blob, and all four DDR3 options share
//! another -- the 1GB/2GB/4GB distinction never reaches the file name. That is
//! why both shipped blobs are named `..._4Gb_1600_B`. Density is detected by the
//! controller at runtime; only the **generation** (DDR3 vs DDR4) changes the PHY
//! programming.
//!
//! The finer options are still offered, because the original offers them and a
//! user comparing the two tools should see the same list -- and because the
//! choice is recorded in `SYSTEM.ini` as `DDR TYPE`.

use std::path::{Path, PathBuf};

/// The eight DRAM configurations the original's dropdown offers.
///
/// Declaration order is the dropdown order, so [`DdrType::ALL`] matches the
/// original exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DdrType {
    /// `2DDR4_1GB` — 2 chips, DDR4, 1 GiB.
    Ddr4X2_1Gb,
    /// `2DDR4_2GB` — 2 chips, DDR4, 2 GiB.
    Ddr4X2_2Gb,
    /// `4DDR4_1GB` — 4 chips, DDR4, 1 GiB.
    Ddr4X4_1Gb,
    /// `4DDR4_2GB` — 4 chips, DDR4, 2 GiB.
    Ddr4X4_2Gb,
    /// `2DDR3_1GB` — 2 chips, DDR3, 1 GiB.
    Ddr3X2_1Gb,
    /// `2DDR3_2GB` — 2 chips, DDR3, 2 GiB.
    Ddr3X2_2Gb,
    /// `4DDR3_1GB` — 4 chips, DDR3, 1 GiB.
    Ddr3X4_1Gb,
    /// `4DDR3_2GB` — 4 chips, DDR3, 2 GiB.
    Ddr3X4_2Gb,
}

impl DdrType {
    /// Every option, in the original's dropdown order.
    pub const ALL: [DdrType; 8] = [
        DdrType::Ddr4X2_1Gb,
        DdrType::Ddr4X2_2Gb,
        DdrType::Ddr4X4_1Gb,
        DdrType::Ddr4X4_2Gb,
        DdrType::Ddr3X2_1Gb,
        DdrType::Ddr3X2_2Gb,
        DdrType::Ddr3X4_1Gb,
        DdrType::Ddr3X4_2Gb,
    ];

    /// The label shown in the dropdown and stored in `SYSTEM.ini`.
    pub fn label(self) -> &'static str {
        match self {
            DdrType::Ddr4X2_1Gb => "2DDR4_1GB",
            DdrType::Ddr4X2_2Gb => "2DDR4_2GB",
            DdrType::Ddr4X4_1Gb => "4DDR4_1GB",
            DdrType::Ddr4X4_2Gb => "4DDR4_2GB",
            DdrType::Ddr3X2_1Gb => "2DDR3_1GB",
            DdrType::Ddr3X2_2Gb => "2DDR3_2GB",
            DdrType::Ddr3X4_1Gb => "4DDR3_1GB",
            DdrType::Ddr3X4_2Gb => "4DDR3_2GB",
        }
    }

    /// Whether this is DDR4 (as opposed to DDR3).
    pub fn is_ddr4(self) -> bool {
        matches!(
            self,
            DdrType::Ddr4X2_1Gb | DdrType::Ddr4X2_2Gb | DdrType::Ddr4X4_1Gb | DdrType::Ddr4X4_2Gb
        )
    }

    /// The DDR generation suffix used in hwsetting file names.
    ///
    /// This is the value `dynamicSwitchUsbHwDDR` returns.
    pub fn hwsetting_suffix(self) -> &'static str {
        if self.is_ddr4() {
            "2DDR4_4Gb_1600_B"
        } else {
            "2DDR3_4Gb_1600_B"
        }
    }

    /// The hwsetting file name for this configuration.
    ///
    /// Note the leading separator: the original builds
    /// `"\kylin_usb_hwsetting_" + suffix + ".bin"` and then joins it onto the
    /// tool directory.
    pub fn hwsetting_file(self) -> String {
        format!("kylin_usb_hwsetting_{}.bin", self.hwsetting_suffix())
    }

    /// Parse a `SYSTEM.ini` `DDR TYPE` value.
    ///
    /// Matching ignores ASCII case and surrounding whitespace, because the value
    /// is hand-editable in a shipped text file.
    pub fn from_label(s: &str) -> Option<Self> {
        let t = s.trim();
        Self::ALL.into_iter().find(|d| d.label().eq_ignore_ascii_case(t))
    }

    /// The index in the original's dropdown.
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|d| *d == self).unwrap_or(0)
    }

    /// A human-readable description for the UI.
    pub fn describe(self) -> String {
        let (gen, chips, size) = match self {
            DdrType::Ddr4X2_1Gb => ("DDR4", 2, "1GB"),
            DdrType::Ddr4X2_2Gb => ("DDR4", 2, "2GB"),
            DdrType::Ddr4X4_1Gb => ("DDR4", 4, "1GB"),
            DdrType::Ddr4X4_2Gb => ("DDR4", 4, "2GB"),
            DdrType::Ddr3X2_1Gb => ("DDR3", 2, "1GB"),
            DdrType::Ddr3X2_2Gb => ("DDR3", 2, "2GB"),
            DdrType::Ddr3X4_1Gb => ("DDR3", 4, "1GB"),
            DdrType::Ddr3X4_2Gb => ("DDR3", 4, "2GB"),
        };
        format!("{gen} ×{chips}  {size}")
    }
}

/// Where the DDR-specific hwsetting blobs live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwSettingSearch {
    /// The tool directory (where the original keeps its blobs).
    pub tool_dir: Option<PathBuf>,
    /// The image directory, which users often keep them in instead.
    pub image_dir: Option<PathBuf>,
}

impl Default for HwSettingSearch {
    fn default() -> Self {
        Self {
            tool_dir: None,
            image_dir: None,
        }
    }
}

impl HwSettingSearch {
    /// Directories to probe, most specific first.
    ///
    /// `hwsetting/` is checked ahead of the bare directory so the blobs can be
    /// kept in one tidy subfolder next to the executable instead of scattered
    /// across it -- which is also how `build.sh win` lays them out.
    pub fn dirs(&self) -> Vec<PathBuf> {
        let mut v = Vec::new();
        if let Some(d) = &self.image_dir {
            v.push(d.join("hwsetting"));
            v.push(d.clone());
            v.push(d.join("Tempfile"));
        }
        if let Some(d) = &self.tool_dir {
            v.push(d.join("hwsetting"));
            v.push(d.clone());
            v.push(d.join("Tempfile"));
        }
        v
    }

    /// Where the search would look and what it would accept there.
    ///
    /// "找不到 hwsetting 文件" is useless on its own: the user needs to know
    /// *where* to put the file. The UI shows this next to the failure.
    pub fn explain(&self, ddr: Option<DdrType>) -> String {
        let wanted = match ddr {
            Some(d) => format!("{} 或 usb_hwsetting.bin", d.hwsetting_file()),
            None => "usb_hwsetting.bin（或先选 DDR 类型）".to_string(),
        };
        let mut s = format!("需要：{wanted}\n已查找：");
        for d in self.dirs() {
            s.push_str(&format!("\n  {}", d.display()));
        }
        s
    }

    /// Find the blob for `ddr`, falling back to the generic `usb_hwsetting.bin`.
    ///
    /// The generic blob is a valid answer for boards whose DRAM matches whatever
    /// it was built for, and it is what the shipped `Tempfile` contains, so it is
    /// preferred over failing outright. [`Self::find_for`] reports which one was
    /// used so the caller can say so.
    pub fn find(&self, ddr: Option<DdrType>) -> Option<(PathBuf, HwSettingKind)> {
        // A specific DDR choice wins over the generic blob.
        if let Some(d) = ddr {
            let name = d.hwsetting_file();
            for dir in self.dirs() {
                let p = dir.join(&name);
                if p.is_file() {
                    return Some((p, HwSettingKind::DdrSpecific));
                }
            }
        }
        for dir in self.dirs() {
            let p = dir.join("usb_hwsetting.bin");
            if p.is_file() {
                return Some((p, HwSettingKind::Generic));
            }
        }
        None
    }

    /// The distinct DDR-specific blobs actually present, for the UI.
    ///
    /// Deduplicated **by file**, not by [`DdrType`]: the four DDR4 options all
    /// resolve to one blob, so keying on the type would report four copies of the
    /// same path. Each entry names the first option that reaches that file.
    pub fn available(&self) -> Vec<(DdrType, PathBuf)> {
        let mut out: Vec<(DdrType, PathBuf)> = Vec::new();
        for d in DdrType::ALL {
            let name = d.hwsetting_file();
            for dir in self.dirs() {
                let p = dir.join(&name);
                if !p.is_file() {
                    continue;
                }
                // `PathBuf` equality is textual, and every candidate here was
                // built from the same `dirs()` list, so this is exact.
                if !out.iter().any(|(_, seen)| *seen == p) {
                    out.push((d, p));
                }
                break;
            }
        }
        out
    }

    /// Whether the blob for a specific option can be found.
    ///
    /// Used by the UI to mark unusable entries rather than letting the user pick
    /// one and fail later.
    pub fn is_available(&self, ddr: DdrType) -> bool {
        let name = ddr.hwsetting_file();
        self.dirs().iter().any(|d| d.join(&name).is_file())
    }

    /// Whether any blob at all can be found.
    ///
    /// Counts DDR-specific blobs too. `find(None)` only looks for the generic
    /// blob, so using it alone would report "nothing available" on a directory
    /// that has exactly the DDR-specific files -- which is the normal case for
    /// the shipped `Tempfile`.
    pub fn any_available(&self) -> bool {
        self.find(None).is_some() || !self.available().is_empty()
    }
}

/// Which blob a lookup settled on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwSettingKind {
    /// `kylin_usb_hwsetting_<DDR>.bin` — matched the selected DRAM.
    DdrSpecific,
    /// `usb_hwsetting.bin` — the generic blob.
    Generic,
}

impl HwSettingKind {
    /// A short label for logs.
    pub fn label(self) -> &'static str {
        match self {
            HwSettingKind::DdrSpecific => "DDR 专用",
            HwSettingKind::Generic => "通用（usb_hwsetting.bin）",
        }
    }
}

/// Strip a directory prefix from a path, for display.
pub fn file_name_of(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropdown_order_matches_the_originals() {
        // Exactly the order `initialization_combobox` pushes them.
        let labels: Vec<&str> = DdrType::ALL.iter().map(|d| d.label()).collect();
        assert_eq!(
            labels,
            vec![
                "2DDR4_1GB",
                "2DDR4_2GB",
                "4DDR4_1GB",
                "4DDR4_2GB",
                "2DDR3_1GB",
                "2DDR3_2GB",
                "4DDR3_1GB",
                "4DDR3_2GB",
            ]
        );
        for (i, d) in DdrType::ALL.iter().enumerate() {
            assert_eq!(d.index(), i, "{} index", d.label());
        }
    }

    #[test]
    fn only_the_generation_changes_the_blob() {
        // `dynamicSwitchUsbHwDDR`: cases 0..3 -> DDR4 file, 4..7 -> DDR3 file.
        for d in DdrType::ALL {
            let expected = if d.index() < 4 {
                "kylin_usb_hwsetting_2DDR4_4Gb_1600_B.bin"
            } else {
                "kylin_usb_hwsetting_2DDR3_4Gb_1600_B.bin"
            };
            assert_eq!(d.hwsetting_file(), expected, "{}", d.label());
        }
        // The two shipped files are exactly the two distinct answers.
        let mut files: Vec<String> = DdrType::ALL.iter().map(|d| d.hwsetting_file()).collect();
        files.sort();
        files.dedup();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn ddr4_is_detected_from_the_index_range() {
        for d in DdrType::ALL {
            assert_eq!(d.is_ddr4(), d.index() < 4, "{}", d.label());
        }
    }

    #[test]
    fn labels_round_trip() {
        for d in DdrType::ALL {
            assert_eq!(DdrType::from_label(d.label()), Some(d));
        }
        // Case and whitespace come from a hand-editable ini file.
        assert_eq!(DdrType::from_label("  4ddr4_2gb "), Some(DdrType::Ddr4X4_2Gb));
        assert_eq!(DdrType::from_label("4DDR3_1GB"), Some(DdrType::Ddr3X4_1Gb));
        assert_eq!(DdrType::from_label("DDR4"), None);
        assert_eq!(DdrType::from_label(""), None);
    }

    #[test]
    fn the_shipped_system_ini_value_parses() {
        // The tool ships `DDR TYPE=4DDR4_2GB`.
        assert_eq!(
            DdrType::from_label("4DDR4_2GB"),
            Some(DdrType::Ddr4X4_2Gb)
        );
    }

    #[test]
    fn describe_mentions_generation_and_size() {
        assert_eq!(DdrType::Ddr4X4_2Gb.describe(), "DDR4 ×4  2GB");
        assert_eq!(DdrType::Ddr3X2_1Gb.describe(), "DDR3 ×2  1GB");
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let p = PathBuf::from(base).join(format!("rtd-ddr-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn a_ddr_specific_blob_wins_over_the_generic_one() {
        let dir = tmpdir("specific");
        std::fs::write(dir.join("usb_hwsetting.bin"), b"generic").unwrap();
        std::fs::write(
            dir.join("kylin_usb_hwsetting_2DDR4_4Gb_1600_B.bin"),
            b"ddr4",
        )
        .unwrap();

        let search = HwSettingSearch {
            tool_dir: Some(dir.clone()),
            image_dir: None,
        };

        let (p, kind) = search.find(Some(DdrType::Ddr4X2_1Gb)).unwrap();
        assert_eq!(kind, HwSettingKind::DdrSpecific);
        assert!(p.to_string_lossy().contains("2DDR4"));

        // A DDR3 request falls back, because only the DDR4 blob is present.
        let (p, kind) = search.find(Some(DdrType::Ddr3X2_1Gb)).unwrap();
        assert_eq!(kind, HwSettingKind::Generic);
        assert!(p.to_string_lossy().ends_with("usb_hwsetting.bin"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tempfile_subdirectory_is_also_searched() {
        let dir = tmpdir("tempfile");
        std::fs::create_dir_all(dir.join("Tempfile")).unwrap();
        std::fs::write(
            dir.join("Tempfile/kylin_usb_hwsetting_2DDR3_4Gb_1600_B.bin"),
            b"ddr3",
        )
        .unwrap();

        let search = HwSettingSearch {
            tool_dir: Some(dir.clone()),
            image_dir: None,
        };
        let (p, kind) = search.find(Some(DdrType::Ddr3X4_2Gb)).unwrap();
        assert_eq!(kind, HwSettingKind::DdrSpecific);
        assert!(p.to_string_lossy().contains("Tempfile"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn available_lists_only_distinct_present_blobs() {
        let dir = tmpdir("avail");
        std::fs::write(
            dir.join("kylin_usb_hwsetting_2DDR4_4Gb_1600_B.bin"),
            b"ddr4",
        )
        .unwrap();
        std::fs::write(
            dir.join("kylin_usb_hwsetting_2DDR3_4Gb_1600_B.bin"),
            b"ddr3",
        )
        .unwrap();

        let search = HwSettingSearch {
            tool_dir: Some(dir.clone()),
            image_dir: None,
        };
        let avail = search.available();
        // The four DDR4 options collapse onto one file, so each blob appears once.
        assert_eq!(avail.len(), 2, "{avail:?}");
        assert!(avail.iter().any(|(d, _)| d.is_ddr4()));
        assert!(avail.iter().any(|(d, _)| !d.is_ddr4()));
        // Every option is usable, because both files are present.
        for d in DdrType::ALL {
            assert!(search.is_available(d), "{} should resolve", d.label());
        }
        assert!(search.any_available());

        // A file that is not there reports unavailable.
        let empty = tmpdir("avail-empty");
        let none = HwSettingSearch {
            tool_dir: Some(empty.clone()),
            image_dir: None,
        };
        assert!(!none.is_available(DdrType::Ddr4X2_1Gb));
        assert!(none.available().is_empty());
        let _ = std::fs::remove_dir_all(&empty);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nothing_found_is_reported_as_none_not_a_panic() {
        let search = HwSettingSearch {
            tool_dir: Some(PathBuf::from("/nonexistent/rtd")),
            image_dir: None,
        };
        assert!(search.find(Some(DdrType::Ddr4X2_1Gb)).is_none());
        assert!(!search.any_available());
    }

    #[test]
    fn file_name_of_handles_a_bare_path() {
        assert_eq!(file_name_of(Path::new("/a/b/c.bin")), "c.bin");
        assert_eq!(file_name_of(Path::new("c.bin")), "c.bin");
    }
}
