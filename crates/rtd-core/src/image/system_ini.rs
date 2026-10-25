//! `SYSTEM.ini` and `img.ini` handling.
//!
//! The tool's configuration is plain INI. Two files matter:
//!
//! * `SYSTEM.ini` — flash geometry, burn options, image path
//! * `image/img.ini` — display control for the GUI
//!
//! # Encoding
//!
//! The shipped files are Windows ANSI. On a Chinese Windows install that is
//! **GBK/CP936**, so a naive UTF-8 read turns paths and labels into mojibake
//! (the tool's own `IMAGE PATH` contains a `W:\w2\...` path, and comments may
//! contain Chinese). We decode GBK first and fall back to UTF-8 when the bytes
//! are not valid GBK.
//!
//! # `SYSTEM.ini` sections
//!
//! ```text
//! [NAND FLASH TYPE]     NAME, BLOCK SIZE, NAND SIZE, PAGE SIZE, ECC BIT, FLASH TYPE
//! [MULTI FLASH TYPE]    FLASH COMBO TYPE, FLASH TOTAL SIZE, DDR TYPE
//! [INFORMATION]         ONE WRITE SIZE, WRITE RANGE, IMAGE PATH
//! [SYSTEM]              SINGLE MODE, BURN FACTORY, BURN SE STORAGE, ENCRYPTION KEY,
//!                       ONLY UPGRADE LAYOUT FIRMWARE, ONLY UPGRADE SECURE FIRMWARE,
//!                       ONLY BURN EFUSE, AUTO BURN, NF WRITER SKIP, COMPARE DATA,
//!                       NAS ENABLE, LK ENABLE, MAX USB CONNECTION, SAVE LOG
//! [1195_SYSTEM]         GO DDR
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{Error, Result};

/// A parsed INI file: section -> key -> value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ini {
    sections: BTreeMap<String, BTreeMap<String, String>>,
}

impl Ini {
    /// Parse INI text.
    ///
    /// Section headers are `[NAME]`; entries are `KEY=VALUE`. Keys and values
    /// keep their original case but are matched case-insensitively. `;` and `#`
    /// start a comment.
    pub fn parse(text: &str) -> Self {
        let mut ini = Ini::default();
        let mut cur = String::new();
        ini.sections.entry(cur.clone()).or_default();

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix('[') {
                if let Some(end) = rest.find(']') {
                    cur = rest[..end].trim().to_string();
                    ini.sections.entry(cur.clone()).or_default();
                    continue;
                }
            }
            if let Some(eq) = line.find('=') {
                let key = line[..eq].trim().to_string();
                let val = line[eq + 1..].trim().to_string();
                ini.sections
                    .entry(cur.clone())
                    .or_default()
                    .insert(key, val);
            }
        }
        ini
    }

    /// Read and decode a file from disk.
    pub fn from_path(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        Ok(Self::parse(&decode_ansi(&bytes)))
    }

    /// Look up a key in a section, case-insensitively.
    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        let s = self
            .sections
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(section))?
            .1;
        s.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// Look up a key, trim it, and treat the empty string as absent.
    pub fn get_nonempty(&self, section: &str, key: &str) -> Option<&str> {
        self.get(section, key).map(str::trim).filter(|v| !v.is_empty())
    }

    /// Look up an integer key.
    ///
    /// `SYSTEM.ini` values are **decimal** (`WRITE RANGE=256`,
    /// `MAX USB CONNECTION=8`); the original reads them with `atoi`. A `0x`
    /// prefix is also accepted for hand-edited files. Bare hex is *not*
    /// accepted, because `abc` would otherwise silently mean 0xABC.
    pub fn get_u32(&self, section: &str, key: &str) -> Result<Option<u32>> {
        match self.get_nonempty(section, key) {
            None => Ok(None),
            Some(v) => parse_int(v)
                .map(Some)
                .ok_or_else(|| Error::Image(format!("[{section}] {key}={v:?} is not an integer"))),
        }
    }

    /// Look up a boolean key.
    ///
    /// The tool writes `0` / `1`; `y`/`n`, `true`/`false` and `yes`/`no` are
    /// accepted too, since factory `.config` files use `y`.
    pub fn get_bool(&self, section: &str, key: &str) -> Result<Option<bool>> {
        match self.get_nonempty(section, key) {
            None => Ok(None),
            Some(v) => match v.to_ascii_lowercase().as_str() {
                "1" | "y" | "yes" | "true" | "on" => Ok(Some(true)),
                "0" | "n" | "no" | "false" | "off" => Ok(Some(false)),
                other => Err(Error::Image(format!(
                    "[{section}] {key}={other:?} is not a boolean"
                ))),
            },
        }
    }

    /// All section names, in sorted order.
    pub fn sections(&self) -> Vec<&str> {
        self.sections
            .iter()
            .filter(|(_, m)| !m.is_empty())
            .map(|(k, _)| k.as_str())
            .collect()
    }
}

/// Decode Windows ANSI bytes, preferring GBK, falling back to UTF-8 and then
/// to a lossy UTF-8 pass.
pub fn decode_ansi(bytes: &[u8]) -> String {
    // A UTF-8 BOM is unambiguous.
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    // GBK first: the shipped files are CP936.
    let (gbk, _, gbk_had_errors) = encoding_rs::GBK.decode(bytes);
    if !gbk_had_errors {
        return gbk.into_owned();
    }
    // Fall back to UTF-8 if the bytes are valid UTF-8.
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    // Last resort: lossy GBK, which never fails.
    let (s, _, _) = encoding_rs::GBK.decode(bytes);
    s.into_owned()
}

fn parse_int(v: &str) -> Option<u32> {
    let t = v.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u32::from_str_radix(h, 16).ok();
    }
    t.parse::<u32>().ok()
}

// ---------------------------------------------------------------------------
// Typed views
// ---------------------------------------------------------------------------

/// Flash geometry as configured in `SYSTEM.ini`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemIni {
    /// `[MULTI FLASH TYPE] FLASH COMBO TYPE` — e.g. `EMMC`.
    pub flash_combo_type: Option<String>,
    /// `[NAND FLASH TYPE] FLASH TYPE` — 0 NAND, 1 NOR, 2 eMMC.
    pub flash_type: Option<u8>,
    /// `[MULTI FLASH TYPE] FLASH TOTAL SIZE`.
    pub flash_total_size: Option<u32>,
    /// `[MULTI FLASH TYPE] DDR TYPE` — e.g. `4DDR4_2GB`.
    pub ddr_type: Option<String>,
    /// `[NAND FLASH TYPE] NAME`.
    pub nand_name: Option<String>,
    /// `[NAND FLASH TYPE] BLOCK SIZE` (KiB for NAND).
    pub block_size: Option<u32>,
    /// `[NAND FLASH TYPE] NAND SIZE` (MiB).
    pub nand_size: Option<u32>,
    /// `[NAND FLASH TYPE] PAGE SIZE`.
    pub page_size: Option<u32>,
    /// `[NAND FLASH TYPE] ECC BIT`.
    pub ecc_bit: Option<u8>,

    /// `[INFORMATION] ONE WRITE SIZE` (MiB) -> `once_trans_max_size`.
    pub one_write_size: Option<u32>,
    /// `[INFORMATION] WRITE RANGE` (KiB) -> `trans_size`.
    pub write_range: Option<u32>,
    /// `[INFORMATION] IMAGE PATH`.
    pub image_path: Option<String>,

    /// `[SYSTEM] SINGLE MODE`.
    pub single_mode: Option<bool>,
    /// `[SYSTEM] BURN FACTORY`.
    pub burn_factory: Option<bool>,
    /// `[SYSTEM] BURN SE STORAGE`.
    pub burn_se_storage: Option<bool>,
    /// `[SYSTEM] ENCRYPTION KEY`.
    pub encryption_key: Option<bool>,
    /// `[SYSTEM] ONLY UPGRADE LAYOUT FIRMWARE`.
    pub only_upgrade_layout_firmware: Option<bool>,
    /// `[SYSTEM] ONLY UPGRADE SECURE FIRMWARE`.
    pub only_upgrade_secure_firmware: Option<bool>,
    /// `[SYSTEM] ONLY BURN EFUSE`.
    pub only_burn_efuse: Option<bool>,
    /// `[SYSTEM] AUTO BURN`.
    pub auto_burn: Option<bool>,
    /// `[SYSTEM] NF WRITER SKIP`.
    pub nf_writer_skip: Option<bool>,
    /// `[SYSTEM] COMPARE DATA`.
    pub compare_data: Option<bool>,
    /// `[SYSTEM] NAS ENABLE`.
    pub nas_enable: Option<bool>,
    /// `[SYSTEM] LK ENABLE`.
    pub lk_enable: Option<bool>,
    /// `[SYSTEM] MAX USB CONNECTION` (the tool ships 8).
    pub max_usb_connection: Option<u32>,
    /// `[SYSTEM] SAVE LOG`.
    pub save_log: Option<bool>,

    /// `[1195_SYSTEM] GO DDR`.
    pub go_ddr: Option<bool>,
}

const SEC_NAND: &str = "NAND FLASH TYPE";
const SEC_MULTI: &str = "MULTI FLASH TYPE";
const SEC_INFO: &str = "INFORMATION";
const SEC_SYSTEM: &str = "SYSTEM";
const SEC_1195: &str = "1195_SYSTEM";

impl SystemIni {
    /// Project a parsed INI into the typed view.
    pub fn from_ini(ini: &Ini) -> Result<Self> {
        let b = |sec: &str, k: &str| ini.get_bool(sec, k);
        let u = |sec: &str, k: &str| ini.get_u32(sec, k);
        let s = |sec: &str, k: &str| {
            ini.get_nonempty(sec, k).map(|v| v.to_string())
        };

        Ok(Self {
            flash_combo_type: s(SEC_MULTI, "FLASH COMBO TYPE"),
            flash_type: u(SEC_NAND, "FLASH TYPE")?.map(|v| v as u8),
            flash_total_size: u(SEC_MULTI, "FLASH TOTAL SIZE")?,
            ddr_type: s(SEC_MULTI, "DDR TYPE"),
            nand_name: s(SEC_NAND, "NAME"),
            block_size: u(SEC_NAND, "BLOCK SIZE")?,
            nand_size: u(SEC_NAND, "NAND SIZE")?,
            page_size: u(SEC_NAND, "PAGE SIZE")?,
            ecc_bit: u(SEC_NAND, "ECC BIT")?.map(|v| v as u8),

            one_write_size: u(SEC_INFO, "ONE WRITE SIZE")?,
            write_range: u(SEC_INFO, "WRITE RANGE")?,
            image_path: s(SEC_INFO, "IMAGE PATH"),

            single_mode: b(SEC_SYSTEM, "SINGLE MODE")?,
            burn_factory: b(SEC_SYSTEM, "BURN FACTORY")?,
            burn_se_storage: b(SEC_SYSTEM, "BURN SE STORAGE")?,
            encryption_key: b(SEC_SYSTEM, "ENCRYPTION KEY")?,
            only_upgrade_layout_firmware: b(SEC_SYSTEM, "ONLY UPGRADE LAYOUT FIRMWARE")?,
            only_upgrade_secure_firmware: b(SEC_SYSTEM, "ONLY UPGRADE SECURE FIRMWARE")?,
            only_burn_efuse: b(SEC_SYSTEM, "ONLY BURN EFUSE")?,
            auto_burn: b(SEC_SYSTEM, "AUTO BURN")?,
            nf_writer_skip: b(SEC_SYSTEM, "NF WRITER SKIP")?,
            compare_data: b(SEC_SYSTEM, "COMPARE DATA")?,
            nas_enable: b(SEC_SYSTEM, "NAS ENABLE")?,
            lk_enable: b(SEC_SYSTEM, "LK ENABLE")?,
            max_usb_connection: u(SEC_SYSTEM, "MAX USB CONNECTION")?,
            save_log: b(SEC_SYSTEM, "SAVE LOG")?,

            go_ddr: b(SEC_1195, "GO DDR")?,
        })
    }

    /// Read `SYSTEM.ini` from disk.
    pub fn from_path(path: &Path) -> Result<Self> {
        Self::from_ini(&Ini::from_path(path)?)
    }

    /// Build the flash geometry the transport needs.
    ///
    /// `ONE WRITE SIZE` and `WRITE RANGE` are in **MiB** and **KiB** respectively
    /// (the tool's own log shows 2 and 256, producing a 2 MiB request that is
    /// then clamped to the 256 KiB wire limit).
    pub fn flash_info(&self) -> crate::protocol::FlashInfo {
        let fi = crate::protocol::FlashInfo {
            flash_type: self.flash_type.unwrap_or(2),
            nand_size: self.nand_size.unwrap_or(0),
            block_size: self.block_size.unwrap_or(0),
            page_size: self.page_size.unwrap_or(0),
            ecc_bit: self.ecc_bit.unwrap_or(0),
            trans_size: self.write_range.map(|kib| kib as i32 * 1024).unwrap_or(0),
            once_trans_max_size: self.one_write_size.map(|mib| mib * 1024 * 1024).unwrap_or(0),
            secure_option: self.encryption_key.unwrap_or(false) as i32,
            ..Default::default()
        };
        fi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real `SYSTEM.ini` shipped with the tool.
    const REAL: &str = "\
[NAND FLASH TYPE]\n\
NAME=\n\
BLOCK SIZE=\n\
NAND SIZE=\n\
PAGE SIZE=\n\
ECC BIT=\n\
FLASH TYPE=2\n\
[MULTI FLASH TYPE]\n\
FLASH COMBO TYPE=EMMC\n\
FLASH TOTAL SIZE=\n\
DDR TYPE=4DDR4_2GB\n\
[INFORMATION]\n\
ONE WRITE SIZE=2\n\
WRITE RANGE=256\n\
IMAGE PATH=W:\\w2\\android\\BPI-1296-Android7\\Openwrt\\bin\\rtd1295-glibc\\install.img\n\
[SYSTEM]\n\
SINGLE MODE=0\n\
BURN FACTORY=0\n\
BURN SE STORAGE=0\n\
ENCRYPTION KEY=0\n\
ONLY UPGRADE LAYOUT FIRMWARE=0\n\
ONLY UPGRADE SECURE FIRMWARE=0\n\
ONLY BURN EFUSE=0\n\
AUTO BURN=0\n\
NF WRITER SKIP=0\n\
COMPARE DATA=0\n\
NAS ENABLE=0\n\
LK ENABLE=1\n\
MAX USB CONNECTION=8\n\
SAVE LOG=1\n\
[1195_SYSTEM]\n\
GO DDR=0\n";

    #[test]
    fn parses_the_real_system_ini() {
        let s = SystemIni::from_ini(&Ini::parse(REAL)).unwrap();
        assert_eq!(s.flash_type, Some(2));
        assert_eq!(s.flash_combo_type.as_deref(), Some("EMMC"));
        assert_eq!(s.ddr_type.as_deref(), Some("4DDR4_2GB"));
        assert_eq!(s.one_write_size, Some(2));
        assert_eq!(s.write_range, Some(256));
        assert_eq!(s.max_usb_connection, Some(8));
        assert_eq!(s.lk_enable, Some(true));
        assert_eq!(s.save_log, Some(true));
        // the ones that matter for the eMMC path
        assert_eq!(s.burn_factory, Some(false));
        assert_eq!(s.burn_se_storage, Some(false));
        assert_eq!(s.only_burn_efuse, Some(false));
        assert_eq!(s.encryption_key, Some(false));
    }

    #[test]
    fn empty_values_become_none_not_empty_strings() {
        let s = SystemIni::from_ini(&Ini::parse(REAL)).unwrap();
        assert_eq!(s.nand_name, None);
        assert_eq!(s.block_size, None);
        assert_eq!(s.nand_size, None);
        assert_eq!(s.page_size, None);
        assert_eq!(s.ecc_bit, None);
        assert_eq!(s.flash_total_size, None);
    }

    #[test]
    fn windows_paths_survive_intact() {
        let s = SystemIni::from_ini(&Ini::parse(REAL)).unwrap();
        assert_eq!(
            s.image_path.as_deref(),
            Some("W:\\w2\\android\\BPI-1296-Android7\\Openwrt\\bin\\rtd1295-glibc\\install.img")
        );
    }

    #[test]
    fn write_range_and_one_write_size_map_to_the_right_fields() {
        let s = SystemIni::from_ini(&Ini::parse(REAL)).unwrap();
        let fi = s.flash_info();
        // WRITE RANGE=256 KiB -> trans_size, which is what chunking uses
        assert_eq!(fi.trans_size, 256 * 1024);
        // ONE WRITE SIZE=2 MiB -> once_trans_max_size
        assert_eq!(fi.once_trans_max_size, 2 * 1024 * 1024);
        // and the effective chunk is clamped to the 256 KiB wire limit
        assert_eq!(fi.effective_chunk(), 256 * 1024);
        assert_eq!(fi.flash_type, 2);
    }

    #[test]
    fn section_and_key_matching_is_case_insensitive() {
        let ini = Ini::parse("[system]\nLK ENABLE=1\n");
        assert_eq!(ini.get("SYSTEM", "lk enable"), Some("1"));
        assert_eq!(ini.get("System", "LK ENABLE"), Some("1"));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let ini = Ini::parse("; comment\n# also\n\n[A]\nk=v\n");
        assert_eq!(ini.get("A", "k"), Some("v"));
    }

    #[test]
    fn booleans_accept_the_factory_spellings() {
        let ini = Ini::parse("[A]\na=y\nb=n\nc=true\nd=no\ne=1\nf=0\n");
        assert_eq!(ini.get_bool("A", "a").unwrap(), Some(true));
        assert_eq!(ini.get_bool("A", "b").unwrap(), Some(false));
        assert_eq!(ini.get_bool("A", "c").unwrap(), Some(true));
        assert_eq!(ini.get_bool("A", "d").unwrap(), Some(false));
        assert_eq!(ini.get_bool("A", "e").unwrap(), Some(true));
        assert_eq!(ini.get_bool("A", "f").unwrap(), Some(false));
        assert!(ini.get_bool("A", "missing").unwrap().is_none());
        assert!(Ini::parse("[A]\nx=maybe\n").get_bool("A", "x").is_err());
    }

    #[test]
    fn integers_are_decimal_with_an_optional_0x_prefix() {
        let ini = Ini::parse("[A]\na=256\nb=0x100\nc=0X100\n");
        assert_eq!(ini.get_u32("A", "a").unwrap(), Some(256));
        assert_eq!(ini.get_u32("A", "b").unwrap(), Some(256));
        assert_eq!(ini.get_u32("A", "c").unwrap(), Some(256));

        // Bare hex must NOT be accepted: otherwise `abc` would silently become
        // 0xABC. This mirrors the original's `atoi`-style decimal reading.
        assert!(
            Ini::parse("[A]\nz=abc\n").get_u32("A", "z").is_err(),
            "`abc` must not be read as hex"
        );
        assert!(Ini::parse("[A]\nz=100abc\n").get_u32("A", "z").is_err());
        assert!(Ini::parse("[A]\nz=-1\n").get_u32("A", "z").is_err());
    }

    #[test]
    fn the_write_range_from_the_real_ini_is_256_not_0x256() {
        // `256` is decimal; a bare-hex parser would have produced 0x256 = 598.
        let s = SystemIni::from_ini(&Ini::parse(REAL)).unwrap();
        assert_eq!(s.write_range, Some(256));
        assert_eq!(s.flash_info().trans_size, 256 * 1024);
    }

    #[test]
    fn gbk_bytes_decode_without_mojibake() {
        // "中文路径" in GBK, preceded by an ASCII key.
        let gbk = b"[A]\npath=C:\\\xd6\xd0\xce\xc4\n";
        let text = decode_ansi(gbk);
        assert!(text.contains("中文"), "got {text:?}");
        let ini = Ini::parse(&text);
        assert!(ini.get("A", "path").unwrap().contains("中文"));
    }

    #[test]
    fn utf8_with_bom_is_decoded() {
        let bytes = b"\xEF\xBB\xBF[A]\nk=v\n";
        let text = decode_ansi(bytes);
        assert!(!text.starts_with('\u{feff}'), "BOM should be stripped");
        assert_eq!(Ini::parse(&text).get("A", "k"), Some("v"));
    }

    #[test]
    fn plain_ascii_is_unchanged() {
        let bytes = b"[A]\nk=plain ascii\n";
        assert_eq!(decode_ansi(bytes), "[A]\nk=plain ascii\n");
    }

    #[test]
    fn a_minimal_ini_parses_without_errors() {
        let s = SystemIni::from_ini(&Ini::parse("[SYSTEM]\nLK ENABLE=1\n")).unwrap();
        assert_eq!(s.lk_enable, Some(true));
        assert_eq!(s.flash_type, None);
        // defaults are applied by flash_info, not by the parser
        assert_eq!(s.flash_info().flash_type, 2);
    }
}
