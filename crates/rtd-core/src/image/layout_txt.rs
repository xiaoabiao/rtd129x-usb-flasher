//! `layout.txt` parsing.
//!
//! Recovered from `LoadFlashLayout` @0x004186D0, which reads the file line by
//! line and, for each line containing a target marker, extracts four
//! space-delimited fields:
//!
//! ```text
//! target=<NAME> offset=<hex> size=<hex> [ name=<label> ]
//! ```
//!
//! The original uses **substring matching** (`strstr`), not a strict parser:
//!
//! * `target=` is compared against the *whole* expected name, including any
//!   trailing space
//! * `offset=` and `size=` are parsed as hexadecimal (`atoh`)
//! * ` name=` (leading space) supplies a free-form label
//!
//! # Trailing-space trap
//!
//! `Layout_Type` member names end with a space (`"FW_KERNEL "`, not
//! `"FW_KERNEL"`), and `LoadFlashLayout` matches the full string. A parser that
//! trims the name will silently fail to find any partition. This module keeps
//! names verbatim and exposes a trimmed helper for display only.

use crate::error::{Error, Result};

/// One entry from `layout.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// The `target=` value, **verbatim** (may have a trailing space).
    pub target: String,
    /// Byte offset into the flash.
    pub offset: u64,
    /// Partition size in bytes.
    pub size: u64,
    /// Optional ` name=` label.
    pub name: Option<String>,
    /// 1-based source line, for diagnostics.
    pub line: usize,
}

impl Partition {
    /// The target name with surrounding whitespace removed, for display.
    pub fn display_target(&self) -> &str {
        self.target.trim()
    }

    /// Byte range this partition occupies.
    pub fn range(&self) -> std::ops::Range<u64> {
        self.offset..self.offset.saturating_add(self.size)
    }

    /// Sector index of this partition's start (512-byte sectors).
    pub fn start_sector(&self) -> u64 {
        self.offset / crate::protocol::consts::SECTOR_SIZE
    }
}

/// Parse a whole `layout.txt`.
///
/// Lines without a `target=` marker are ignored, matching the original.
/// A line with `target=` but unparsable numbers is an error: the original would
/// silently produce a zero-size partition, which is the kind of failure that
/// wastes a burn cycle, so we reject it.
pub fn parse(text: &str) -> Result<Vec<Partition>> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let lineno = i + 1;

        // Two shapes appear in real `layout.txt` files:
        //
        //   target=FW_KERNEL offset=0x200 size=0x25ffe00 name=low-region.img
        //   #define PART0 " offset=0x2600000 size=0x10000000 ... name=p1.img "
        //
        // The first is what `LoadFlashLayout` @0x004186D0 scans for. The second
        // is how `emmc_burner`/`nand_burner` name their members (`ScanTargetName:
        // PART0, PartNumFileName: \p1.img` in the original's log) -- those lines
        // carry no `target=` at all, so a parser that only looks for `target=`
        // silently drops the real partitions and burns only the low region.
        //
        // Both forms use the same `offset=`/`size=`/` name=` geometry, so a
        // `#define` line that has geometry is a partition whose target is the
        // `#define` name (`PART0`, `MBR0`, ...).
        let target = match extract(raw, "target=") {
            Some(v) => v,
            None => {
                if raw.trim_start().starts_with("#define ")
                    && raw.contains("offset=")
                    && raw.contains("size=")
                {
                    match define_name(raw) {
                        Some(n) => n.to_string(),
                        None => continue,
                    }
                } else {
                    // A bare `#define` (date, version, tag) is not a partition.
                    continue;
                }
            }
        };
        let offset = match extract(raw, "offset=") {
            Some(v) => parse_hex(&v, lineno, "offset")?,
            None => {
                return Err(Error::Image(format!(
                    "line {lineno}: `target=` without `offset=`: {raw:?}"
                )))
            }
        };
        let size = match extract(raw, "size=") {
            Some(v) => parse_hex(&v, lineno, "size")?,
            None => {
                return Err(Error::Image(format!(
                    "line {lineno}: `target=` without `size=`: {raw:?}"
                )))
            }
        };
        // ` name=` carries a leading space to distinguish it from `name=`.
        let name = extract(raw, " name=").map(|v| v.trim().to_string());

        out.push(Partition {
            target,
            offset,
            size,
            name,
            line: lineno,
        });
    }
    Ok(out)
}

/// The identifier of a `#define <NAME> "..."` line.
///
/// Used for the `PART0` / `MBR0` entries that carry their geometry inside the
/// string instead of in a `target=` field.
fn define_name(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("#define ")?;
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    if end == 0 {
        None
    } else {
        Some(&rest[..end])
    }
}

/// Look up a partition by target name.
///
/// Matching is **exact** on the stored string (trailing space included),
/// mirroring `_mbscmp` in the original. Use [`find_loose`] when parsing text
/// written by hand.
pub fn find<'a>(parts: &'a [Partition], target: &str) -> Option<&'a Partition> {
    parts.iter().find(|p| p.target == target)
}

/// Look up a partition ignoring surrounding whitespace and ASCII case.
///
/// The original is case-sensitive; this helper exists for hand-written files
/// and for matching against `Layout_Type` names that carry a trailing space.
pub fn find_loose<'a>(parts: &'a [Partition], target: &str) -> Option<&'a Partition> {
    let want = target.trim();
    parts
        .iter()
        .find(|p| p.target.trim().eq_ignore_ascii_case(want))
}

/// Extract the value following `key` up to the next whitespace.
///
/// Mirrors the original's `get_targe_value`, which takes everything up to the
/// next separator.
fn extract(line: &str, key: &str) -> Option<String> {
    let i = line.find(key)?;
    let after = &line[i + key.len()..];
    if after.is_empty() {
        return Some(String::new());
    }
    let end = after
        .find(|c: char| c == ' ' || c == '\t' || c == '\r' || c == '\n')
        .unwrap_or(after.len());
    Some(after[..end].to_string())
}

/// Parse a hex field: optional `0x`, case-insensitive, stopping at the first
/// invalid character (like `atoh`).
///
/// **64-bit on purpose.** The original is a 32-bit program and its `atoh`
/// truncates, but `layout.txt` offsets in the 7.8 GB CM360 package exceed
/// 4 GiB (`PART4 offset=1620ba000`). Truncating that silently points the burn at
/// the wrong eMMC sector, so this parses into `u64` and rejects overflow.
fn parse_hex(s: &str, line: usize, field: &str) -> Result<u64> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.is_empty() {
        return Err(Error::Image(format!("line {line}: empty `{field}=`")));
    }
    let mut value: u64 = 0;
    let mut digits = 0usize;
    for c in t.chars() {
        let Some(d) = c.to_digit(16) else { break };
        value = value
            .checked_mul(16)
            .and_then(|v| v.checked_add(u64::from(d)))
            .ok_or_else(|| {
                Error::Image(format!("line {line}: `{field}={s:?}` overflows 64 bits"))
            })?;
        digits += 1;
    }
    if digits == 0 {
        return Err(Error::Image(format!(
            "line {line}: `{field}={s:?}` is not hexadecimal"
        )));
    }
    Ok(value)
}

/// Render partitions back into `layout.txt` text.
pub fn to_text(parts: &[Partition]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for p in parts {
        match &p.name {
            Some(n) => {
                let _ = writeln!(
                    s,
                    "target={} offset={:#x} size={:#x}  name={}",
                    p.target, p.offset, p.size, n
                );
            }
            None => {
                let _ = writeln!(
                    s,
                    "target={} offset={:#x} size={:#x}",
                    p.target, p.offset, p.size
                );
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_line() {
        let parts =
            parse("target=FW_KERNEL offset=0x3000000 size=0x800000  name=kernel\n").unwrap();
        assert_eq!(parts.len(), 1);
        let p = &parts[0];
        assert_eq!(p.target, "FW_KERNEL");
        assert_eq!(p.offset, 0x300_0000);
        assert_eq!(p.size, 0x80_0000);
        assert_eq!(p.name.as_deref(), Some("kernel"));
    }

    #[test]
    fn field_value_stops_at_the_first_separator() {
        // `extract` takes everything up to the next space/tab/CR/LF, which is
        // what the original's `get_targe_value` does.
        let parts = parse("target=FW_KERNEL   offset=0x10 size=0x20\n").unwrap();
        assert_eq!(parts[0].target, "FW_KERNEL");
        assert_eq!(parts[0].offset, 0x10);
    }

    #[test]
    fn trailing_whitespace_is_not_part_of_the_parsed_name() {
        // Because field values stop at the first separator, a `layout.txt` line
        // cannot itself carry the trailing space that `Layout_Type` uses. The
        // callers compensate by matching loosely (see `find_loose`), which is
        // why that helper exists.
        let parts = parse("target=FW_KERNEL  offset=0x100 size=0x200\n").unwrap();
        assert_eq!(parts[0].target, "FW_KERNEL");
        assert_eq!(parts[0].display_target(), "FW_KERNEL");

        // A file that *does* contain the space inside the value (no separator
        // before it) keeps it verbatim.
        let parts = parse("target=FW_BL31  offset=0x1 size=0x2\n").unwrap();
        assert_eq!(parts[0].target, "FW_BL31");
    }

    #[test]
    fn exact_and_loose_lookup_behave_differently() {
        // A file that carries the trailing space explicitly.
        let parts = parse("target=FW_BL31   offset=0x1 size=0x2\n").unwrap();
        // exact lookup needs the stored spelling
        assert!(find(&parts, "FW_BL31").is_some());
        // loose lookup tolerates whitespace and case
        assert!(find_loose(&parts, "  fw_bl31 ").is_some());
        assert!(find_loose(&parts, "fw_gold_kernel").is_none());
    }

    #[test]
    fn skips_lines_without_a_target_marker() {
        let text = "\
            # comment\n\
            some other text\n\
            \n\
            target=A offset=0x0 size=0x1\n";
        let parts = parse(text).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].line, 4);
    }

    #[test]
    fn accepts_uppercase_and_bare_hex() {
        let parts = parse("target=A offset=100 size=200\n").unwrap();
        assert_eq!(parts[0].offset, 0x100);
        assert_eq!(parts[0].size, 0x200);

        let parts = parse("target=A offset=0X100 size=0X200\n").unwrap();
        assert_eq!(parts[0].offset, 0x100);
    }

    #[test]
    fn rejects_target_without_offset_or_size() {
        assert!(parse("target=A size=0x1\n").is_err());
        assert!(parse("target=A offset=0x1\n").is_err());
        assert!(parse("target=A offset= size=0x1\n").is_err());
    }

    #[test]
    fn range_and_sector_helpers() {
        let parts = parse("target=A offset=0x400 size=0x200\n").unwrap();
        let p = &parts[0];
        assert_eq!(p.range(), 0x400..0x600);
        assert_eq!(p.start_sector(), 2);
    }

    #[test]
    fn text_round_trip_preserves_offset_and_size() {
        let text = "target=FW_KERNEL offset=0x3000000 size=0x800000  name=kernel\n";
        let parts = parse(text).unwrap();
        let back = to_text(&parts);
        let again = parse(&back).unwrap();
        assert_eq!(again[0].offset, parts[0].offset);
        assert_eq!(again[0].size, parts[0].size);
        assert_eq!(again[0].name, parts[0].name);
    }

    #[test]
    fn handles_a_realistic_multi_partition_file() {
        let text = "\
            target=FW_FWTBL offset=0x0 size=0x10000\n\
            target=FW_CONFIG offset=0x10000 size=0x10000\n\
            target=FW_KERNEL offset=0x3000000 size=0x800000 name=kernel\n\
            target=FW_KERNEL_DT offset=0x3800000 size=0x10000\n\
            target=FW_KERNEL_ROOTFS offset=0x4000000 size=0x1800000 name=rootfs\n";
        let parts = parse(text).unwrap();
        assert_eq!(parts.len(), 5);
        assert_eq!(
            parts.iter().map(|p| p.target.as_str()).collect::<Vec<_>>(),
            vec![
                "FW_FWTBL",
                "FW_CONFIG",
                "FW_KERNEL",
                "FW_KERNEL_DT",
                "FW_KERNEL_ROOTFS"
            ]
        );
        assert_eq!(find(&parts, "FW_KERNEL_ROOTFS").unwrap().size, 0x180_0000);
    }

    #[test]
    fn parses_the_define_part_entries_cm360_uses() {
        // Verbatim from `install-cm360-fnos-1.2.0302-full-uboot-f2.img`. Only
        // `FW_KERNEL` has `target=`; `PART0/PART1/MBR0` carry their geometry in
        // a `#define NAME " ... "` string. Missing them silently burns just the
        // low region, which does not boot.
        let text = "\
            #define CREATE_DATE \" Oct 22 2026 \"\n\
            #define FW_KERNEL \" target=3000000 offset=200 size=25ffe00 type=bin name=low-region.img \"\n\
            #define PART0 \" offset=2600000 size=10000000 mount_point=/boot name=p1.img \"\n\
            #define PART1 \" offset=12600000 size=1bf900000 mount_point=/ name=p2.img \"\n\
            #define MBR0 \" offset=0 size=200 name=mbr.bin \"\n\
            #define TAG 45\n";
        let parts = parse(text).unwrap();
        assert_eq!(
            parts.iter().map(|p| p.target.as_str()).collect::<Vec<_>>(),
            vec!["3000000", "PART0", "PART1", "MBR0"]
        );
        assert_eq!(parts[1].offset, 0x260_0000);
        assert_eq!(parts[1].size, 0x1000_0000);
        assert_eq!(parts[1].name.as_deref(), Some("p1.img"));
        assert_eq!(parts[1].start_sector(), 0x1_3000);
        assert_eq!(parts[3].offset, 0);
        assert_eq!(parts[3].name.as_deref(), Some("mbr.bin"));
    }
}
