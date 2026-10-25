//! `bootloader.tar` member identification and flash placement.
//!
//! `ReadBootloaderTarFile` @0x0041C1E0 extracts the tar and records, for each
//! member, its length and its **start sector** on the flash. The members are
//! laid out back-to-back starting at a known base, with the rule
//!
//! ```text
//! next_lba = lba + ceil(size / 512)
//! ```
//!
//! Verified against the tool's own debug log, which prints the start block of
//! each member:
//!
//! ```text
//! uboot hwsetting address icon[0] : start block : 256    <- hw_setting.bin  3200 B
//! boocode address icon[0] : start block 263              <- uboot.bin     604128 B
//! uboot FSBL address icon[0] : start block : 1443        <- fsbl.bin       72544 B
//! uboot tee_enc.bin address icon[0] : start block : 1585 <- tee.bin       507616 B
//! ```
//!
//! The five members the shipped tar contains are `bl31.bin`, `fsbl.bin`,
//! `hw_setting.bin`, `tee.bin` and `uboot.bin`. Only four of them occupy the
//! logged address chain; `bl31.bin` is placed separately (its length is carried
//! in `FW_Bl31_Len` / `Bl31_enc_Len`).

use crate::error::{Error, Result};
use crate::protocol::consts::{lba, SECTOR_SIZE};

/// A recognised bootloader member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Member {
    /// `hw_setting.bin` — the DRAM/hardware configuration blob.
    HwSetting,
    /// `uboot.bin` — the second-stage bootloader.
    Uboot,
    /// `fsbl.bin` — the first-stage bootloader.
    Fsbl,
    /// `tee.bin` — the trusted execution environment.
    Tee,
    /// `bl31.bin` — ARM Trusted Firmware BL31.
    Bl31,
}

impl Member {
    /// The exact tar entry name.
    pub fn file_name(self) -> &'static str {
        match self {
            Member::HwSetting => "hw_setting.bin",
            Member::Uboot => "uboot.bin",
            Member::Fsbl => "fsbl.bin",
            Member::Tee => "tee.bin",
            Member::Bl31 => "bl31.bin",
        }
    }

    /// The start sector recorded in the debug log, when the member has one.
    ///
    /// `bl31.bin` is not part of the back-to-back chain in the logged runs.
    pub fn logged_lba(self) -> Option<u64> {
        Some(match self {
            Member::HwSetting => lba::HW_SETTING,
            Member::Uboot => lba::UBOOT,
            Member::Fsbl => lba::FSBL,
            Member::Tee => lba::TEE,
            Member::Bl31 => return None,
        })
    }

    /// Identify a member from a tar entry name.
    ///
    /// Matching is on the basename and is case-insensitive, since tars produced
    /// on Windows occasionally carry a directory prefix or different case.
    pub fn from_file_name(name: &str) -> Option<Self> {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let lower = base.to_ascii_lowercase();
        Some(match lower.as_str() {
            "hw_setting.bin" => Member::HwSetting,
            "uboot.bin" => Member::Uboot,
            "fsbl.bin" => Member::Fsbl,
            "tee.bin" => Member::Tee,
            "bl31.bin" => Member::Bl31,
            _ => return None,
        })
    }

    /// The order in which the logged chain writes the members.
    ///
    /// `hw_setting` first at 256, then `uboot` (263), `fsbl` (1443), `tee` (1585).
    pub const CHAIN: [Member; 4] = [
        Member::HwSetting,
        Member::Uboot,
        Member::Fsbl,
        Member::Tee,
    ];
}

/// A member together with its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedMember {
    /// Which member this is.
    pub member: Member,
    /// Raw bytes as stored in the tar.
    pub data: Vec<u8>,
    /// Start sector, filled in by [`plan_chain`].
    pub lba: u64,
}

impl LoadedMember {
    /// Number of 512-byte sectors this member occupies.
    pub fn sectors(&self) -> u64 {
        sectors_for(self.data.len())
    }
}

/// Sectors required for `bytes`, rounding up.
pub fn sectors_for(bytes: usize) -> u64 {
    (bytes as u64).div_ceil(SECTOR_SIZE)
}

/// Assign start sectors to the chain members using the verified rule.
///
/// Members appearing in [`Member::CHAIN`] are placed back-to-back from
/// [`lba::HW_SETTING`]; any other member (i.e. `bl31.bin`) keeps `lba = 0` and
/// is left for the caller, matching the original's separate handling.
///
/// Returns the next free sector after the chain.
pub fn plan_chain(members: &mut [LoadedMember]) -> u64 {
    let mut cursor = lba::HW_SETTING;
    for want in Member::CHAIN {
        if let Some(m) = members.iter_mut().find(|m| m.member == want) {
            m.lba = cursor;
            cursor += m.sectors();
        }
    }
    cursor
}

/// Extract every recognised bootloader member from a tar archive.
pub fn read_tar(reader: impl std::io::Read) -> Result<Vec<LoadedMember>> {
    let mut ar = tar::Archive::new(reader);
    let mut out = Vec::new();
    for entry in ar.entries().map_err(|e| Error::Image(e.to_string()))? {
        let mut entry = entry.map_err(|e| Error::Image(e.to_string()))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| Error::Image(e.to_string()))?
            .to_string_lossy()
            .into_owned();
        let Some(member) = Member::from_file_name(&path) else {
            continue;
        };
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut data)?;
        out.push(LoadedMember {
            member,
            data,
            lba: 0,
        });
    }
    if out.is_empty() {
        return Err(Error::Image(
            "bootloader.tar contained no recognised members".into(),
        ));
    }
    Ok(out)
}

/// Read and plan a bootloader tar in one step.
pub fn load(path: &std::path::Path) -> Result<(Vec<LoadedMember>, u64)> {
    let f = std::fs::File::open(path)?;
    let mut members = read_tar(std::io::BufReader::new(f))?;
    let next = plan_chain(&mut members);
    members.sort_by_key(|m| (m.lba, m.member));
    Ok((members, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .join("fixtures/image")
            .join(name)
    }

    fn bootloader_tar() -> PathBuf {
        let p = fixture("bootloader.tar");
        if !p.exists() {
            panic!(
                "fixture {} missing.\n  \
                 cp \"<tool>/Tempfile/bootloader.tar\" fixtures/image/",
                p.display()
            );
        }
        p
    }

    #[test]
    fn sectors_round_up() {
        assert_eq!(sectors_for(0), 0);
        assert_eq!(sectors_for(1), 1);
        assert_eq!(sectors_for(512), 1);
        assert_eq!(sectors_for(513), 2);
        // The real members.
        assert_eq!(sectors_for(3200), 7); // 6.25 -> 7
        assert_eq!(sectors_for(604_128), 1180);
        assert_eq!(sectors_for(72_544), 142);
        assert_eq!(sectors_for(507_616), 992);
        assert_eq!(sectors_for(25_248), 50);
    }

    #[test]
    fn the_verified_chain_is_reproduced_exactly() {
        // The arithmetic that the debug log confirms.
        let mut cursor = lba::HW_SETTING;
        assert_eq!(cursor, 256);
        cursor += sectors_for(3200);
        assert_eq!(cursor, 263, "uboot starts at 263");
        cursor += sectors_for(604_128);
        assert_eq!(cursor, 1443, "fsbl starts at 1443");
        cursor += sectors_for(72_544);
        assert_eq!(cursor, 1585, "tee starts at 1585");
        cursor += sectors_for(507_616);
        assert_eq!(cursor, 2577, "end of chain");
    }

    #[test]
    fn plan_chain_assigns_the_logged_addresses() {
        // Sizes taken from the real bootloader.tar listing.
        let mut members = vec![
            LoadedMember {
                member: Member::Tee,
                data: vec![0; 507_616],
                lba: 0,
            },
            LoadedMember {
                member: Member::HwSetting,
                data: vec![0; 3200],
                lba: 0,
            },
            LoadedMember {
                member: Member::Uboot,
                data: vec![0; 604_128],
                lba: 0,
            },
            LoadedMember {
                member: Member::Fsbl,
                data: vec![0; 72_544],
                lba: 0,
            },
        ];
        let next = plan_chain(&mut members);
        let get = |m: Member| members.iter().find(|x| x.member == m).unwrap().lba;
        assert_eq!(get(Member::HwSetting), 256);
        assert_eq!(get(Member::Uboot), 263);
        assert_eq!(get(Member::Fsbl), 1443);
        assert_eq!(get(Member::Tee), 1585);
        assert_eq!(next, 2577);
    }

    #[test]
    fn bl31_is_not_part_of_the_chain() {
        let mut members = vec![
            LoadedMember {
                member: Member::Bl31,
                data: vec![0; 25_248],
                lba: 0,
            },
            LoadedMember {
                member: Member::HwSetting,
                data: vec![0; 3200],
                lba: 0,
            },
        ];
        plan_chain(&mut members);
        assert_eq!(
            members.iter().find(|m| m.member == Member::Bl31).unwrap().lba,
            0,
            "bl31 is handled separately by the original"
        );
        assert_eq!(Member::Bl31.logged_lba(), None);
    }

    #[test]
    fn member_names_are_matched_by_basename_and_case() {
        for (input, want) in [
            ("hw_setting.bin", Member::HwSetting),
            ("HW_SETTING.BIN", Member::HwSetting),
            ("dir/uboot.bin", Member::Uboot),
            ("dir\\fsbl.bin", Member::Fsbl),
            ("tee.bin", Member::Tee),
            ("bl31.bin", Member::Bl31),
        ] {
            assert_eq!(Member::from_file_name(input), Some(want), "{input}");
        }
        assert_eq!(Member::from_file_name("layout.txt"), None);
        assert_eq!(Member::from_file_name("install.img"), None);
    }

    #[test]
    fn real_bootloader_tar_loads_and_plans_correctly() {
        let path = bootloader_tar();
        let (members, next) = load(&path).unwrap();

        assert_eq!(members.len(), 5, "the shipped tar has 5 members");
        let names: Vec<&str> = members.iter().map(|m| m.member.file_name()).collect();
        for want in ["hw_setting.bin", "uboot.bin", "fsbl.bin", "tee.bin", "bl31.bin"] {
            assert!(names.contains(&want), "missing {want} in {names:?}");
        }

        let get = |m: Member| members.iter().find(|x| x.member == m).unwrap();
        // Payload sizes must match the tar listing exactly.
        assert_eq!(get(Member::HwSetting).data.len(), 3200);
        assert_eq!(get(Member::Uboot).data.len(), 604_128);
        assert_eq!(get(Member::Fsbl).data.len(), 72_544);
        assert_eq!(get(Member::Tee).data.len(), 507_616);
        assert_eq!(get(Member::Bl31).data.len(), 25_248);

        // And the planned addresses must be the logged ones.
        assert_eq!(get(Member::HwSetting).lba, 256);
        assert_eq!(get(Member::Uboot).lba, 263);
        assert_eq!(get(Member::Fsbl).lba, 1443);
        assert_eq!(get(Member::Tee).lba, 1585);
        assert_eq!(next, 2577);

        // Members are returned ordered by placement.
        let lbas: Vec<u64> = members.iter().map(|m| m.lba).collect();
        let mut sorted = lbas.clone();
        sorted.sort_unstable();
        assert_eq!(lbas, sorted);
    }

    #[test]
    fn missing_tar_is_an_error_not_a_silent_empty_list() {
        let p = Path::new("/nonexistent/bootloader.tar");
        assert!(load(p).is_err());
    }
}
