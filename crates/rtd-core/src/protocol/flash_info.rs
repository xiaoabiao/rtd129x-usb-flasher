//! `_FlashInfo` — the 64-byte geometry descriptor.
//!
//! Exact layout from the PDB (`_FlashInfo size=64 align=8`). Note that
//! `trans_size` is MSVC `long` = **4 bytes** on Win32, not 8, which is why
//! `write_special_count` follows it at +0x1C.
//!
//! ```text
//! +0x00  u8   flashType
//! +0x04  u32  nandSize
//! +0x08  u32  blockSize
//! +0x0C  u32  pageSize
//! +0x10  u8   eccBit
//! +0x14  u32  start_addr
//! +0x18  i32  trans_size              <- 4 bytes (MSVC long)
//! +0x1C  u32  write_special_count
//! +0x20  i64  cover_value             <- 8 bytes, naturally aligned
//! +0x28  u16  spare_value
//! +0x2C  u32  once_trans_max_size     <- 2-byte hole at +0x2A
//! +0x30  i32  secure_option
//! +0x34  i32  go_or_jump_opetion
//! +0x38  u32  read_data_range
//! +0x3C  u32  read_spare_count
//! ------------------------------------------------
//! total 64 bytes
//! ```

use super::consts::{self, SECTOR_SIZE};
use super::opcode::FlashType;

/// Flash geometry, mirroring `_FlashInfo` (64 bytes, align 8).
///
/// `repr(C)` is required: Rust's default layout reorders fields and would make
/// this 56 bytes. The wire format depends on MSVC's field order and padding.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashInfo {
    /// +0x00  0 = NAND, 1 = NOR, 2 = eMMC
    pub flash_type: u8,
    /// +0x04  NAND size in MiB
    pub nand_size: u32,
    /// +0x08  block size in KiB
    pub block_size: u32,
    /// +0x0C  page size in bytes
    pub page_size: u32,
    /// +0x10
    pub ecc_bit: u8,
    /// +0x14  first byte address
    pub start_addr: u32,
    /// +0x18  transfer size (MSVC `long`, 4 bytes)
    pub trans_size: i32,
    /// +0x1C
    pub write_special_count: u32,
    /// +0x20  passed to `WriteDevice` as a `long64`
    pub cover_value: i64,
    /// +0x28  spare / OOB value; when 0x79 the high byte carries remap index
    pub spare_value: u16,
    /// +0x2C  maximum size of one transfer
    pub once_trans_max_size: u32,
    /// +0x30
    pub secure_option: i32,
    /// +0x34  `go` / `jump` selection
    pub go_or_jump_option: i32,
    /// +0x38
    pub read_data_range: u32,
    /// +0x3C
    pub read_spare_count: u32,
}

impl Default for FlashInfo {
    fn default() -> Self {
        // Sensible eMMC defaults; the real tool always reads these from the UI.
        Self {
            flash_type: FlashType::Emmc as u8,
            nand_size: 0,
            block_size: 0,
            page_size: 0,
            ecc_bit: 0,
            start_addr: 0,
            // SYSTEM.ini `WRITE RANGE=256` (KiB) -- the value the tool actually
            // chunks on.
            trans_size: 0x4_0000,
            write_special_count: 0,
            cover_value: 0,
            spare_value: 0,
            // SYSTEM.ini `ONE WRITE SIZE=2` (MiB).
            once_trans_max_size: 0x20_0000,
            secure_option: 0,
            go_or_jump_option: 0,
            read_data_range: 0,
            read_spare_count: 0,
        }
    }
}

impl FlashInfo {
    /// Serialise into the 64-byte on-wire layout.
    pub fn encode(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0x00] = self.flash_type;
        b[0x04..0x08].copy_from_slice(&self.nand_size.to_le_bytes());
        b[0x08..0x0C].copy_from_slice(&self.block_size.to_le_bytes());
        b[0x0C..0x10].copy_from_slice(&self.page_size.to_le_bytes());
        b[0x10] = self.ecc_bit;
        b[0x14..0x18].copy_from_slice(&self.start_addr.to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&self.trans_size.to_le_bytes());
        b[0x1C..0x20].copy_from_slice(&self.write_special_count.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&self.cover_value.to_le_bytes());
        b[0x28..0x2A].copy_from_slice(&self.spare_value.to_le_bytes());
        b[0x2C..0x30].copy_from_slice(&self.once_trans_max_size.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&self.secure_option.to_le_bytes());
        b[0x34..0x38].copy_from_slice(&self.go_or_jump_option.to_le_bytes());
        b[0x38..0x3C].copy_from_slice(&self.read_data_range.to_le_bytes());
        b[0x3C..0x40].copy_from_slice(&self.read_spare_count.to_le_bytes());
        b
    }

    /// Parse the 64-byte layout back.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 64 {
            return None;
        }
        Some(Self {
            flash_type: b[0x00],
            nand_size: u32::from_le_bytes(b[0x04..0x08].try_into().ok()?),
            block_size: u32::from_le_bytes(b[0x08..0x0C].try_into().ok()?),
            page_size: u32::from_le_bytes(b[0x0C..0x10].try_into().ok()?),
            ecc_bit: b[0x10],
            start_addr: u32::from_le_bytes(b[0x14..0x18].try_into().ok()?),
            trans_size: i32::from_le_bytes(b[0x18..0x1C].try_into().ok()?),
            write_special_count: u32::from_le_bytes(b[0x1C..0x20].try_into().ok()?),
            cover_value: i64::from_le_bytes(b[0x20..0x28].try_into().ok()?),
            spare_value: u16::from_le_bytes(b[0x28..0x2A].try_into().ok()?),
            once_trans_max_size: u32::from_le_bytes(b[0x2C..0x30].try_into().ok()?),
            secure_option: i32::from_le_bytes(b[0x30..0x34].try_into().ok()?),
            go_or_jump_option: i32::from_le_bytes(b[0x34..0x38].try_into().ok()?),
            read_data_range: u32::from_le_bytes(b[0x38..0x3C].try_into().ok()?),
            read_spare_count: u32::from_le_bytes(b[0x3C..0x40].try_into().ok()?),
        })
    }

    /// The chunk size the tool actually uses for bulk writes.
    ///
    /// **This is `trans_size`, not `once_trans_max_size`.**
    /// `emmc_burner` @0x00407050 does `local_4c = param_3.trans_size` and passes
    /// that into `WriteDevice` as the per-chunk size. The historical debug log
    /// confirms it: 82 143 lines of `onceTransSize : 0x40000` (= 256 KiB), which
    /// is `SYSTEM.ini`'s `WRITE RANGE=256` (KiB). `once_trans_max_size`
    /// (`ONE WRITE SIZE=2`) is used elsewhere.
    ///
    /// The value is clamped to [`consts::MAX_USB_TRANSFER`] (256 KiB, the
    /// largest frame the tool ever emitted in the historical logs).
    pub fn effective_chunk(&self) -> usize {
        let want = if self.trans_size <= 0 {
            consts::MAX_USB_TRANSFER
        } else {
            self.trans_size as usize
        };
        want.clamp(1, consts::MAX_USB_TRANSFER)
    }

    /// The size of one "round": `once_trans_max_size` (`SYSTEM.ini`'s
    /// `ONE WRITE SIZE=2`, i.e. 2 MiB).
    ///
    /// `WriteDevice` @0x004057D0 sends a member as consecutive rounds of this
    /// size. Each round is its own transfer -- it restarts `iIndicator` at FIRST,
    /// advances the sector address by one round, and is answered by exactly one
    /// status. The historical log shows eight 256 KiB chunks sharing one address,
    /// then the next eight starting at `address + 0x1000`.
    ///
    /// Falls back to a multiple of the chunk when the field is unset, so the
    /// round is never *smaller* than a chunk.
    pub fn effective_once_max(&self) -> usize {
        let want = if self.once_trans_max_size == 0 {
            self.effective_chunk()
        } else {
            self.once_trans_max_size as usize
        };
        want.max(self.effective_chunk())
    }

    /// Sector index for a byte address.
    pub fn sector_of(byte_addr: u64) -> u64 {
        byte_addr / SECTOR_SIZE
    }

    /// Advance a sector index by a byte count, rounding up.
    ///
    /// This is the layout rule verified against the historical debug log:
    /// `next_lba = lba + ceil(size / 512)`.
    pub fn advance_sectors(lba: u64, bytes: usize) -> u64 {
        lba + (bytes as u64).div_ceil(SECTOR_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flash_info_size_is_exactly_64() {
        assert_eq!(FlashInfo::default().encode().len(), 64);
        // The MSVC struct size, from the PDB.
        assert_eq!(std::mem::size_of::<FlashInfo>(), 64);
    }

    #[test]
    fn field_offsets_match_the_pdb() {
        let fi = FlashInfo {
            flash_type: 2,
            nand_size: 0x1111_1111,
            block_size: 0x2222_2222,
            page_size: 0x3333_3333,
            ecc_bit: 0x44,
            start_addr: 0x5555_5555,
            trans_size: 0x6666_6666u32 as i32,
            write_special_count: 0x7777_7777,
            cover_value: -1,
            spare_value: 0x8888,
            once_trans_max_size: 0x9999_9999,
            secure_option: 1,
            go_or_jump_option: 2,
            read_data_range: 3,
            read_spare_count: 4,
        };
        let b = fi.encode();
        assert_eq!(b[0x00], 2, "flashType @0x00");
        assert_eq!(&b[0x04..0x08], &0x1111_1111u32.to_le_bytes(), "nandSize @0x04");
        assert_eq!(&b[0x08..0x0C], &0x2222_2222u32.to_le_bytes(), "blockSize @0x08");
        assert_eq!(&b[0x0C..0x10], &0x3333_3333u32.to_le_bytes(), "pageSize @0x0C");
        assert_eq!(b[0x10], 0x44, "eccBit @0x10");
        assert_eq!(&b[0x14..0x18], &0x5555_5555u32.to_le_bytes(), "start_addr @0x14");
        assert_eq!(
            &b[0x18..0x1C],
            &0x6666_6666u32.to_le_bytes(),
            "trans_size @0x18 is 4 bytes"
        );
        assert_eq!(
            &b[0x1C..0x20],
            &0x7777_7777u32.to_le_bytes(),
            "write_special_count @0x1C"
        );
        assert_eq!(&b[0x20..0x28], &(-1i64).to_le_bytes(), "cover_value @0x20");
        assert_eq!(&b[0x28..0x2A], &0x8888u16.to_le_bytes(), "spare_value @0x28");
        assert_eq!(&b[0x2A..0x2C], &[0, 0], "2-byte hole @0x2A");
        assert_eq!(
            &b[0x2C..0x30],
            &0x9999_9999u32.to_le_bytes(),
            "once_trans_max_size @0x2C"
        );
        assert_eq!(&b[0x30..0x34], &1i32.to_le_bytes(), "secure_option @0x30");
        assert_eq!(&b[0x38..0x3C], &3u32.to_le_bytes(), "read_data_range @0x38");
        assert_eq!(&b[0x3C..0x40], &4u32.to_le_bytes(), "read_spare_count @0x3C");
    }

    #[test]
    fn round_trips() {
        let fi = FlashInfo {
            flash_type: 2,
            start_addr: 0x150_0000,
            trans_size: 0x4_0000,
            once_trans_max_size: 0x20_0000,
            ..Default::default()
        };
        assert_eq!(FlashInfo::decode(&fi.encode()), Some(fi));
    }

    #[test]
    fn chunk_comes_from_trans_size_and_is_capped() {
        // The historical log shows 256 KiB chunks, which equals trans_size.
        let fi = FlashInfo {
            trans_size: 0x4_0000,
            ..Default::default()
        };
        assert_eq!(fi.effective_chunk(), 0x4_0000);
        assert_eq!(fi.effective_chunk(), consts::MAX_USB_TRANSFER);

        // A smaller trans_size is honoured.
        let fi = FlashInfo {
            trans_size: 0x1_0000,
            ..Default::default()
        };
        assert_eq!(fi.effective_chunk(), 0x1_0000);

        // Zero / negative falls back to the cap.
        for bad in [0i32, -1] {
            let fi = FlashInfo {
                trans_size: bad,
                ..Default::default()
            };
            assert_eq!(fi.effective_chunk(), consts::MAX_USB_TRANSFER);
        }

        // Anything larger is clamped to 256 KiB.
        let fi = FlashInfo {
            trans_size: 0x40_0000, // 4 MiB requested
            ..Default::default()
        };
        assert_eq!(fi.effective_chunk(), consts::MAX_USB_TRANSFER);

        // once_trans_max_size must NOT influence the chunk size.
        let fi = FlashInfo {
            trans_size: 0x1_0000,
            once_trans_max_size: 0x20_0000,
            ..Default::default()
        };
        assert_eq!(
            fi.effective_chunk(),
            0x1_0000,
            "chunking follows trans_size, not once_trans_max_size"
        );
    }

    #[test]
    fn sector_advance_matches_the_verified_layout() {
        // The exact chain recovered from the historical debug log.
        let mut lba = consts::lba::HW_SETTING;
        assert_eq!(lba, 256);
        lba = FlashInfo::advance_sectors(lba, 3200); // hw_setting.bin
        assert_eq!(lba, consts::lba::UBOOT, "uboot starts at 263");
        lba = FlashInfo::advance_sectors(lba, 604128); // uboot.bin
        assert_eq!(lba, consts::lba::FSBL, "fsbl starts at 1443");
        lba = FlashInfo::advance_sectors(lba, 72544); // fsbl.bin
        assert_eq!(lba, consts::lba::TEE, "tee starts at 1585");
    }

    #[test]
    fn sector_of_is_a_floor_division() {
        assert_eq!(FlashInfo::sector_of(0), 0);
        assert_eq!(FlashInfo::sector_of(511), 0);
        assert_eq!(FlashInfo::sector_of(512), 1);
        assert_eq!(FlashInfo::sector_of(0x150_0000), 0x150_0000 / 512);
    }
}
