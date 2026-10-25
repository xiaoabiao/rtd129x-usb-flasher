//! CBW — the 43-byte Command Block Wrapper the host sends.
//!
//! Layout (all multi-byte fields little-endian):
//!
//! ```text
//! +0x00  4  dCBWSignature        0x43425355  'USBC'
//! +0x04  4  dCBWTag              0x12345678
//! +0x08  4  dCBWDataTransferLength
//! +0x0C  1  bmCBWFlags           0x80 = read, 0x00 = write
//! +0x0D  1  iIndicator           chunk position | mode flags
//! +0x0E  1  bCBWCBLength         28
//! +0x0F 28  CBWCB[]              see `CbwCb`
//! ------------------------------------------------
//! total 43 bytes (the original pushes 0x2B)
//! ````

use super::consts::*;
use super::opcode::Opcode;

/// The 28-byte command block (PDB struct `_CBWCB`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CbwCb {
    /// +0x00  top-level opcode
    pub opcode: u8,
    /// +0x01  sub-command / flags
    pub cmd_type: u8,
    /// +0x02  sector index for bootloader writes, raw byte address for hwsetting
    pub logical_block_address: u32,
    /// +0x06
    pub nand_ecc_bit: u8,
    /// +0x07  0 = NAND, 1 = NOR, 2 = eMMC
    pub flash_type: u8,
    /// +0x08
    pub page_size: u16,
    /// +0x0A
    pub block_size: u32,
    /// +0x0E
    pub nand_size: u32,
    /// +0x12  spare/OOB value; when 0x79 the high byte carries the remap index
    pub spare: u16,
    /// +0x14
    pub write_special_size: u32,
    /// +0x18  CRC32 of this chunk's payload
    pub crc32: u32,
}

impl CbwCb {
    /// Encoded length; matches `_CBWCB` exactly.
    pub const LEN: usize = CBW_CBWCB_LEN;

    /// Serialise into a 28-byte block.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0x00] = self.opcode;
        b[0x01] = self.cmd_type;
        b[0x02..0x06].copy_from_slice(&self.logical_block_address.to_le_bytes());
        b[0x06] = self.nand_ecc_bit;
        b[0x07] = self.flash_type;
        b[0x08..0x0A].copy_from_slice(&self.page_size.to_le_bytes());
        b[0x0A..0x0E].copy_from_slice(&self.block_size.to_le_bytes());
        b[0x0E..0x12].copy_from_slice(&self.nand_size.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&self.spare.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&self.write_special_size.to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&self.crc32.to_le_bytes());
        b
    }

    /// Parse a 28-byte block back.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::LEN {
            return None;
        }
        Some(Self {
            opcode: b[0x00],
            cmd_type: b[0x01],
            logical_block_address: u32::from_le_bytes(b[0x02..0x06].try_into().ok()?),
            nand_ecc_bit: b[0x06],
            flash_type: b[0x07],
            page_size: u16::from_le_bytes(b[0x08..0x0A].try_into().ok()?),
            block_size: u32::from_le_bytes(b[0x0A..0x0E].try_into().ok()?),
            nand_size: u32::from_le_bytes(b[0x0E..0x12].try_into().ok()?),
            spare: u16::from_le_bytes(b[0x12..0x14].try_into().ok()?),
            write_special_size: u32::from_le_bytes(b[0x14..0x18].try_into().ok()?),
            crc32: u32::from_le_bytes(b[0x18..0x1C].try_into().ok()?),
        })
    }

    /// Reinterpret the opcode byte through the enum.
    pub fn opcode(&self) -> Option<Opcode> {
        Opcode::from_u8(self.opcode)
    }
}

/// The 43-byte Command Block Wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cbw {
    pub signature: u32,
    pub tag: u32,
    pub data_transfer_length: u32,
    pub flags: u8,
    pub indicator: u8,
    pub cbwcb_length: u8,
    pub cbwcb: CbwCb,
}

impl Cbw {
    /// Encoded length; matches the original's `push 0x2B`.
    pub const LEN: usize = CBW_LEN;

    /// Build a frame with the signature, tag and CBWCB length pre-filled.
    #[allow(clippy::too_many_arguments)]
    /// A zero-payload status query.
    ///
    /// Safe in any device state: it asks for nothing and writes nothing, so it
    /// is what a connection probe should send.
    pub fn sense_query(fi: &crate::protocol::FlashInfo) -> Self {
        Self::new(
            crate::protocol::opcode::Opcode::Sense as u8,
            0,
            0,
            0,
            crate::protocol::indicator::LAST,
            crate::protocol::consts::CBW_FLAGS_READ,
            fi.flash_type,
            fi.page_size as u16,
            fi.block_size,
            fi.nand_size,
            fi.spare_value,
            fi.ecc_bit,
            crc32fast::hash(&[]),
        )
    }

    pub fn new(
        opcode: u8,
        cmd_type: u8,
        lba: u32,
        data_len: usize,
        indicator: u8,
        flags: u8,
        flash_type: u8,
        page_size: u16,
        block_size: u32,
        nand_size: u32,
        spare: u16,
        ecc_bit: u8,
        crc32: u32,
    ) -> Self {
        Self {
            signature: CBW_SIGNATURE,
            tag: CBW_TAG,
            data_transfer_length: data_len as u32,
            flags,
            indicator,
            cbwcb_length: CBW_CBWCB_LEN as u8,
            cbwcb: CbwCb {
                opcode,
                cmd_type,
                logical_block_address: lba,
                nand_ecc_bit: ecc_bit,
                flash_type,
                page_size,
                block_size,
                nand_size,
                spare,
                write_special_size: 0,
                crc32,
            },
        }
    }

    /// Serialise into a 43-byte frame.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0x00..0x04].copy_from_slice(&self.signature.to_le_bytes());
        b[0x04..0x08].copy_from_slice(&self.tag.to_le_bytes());
        b[0x08..0x0C].copy_from_slice(&self.data_transfer_length.to_le_bytes());
        b[0x0C] = self.flags;
        b[0x0D] = self.indicator;
        b[0x0E] = self.cbwcb_length;
        b[CBW_CBWCB_OFFSET..CBW_CBWCB_OFFSET + CbwCb::LEN]
            .copy_from_slice(&self.cbwcb.encode());
        b
    }

    /// Parse a 43-byte frame back (used by the test harness and log replay).
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::LEN {
            return None;
        }
        Some(Self {
            signature: u32::from_le_bytes(b[0x00..0x04].try_into().ok()?),
            tag: u32::from_le_bytes(b[0x04..0x08].try_into().ok()?),
            data_transfer_length: u32::from_le_bytes(b[0x08..0x0C].try_into().ok()?),
            flags: b[0x0C],
            indicator: b[0x0D],
            cbwcb_length: b[0x0E],
            cbwcb: CbwCb::decode(&b[CBW_CBWCB_OFFSET..])?,
        })
    }

    /// Whether this frame is well-formed enough to send.
    pub fn validate(&self) -> bool {
        self.signature == CBW_SIGNATURE
            && self.cbwcb_length as usize == CBW_CBWCB_LEN
            && Opcode::from_u8(self.cbwcb.opcode).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{cmd_type, FlashType};

    fn sample() -> Cbw {
        Cbw::new(
            Opcode::Write as u8,
            cmd_type::WRITE_CHUNK,
            0x0107,
            0x40000,
            indicator::FIRST,
            CBW_FLAGS_WRITE,
            FlashType::Emmc as u8,
            0,
            0,
            0,
            0,
            0,
            0xDEAD_BEEF,
        )
    }

    #[test]
    fn cbw_is_exactly_43_bytes() {
        let e = sample().encode();
        assert_eq!(e.len(), 43);
        assert_eq!(e.len(), CBW_LEN);
    }

    #[test]
    fn signature_and_tag_are_little_endian() {
        let e = sample().encode();
        // 'USBC' little-endian -> 55 53 42 43
        assert_eq!(&e[0x00..0x04], &[0x55, 0x53, 0x42, 0x43]);
        // 0x12345678 little-endian -> 78 56 34 12
        assert_eq!(&e[0x04..0x08], &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn field_offsets_match_the_disassembly() {
        let e = sample().encode();
        assert_eq!(&e[0x08..0x0C], &0x40000u32.to_le_bytes(), "data length");
        assert_eq!(e[0x0C], CBW_FLAGS_WRITE, "bmCBWFlags");
        assert_eq!(e[0x0D], indicator::FIRST, "iIndicator");
        assert_eq!(e[0x0E], 28, "bCBWCBLength");
        // CBWCB begins at 0x0F
        assert_eq!(e[0x0F], Opcode::Write as u8);
        assert_eq!(e[0x10], cmd_type::WRITE_CHUNK);
        assert_eq!(&e[0x11..0x15], &0x0107u32.to_le_bytes(), "LBA");
        assert_eq!(&e[0x0F + 0x18..0x0F + 0x1C], &0xDEAD_BEEFu32.to_le_bytes(), "CRC");
    }

    #[test]
    fn cbwcb_lays_out_like_the_pdb_struct() {
        let cb = CbwCb {
            opcode: 0xF4,
            cmd_type: 0x01,
            logical_block_address: 0x1122_3344,
            nand_ecc_bit: 0xAA,
            flash_type: 0x02,
            page_size: 0x0800,
            block_size: 0x0002_0000,
            nand_size: 0x1000,
            spare: 0x0079,
            write_special_size: 0x1234,
            crc32: 0xCAFE_BABE,
        };
        let b = cb.encode();
        assert_eq!(b.len(), 28);
        assert_eq!(b[0x00], 0xF4);
        assert_eq!(b[0x01], 0x01);
        assert_eq!(&b[0x02..0x06], &0x1122_3344u32.to_le_bytes());
        assert_eq!(b[0x06], 0xAA);
        assert_eq!(b[0x07], 0x02);
        assert_eq!(&b[0x08..0x0A], &0x0800u16.to_le_bytes());
        assert_eq!(&b[0x0A..0x0E], &0x0002_0000u32.to_le_bytes());
        assert_eq!(&b[0x0E..0x12], &0x1000u32.to_le_bytes());
        assert_eq!(&b[0x12..0x14], &0x0079u16.to_le_bytes());
        assert_eq!(&b[0x14..0x18], &0x1234u32.to_le_bytes());
        assert_eq!(&b[0x18..0x1C], &0xCAFE_BABEu32.to_le_bytes());
    }

    #[test]
    fn round_trips() {
        let c = sample();
        assert_eq!(Cbw::decode(&c.encode()), Some(c));
        assert!(c.validate());
    }

    #[test]
    fn rejects_bad_frames() {
        let mut e = sample().encode();
        e[0] = 0x00; // corrupt the signature
        let d = Cbw::decode(&e).unwrap();
        assert!(!d.validate());
        // truncated input
        assert_eq!(Cbw::decode(&e[..42]), None);
    }
}
