//! CSW — the 50-byte Command Status Wrapper the device sends back.
//!
//! Layout (all multi-byte fields little-endian):
//!
//! ```text
//! +0x00  4  dCSWSignature   0x53425355  'USBS'
//! +0x04  4  dCSWTag         0x12345678
//! +0x08  4  dCSWDataResidue
//! +0x0C  1  sense / channel byte
//! +0x0D  1  bCSWStatus      <- NOT offset 12, as real SCSI would have it
//! +0x0E 36  reserved
//! ------------------------------------------------
//! total 50 bytes
//! ```
//!
//! The status offset of 13 was proven from disassembly: the frame base is
//! `ebp-0x9c`, the code stores the BUSY sentinel with
//! `mov byte ptr [ebp-0x8f], 2`, and `0x9c - 0x8f == 13`. The read length is
//! `push 0x32` (50).

use super::consts::*;
use crate::error::CswStatus;

/// A decoded CSW frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Csw {
    pub signature: u32,
    pub tag: u32,
    pub data_residue: u32,
    /// The byte at offset 12, just before the status.
    pub sense: u8,
    /// The byte at offset 13.
    pub status_raw: u8,
}

impl Csw {
    /// Encoded length; matches the original's `push 0x32` read.
    pub const LEN: usize = CSW_LEN;

    /// Parse a raw 50-byte CSW.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::LEN {
            return None;
        }
        Some(Self {
            signature: u32::from_le_bytes(b[0x00..0x04].try_into().ok()?),
            tag: u32::from_le_bytes(b[CSW_TAG_OFFSET..CSW_TAG_OFFSET + 4].try_into().ok()?),
            data_residue: u32::from_le_bytes(b[0x08..0x0C].try_into().ok()?),
            sense: b[CSW_STATUS_OFFSET - 1],
            status_raw: b[CSW_STATUS_OFFSET],
        })
    }

    /// The status byte as an enum, if it is a known value.
    pub fn status(&self) -> Option<CswStatus> {
        CswStatus::from_u8(self.status_raw)
    }

    /// Verify signature and tag the way the original does:
    /// `cmp [frame],0x53425355` / `cmp [frame+4],0x12345678`.
    pub fn verify(&self) -> bool {
        self.signature == CSW_SIGNATURE && self.tag == CBW_TAG
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic CSW the way the device would.
    fn make(status: u8, sense: u8) -> [u8; CSW_LEN] {
        let mut b = [0u8; CSW_LEN];
        b[0x00..0x04].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        b[0x04..0x08].copy_from_slice(&CBW_TAG.to_le_bytes());
        b[0x0C] = sense;
        b[CSW_STATUS_OFFSET] = status;
        b
    }

    #[test]
    fn csw_is_exactly_50_bytes() {
        assert_eq!(CSW_LEN, 50);
        assert_eq!(Csw::LEN, 50);
    }

    #[test]
    fn status_is_read_from_offset_13() {
        // Put a decoy at offset 12 and the real status at 13.
        let raw = make(0, 0xAB);
        let c = Csw::decode(&raw).unwrap();
        assert_eq!(c.sense, 0xAB, "offset 12 is the sense byte");
        assert_eq!(c.status_raw, 0, "offset 13 is the status");
        assert!(!c.verify() == false);

        let raw = make(CswStatus::Busy as u8, 0x00);
        let c = Csw::decode(&raw).unwrap();
        assert_eq!(c.status(), Some(CswStatus::Busy));
    }

    #[test]
    fn signature_and_tag_verify() {
        let good = Csw::decode(&make(0, 0)).unwrap();
        assert!(good.verify());

        let mut bad = make(0, 0);
        bad[0] = 0xFF;
        assert!(!Csw::decode(&bad).unwrap().verify());

        let mut bad = make(0, 0);
        bad[4] = 0xFF;
        assert!(!Csw::decode(&bad).unwrap().verify());
    }

    #[test]
    fn all_known_statuses_decode() {
        for v in 0u8..=6 {
            let c = Csw::decode(&make(v, 0)).unwrap();
            assert_eq!(c.status().map(|s| s as u8), Some(v));
        }
        let c = Csw::decode(&make(9, 0)).unwrap();
        assert!(c.status().is_none(), "9 is not a known status");
    }

    #[test]
    fn rejects_truncated() {
        assert!(Csw::decode(&[0u8; 49]).is_none());
    }
}
