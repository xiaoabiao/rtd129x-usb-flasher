//! High-level hwsetting blob handling: decrypt, split instructions from the
//! trailer, edit, re-encrypt.
//!
//! # Blob layout
//!
//! ```text
//! [ instructions ]  flat little-endian u32 stream (w/p/n/m)
//! [ 0xFFFFFFFF ]    terminator
//! [ trailer ]       16-byte header + a small zero-padded field + 32-byte MAC
//! ```
//!
//! The trailer is preserved **verbatim**. Its MAC algorithm was not recovered
//! (it is not MD5 or SHA over any obvious range), so regenerating it is out of
//! scope; keeping an existing trailer is the supported path. This is exactly
//! what was agreed for this project: *reuse the existing trailer to sidestep the
//! MAC*.
//!
//! The 16-byte header is identical in all three shipped blobs:
//!
//! ```text
//! efabcdaa 13572468 a1b2c3d4 9092baba
//! ```
//!
//! Note bytes `4..12` equal the AES key's bytes `4..12`, and the first three
//! bytes look like a permutation of the key's first three -- suggestive of a
//! key-check tag, but not proven.

pub mod atoh;
pub mod crypto;
pub mod op;

use crate::error::{Error, Result};
use crate::hwconfig::crypto::HwSettingCipher;
use crate::hwconfig::op::Op;

/// The header every shipped trailer starts with.
pub const TRAILER_HEADER: [u8; 16] = [
    0xef, 0xab, 0xcd, 0xaa, 0x13, 0x57, 0x24, 0x68, 0xa1, 0xb2, 0xc3, 0xd4, 0x90, 0x92, 0xba,
    0xba,
];

/// Size of the trailer's fixed header.
pub const TRAILER_HEADER_LEN: usize = 16;
/// Size of the trailing MAC.
pub const TRAILER_MAC_LEN: usize = 32;

/// A decoded hwsetting blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwSetting {
    /// The instruction list.
    pub ops: Vec<Op>,
    /// Trailer bytes after the terminator, preserved byte-for-byte.
    pub trailer: Vec<u8>,
}

impl HwSetting {
    /// Decode a plaintext blob.
    pub fn from_plaintext(plain: &[u8]) -> Result<Self> {
        let (instr, trailer) = op::split_stream(plain)?;
        let (ops, _) = op::decode(instr)?;
        Ok(Self {
            ops,
            trailer: trailer.to_vec(),
        })
    }

    /// Decode an encrypted blob (decrypting first).
    pub fn from_encrypted(blob: &[u8]) -> Result<Self> {
        let plain = HwSettingCipher::new().decrypt(blob)?;
        Self::from_plaintext(&plain)
    }

    /// Encode back to plaintext, reappending the trailer unchanged.
    pub fn to_plaintext(&self) -> Result<Vec<u8>> {
        let mut out = op::encode(&self.ops);
        out.extend_from_slice(&self.trailer);
        Ok(out)
    }

    /// Encode back to an encrypted blob.
    pub fn to_encrypted(&self) -> Result<Vec<u8>> {
        let plain = self.to_plaintext()?;
        HwSettingCipher::new().encrypt_padded(&plain).map(|(b, _)| b)
    }

    /// Instruction count by kind, for reporting.
    pub fn counts(&self) -> OpCounts {
        let mut c = OpCounts::default();
        for op in &self.ops {
            match op {
                Op::Write { .. } => c.write += 1,
                Op::Poll { .. } => c.poll += 1,
                Op::Mask { .. } => c.mask += 1,
                Op::Nop { .. } => c.nop += 1,
            }
        }
        c
    }

    /// Replace the trailer (used when reusing one from a reference blob).
    pub fn set_trailer(&mut self, trailer: Vec<u8>) {
        self.trailer = trailer;
    }

    /// The known-good 16-byte trailer header, with no MAC.
    ///
    /// Every shipped blob starts its trailer with [`TRAILER_HEADER`]. This
    /// helper exists so a caller can build a placeholder trailer; note that the
    /// MAC is **not** computed here (the algorithm was never recovered), so a
    /// blob built this way should not be sent to hardware. Use a trailer copied
    /// from a real blob instead.
    pub fn default_trailer() -> Vec<u8> {
        TRAILER_HEADER.to_vec()
    }

    /// Sanity-check the trailer shape.
    ///
    /// Returns `Ok(())` when the trailer is at least long enough to hold a
    /// header and a MAC. The shipped blobs are 60..120 bytes.
    pub fn validate_trailer(&self) -> Result<()> {
        if self.trailer.len() < TRAILER_HEADER_LEN + TRAILER_MAC_LEN {
            return Err(Error::HwConfig(format!(
                "trailer is {} bytes; need at least {}",
                self.trailer.len(),
                TRAILER_HEADER_LEN + TRAILER_MAC_LEN
            )));
        }
        Ok(())
    }
}

/// Instruction counts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OpCounts {
    /// `w` operations.
    pub write: usize,
    /// `p` operations.
    pub poll: usize,
    /// `m` operations.
    pub mask: usize,
    /// `n` operations.
    pub nop: usize,
}

impl OpCounts {
    /// Total instruction count.
    pub fn total(&self) -> usize {
        self.write + self.poll + self.mask + self.nop
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .join("fixtures/hwsetting")
    }

    /// Read a fixture, or panic with an actionable message (never skip).
    fn read_fixture(name: &str) -> Vec<u8> {
        let p = fixtures().join(name);
        std::fs::read(&p).unwrap_or_else(|e| {
            panic!(
                "fixture {} missing ({e}).\n\
                 Copy the real blobs there:\n  \
                 cp \"<tool>/Tempfile/*hwsetting*.bin\" fixtures/hwsetting/",
                p.display()
            )
        })
    }

    const SHIPPED: &[&str] = &[
        "usb_hwsetting.bin",
        "kylin_usb_hwsetting_2DDR3_4Gb_1600_B.bin",
        "kylin_usb_hwsetting_2DDR4_4Gb_1600_B.bin",
    ];

    #[test]
    fn aes_is_a_true_bijection_on_every_shipped_blob() {
        let c = HwSettingCipher::new();
        for name in SHIPPED {
            let blob = read_fixture(name);
            let plain = c.decrypt(&blob).expect("decrypt");
            let back = c.encrypt(&plain).expect("encrypt");
            assert_eq!(back, blob, "{name}: encrypt(decrypt(x)) != x");
        }
    }

    #[test]
    fn every_shipped_blob_decodes_and_round_trips() {
        for name in SHIPPED {
            let blob = read_fixture(name);
            let hw = HwSetting::from_encrypted(&blob).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!hw.ops.is_empty(), "{name}: no instructions decoded");
            hw.validate_trailer().unwrap_or_else(|e| panic!("{name}: {e}"));

            // plaintext round trip
            let plain = hw.to_plaintext().unwrap();
            let re = HwSetting::from_plaintext(&plain).unwrap();
            assert_eq!(re, hw, "{name}: plaintext round trip");

            // and the full encrypted round trip is byte-identical
            let enc = hw.to_encrypted().unwrap();
            assert_eq!(enc, blob, "{name}: encrypted round trip");
        }
    }

    /// The exact instruction mix recovered from the real blobs.
    ///
    /// These counts are the strongest available evidence that the grammar is
    /// right: the kylin blobs exercise all four op types, and an incorrect
    /// grammar would not reproduce them losslessly.
    #[test]
    fn instruction_mix_matches_the_recorded_counts() {
        let expected: &[(&str, OpCounts)] = &[
            (
                "usb_hwsetting.bin",
                OpCounts {
                    write: 128,
                    poll: 0,
                    mask: 0,
                    nop: 12,
                },
            ),
            (
                "kylin_usb_hwsetting_2DDR3_4Gb_1600_B.bin",
                OpCounts {
                    write: 165,
                    poll: 3,
                    mask: 13,
                    nop: 2,
                },
            ),
            (
                "kylin_usb_hwsetting_2DDR4_4Gb_1600_B.bin",
                OpCounts {
                    write: 177,
                    poll: 6,
                    mask: 21,
                    nop: 3,
                },
            ),
        ];
        for (name, want) in expected {
            let blob = read_fixture(name);
            let hw = HwSetting::from_encrypted(&blob).unwrap();
            assert_eq!(&hw.counts(), want, "{name}");
        }
    }

    #[test]
    fn usb_hwsetting_starts_with_the_known_register_writes() {
        let blob = read_fixture("usb_hwsetting.bin");
        let hw = HwSetting::from_encrypted(&blob).unwrap();
        assert_eq!(
            hw.ops[0],
            Op::Write {
                addr: 0x1801_A010,
                value: 0x1F
            }
        );
        assert_eq!(
            hw.ops[1],
            Op::Write {
                addr: 0x1801_A004,
                value: 0x31
            }
        );
        // and nearly all addresses land in the RTD129x register window
        let in_window = hw
            .ops
            .iter()
            .filter(|o| match o {
                Op::Write { addr, .. } | Op::Poll { addr, .. } | Op::Mask { addr, .. } => {
                    (0x1800_0000..0x1802_0000).contains(addr)
                }
                Op::Nop { .. } => false,
            })
            .count();
        assert!(
            in_window > 100,
            "only {in_window} ops target the DDR controller window"
        );
    }

    #[test]
    fn trailer_header_is_identical_across_blobs() {
        for name in SHIPPED {
            let blob = read_fixture(name);
            let hw = HwSetting::from_encrypted(&blob).unwrap();
            assert_eq!(
                &hw.trailer[..TRAILER_HEADER_LEN],
                &TRAILER_HEADER,
                "{name}: unexpected trailer header"
            );
            assert!(
                (TRAILER_HEADER_LEN + TRAILER_MAC_LEN..=256).contains(&hw.trailer.len()),
                "{name}: trailer length {} out of expected range",
                hw.trailer.len()
            );
        }
    }

    #[test]
    fn edited_ops_re_encode_with_a_reused_trailer() {
        // The supported workflow for regenerating a blob: build ops, then graft
        // a trailer from a known-good reference blob (sidestepping the MAC).
        let reference = HwSetting::from_encrypted(&read_fixture("usb_hwsetting.bin")).unwrap();

        let mut edited = HwSetting {
            ops: vec![
                Op::Write {
                    addr: 0x1801_A010,
                    value: 0x2F,
                },
                Op::Nop { value: 0x1000 },
            ],
            trailer: reference.trailer.clone(),
        };

        let enc = edited.to_encrypted().unwrap();
        let back = HwSetting::from_encrypted(&enc).unwrap();
        assert_eq!(back.ops, edited.ops);
        assert_eq!(back.trailer, reference.trailer);

        // and the trailer can be swapped explicitly
        edited.set_trailer(vec![0u8; 64]);
        assert_eq!(edited.trailer.len(), 64);
        assert!(edited.validate_trailer().is_ok());
    }

    #[test]
    fn validate_trailer_rejects_short_trailers() {
        let hw = HwSetting {
            ops: vec![],
            trailer: vec![0u8; 8],
        };
        assert!(hw.validate_trailer().is_err());
    }

    #[test]
    fn text_edit_workflow_is_lossless_for_the_instruction_part() {
        // Simulates the UI: decode -> show as .config text -> user edits -> encode.
        let blob = read_fixture("usb_hwsetting.bin");
        let hw = HwSetting::from_encrypted(&blob).unwrap();

        let text = op::to_config_text(&hw.ops);
        let reparsed = op::parse_config(&text).unwrap();
        assert_eq!(reparsed, hw.ops, "text round trip must preserve every op");

        // The instruction bytes must match the original plaintext prefix.
        let plain = HwSettingCipher::new().decrypt(&blob).unwrap();
        let orig_instr_end = op::find_terminator_end(&plain).unwrap();
        let reencoded = op::encode(&reparsed);
        assert_eq!(
            reencoded,
            &plain[..orig_instr_end],
            "re-encoded instructions differ from the original plaintext"
        );
    }
}
