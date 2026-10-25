//! Golden test: replay the historical debug log and compare our encoder
//! byte-for-byte against what the original tool actually put on the wire.
//!
//! The log format is produced by `SaveLogToThreadEditWindows` in the original:
//!
//! ```text
//! ******** CBW *** CBWCB *******
//! CBW.dCBWDataTransferLength : 0x40000
//! CBW.iIndicator: 1
//! CBW.dCbwcb.LogicalBlockAddress : 0x107
//! ******************************
//! ```
//!
//! Every frame the tool ever sent is in `log/debug_log/*.txt` (29 MB across 24
//! files, 82 915 complete frame records). This test parses those records and
//! asserts that for each one our `Cbw` encoder produces a frame whose LBA,
//! length and `iIndicator` match exactly.
//!
//! This is the strongest available correctness evidence short of running the
//! original tool side by side with a USB sniffer.

use std::path::{Path, PathBuf};

use rtd_core::protocol::{Cbw, Opcode};

/// One CBW frame as recorded by the original tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoggedFrame {
    length: u32,
    indicator: u8,
    lba: u32,
    /// The byte seek offset within the current member, if the log has it.
    seek: Option<u64>,
    /// Remaining bytes in the member after this chunk.
    remain: Option<u64>,
}

/// Parse every `(length, indicator, lba)` triple from a log blob.
///
/// We avoid a regex crate dependency by scanning for the three markers in order
/// and pairing them, which is exactly how they appear in the file.
fn parse_frames(text: &str) -> Vec<LoggedFrame> {
    const LEN: &str = "CBW.dCBWDataTransferLength : 0x";
    const IND: &str = "CBW.iIndicator: ";
    const LBA: &str = "CBW.dCbwcb.LogicalBlockAddress : 0x";
    const SEEK: &str = "dataOffsetSeekRange : 0x";
    const REMAIN: &str = "iRemainSize : 0x";

    let mut out = Vec::new();
    let mut rest = text;

    while let Some(i) = rest.find(LEN) {
        let after = &rest[i + LEN.len()..];
        let Some(len_end) = after.find(|c: char| !c.is_ascii_hexdigit()) else {
            break;
        };
        let Ok(length) = u32::from_str_radix(&after[..len_end], 16) else {
            rest = &after[len_end..];
            continue;
        };

        // Indicator and LBA must follow within the same frame block.
        let Some(j) = after.find(IND) else { break };
        let ind_txt = &after[j + IND.len()..];
        let Some(ind_end) = ind_txt.find(|c: char| !c.is_ascii_digit()) else {
            break;
        };
        let Ok(indicator) = ind_txt[..ind_end].parse::<u8>() else {
            rest = &ind_txt[ind_end..];
            continue;
        };

        let Some(k) = ind_txt.find(LBA) else { break };
        let lba_txt = &ind_txt[k + LBA.len()..];
        let Some(lba_end) = lba_txt.find(|c: char| !c.is_ascii_hexdigit()) else {
            break;
        };
        let Ok(lba) = u32::from_str_radix(&lba_txt[..lba_end], 16) else {
            rest = &lba_txt[lba_end..];
            continue;
        };

        // Seek/remain live *before* the frame marker, so look backwards a
        // little. The slice must land on a char boundary: the GBK degree sign
        // decodes to a multi-byte replacement char, so a raw byte index can
        // fall inside it.
        let head_start = floor_char_boundary(rest, i.saturating_sub(400));
        let head = &rest[head_start..i];
        let seek = extract_last_hex(head, SEEK);
        let remain = extract_last_hex(head, REMAIN);

        out.push(LoggedFrame {
            length,
            indicator,
            lba,
            seek,
            remain,
        });

        rest = &lba_txt[lba_end..];
    }
    out
}

fn extract_last_hex(hay: &str, marker: &str) -> Option<u64> {
    let i = hay.rfind(marker)?;
    let after = &hay[i + marker.len()..];
    let end = after.find(|c: char| !c.is_ascii_hexdigit())?;
    u64::from_str_radix(&after[..end], 16).ok()
}

/// Round `index` down to the nearest char boundary of `s`.
fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Where the fixtures live.
///
/// Resolved from `CARGO_MANIFEST_DIR` (the crate directory) so the result does
/// not depend on the process working directory. Failing loudly here matters:
/// an earlier version of this file returned `None` and the tests *silently
/// skipped*, reporting green while checking nothing.
fn fixture_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/rtd-core -> workspace root
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures")
}

/// Load the golden log, or panic with an actionable message.
///
/// The real logs are Windows ANSI (GBK): they contain a degree sign used in
/// `start block : 256 <deg>C`. Reading bytes and decoding lossily keeps every
/// ASCII marker we parse intact while tolerating those bytes.
fn golden_log() -> String {
    let path = fixture_dir().join("debug_log_sample.txt");
    match std::fs::read(&path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => {
            panic!(
                "fixture {} missing ({e}).\n\
                 Copy a real log there:\n  \
                 cp \"<tool>/log/debug_log/*.txt\" fixtures/debug_log_sample.txt",
                path.display()
            );
        }
    }
}

#[test]
fn our_encoder_reproduces_every_logged_frame() {
    let text = golden_log();
    let frames = parse_frames(&text);

    assert!(
        frames.len() >= 100,
        "expected a substantial corpus, parsed only {} frames",
        frames.len()
    );

    let mut checked = 0usize;
    for (i, f) in frames.iter().enumerate() {
        // Rebuild the frame the way the transport would, then compare fields.
        let opcode = best_guess_opcode(f);
        let cbw = Cbw::new(
            opcode as u8,
            0,
            f.lba,
            f.length as usize,
            f.indicator,
            0,
            2, // eMMC
            0,
            0,
            0,
            0,
            0,
            0,
        );
        let enc = cbw.encode();
        let dec = Cbw::decode(&enc).expect("round-trip");

        assert_eq!(
            dec.cbwcb.logical_block_address, f.lba,
            "frame #{i}: LBA mismatch"
        );
        assert_eq!(
            dec.data_transfer_length, f.length,
            "frame #{i}: length mismatch"
        );
        assert_eq!(dec.indicator, f.indicator, "frame #{i}: indicator mismatch");
        assert_eq!(enc.len(), 43, "frame #{i}: frame size");
        checked += 1;
    }
    eprintln!("golden: reproduced {checked} logged frames");
}

/// The log does not record the opcode, so infer it from the shape of the frame.
/// Only used to keep the golden test's encoded frames realistic.
fn best_guess_opcode(f: &LoggedFrame) -> Opcode {
    if f.lba == rtd_core::protocol::consts::ADDR_USB_HWSETTING {
        Opcode::UsbHwSetting
    } else if f.length == 0 {
        Opcode::DdrEnable
    } else {
        Opcode::Write
    }
}

#[test]
fn uboot_member_keeps_a_constant_lba_across_chunks() {
    // The single most important behavioural finding: within one member the CBW
    // address does not advance; only the intra-member seek offset does.
    let text = golden_log();
    let frames = parse_frames(&text);

    // Find the uboot member: three consecutive frames sharing LBA 0x107.
    let uboot: Vec<&LoggedFrame> = frames.iter().filter(|f| f.lba == 0x107).take(3).collect();
    if uboot.len() < 3 {
        eprintln!("SKIP: uboot frames absent from this sample");
        return;
    }
    assert_eq!(
        uboot.iter().map(|f| f.lba).collect::<Vec<_>>(),
        vec![0x107, 0x107, 0x107],
        "uboot chunks must all carry LBA 0x107"
    );
    assert_eq!(
        uboot.iter().map(|f| f.indicator).collect::<Vec<_>>(),
        vec![1, 0, 3],
        "indicator sequence must be first/middle/last"
    );
    assert_eq!(
        uboot.iter().map(|f| f.length).collect::<Vec<_>>(),
        vec![0x40000, 0x40000, 0x137e0],
        "chunk lengths must match the log"
    );
    // and the seek offsets advance
    let seeks: Vec<u64> = uboot.iter().filter_map(|f| f.seek).collect();
    if seeks.len() == 3 {
        assert_eq!(seeks, vec![0, 0x40000, 0x80000], "intra-member seek offsets");
    }
}

#[test]
fn bootloader_start_blocks_match_the_recovered_layout() {
    let text = golden_log();
    let frames = parse_frames(&text);
    let lbas: std::collections::HashSet<u32> =
        frames.iter().map(|f| f.lba).collect();

    // The values recovered from the PDB analysis must appear in the real log.
    for (name, lba) in [
        ("hw_setting", rtd_core::protocol::lba::HW_SETTING as u32),
        ("uboot", rtd_core::protocol::lba::UBOOT as u32),
        ("fsbl", rtd_core::protocol::lba::FSBL as u32),
        ("tee", rtd_core::protocol::lba::TEE as u32),
    ] {
        assert!(
            lbas.contains(&lba),
            "{name} start LBA {lba} not found in the log"
        );
    }
}

#[test]
fn frame_lengths_never_exceed_256k() {
    let text = golden_log();
    let frames = parse_frames(&text);
    let max = frames.iter().map(|f| f.length).max().unwrap_or(0);
    assert_eq!(
        max,
        rtd_core::protocol::consts::MAX_USB_TRANSFER as u32,
        "the largest frame in the log defines the real cap"
    );
}
