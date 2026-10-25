//! Wire-level constants for the RTD129x USB download protocol.
//!
//! Every value here is taken from the reverse-engineered specification in
//! `w2_reverse/spec/protocol.json` and cross-checked against the original
//! `rtumdfsample.exe` disassembly. The most important deviations from real
//! SCSI are:
//!
//! * the CBW is **43** bytes (not 31) and carries a **28**-byte command block
//! * the CSW is **50** bytes (not 13) and its status byte lives at offset **13**
//! * the opcodes are a private set `0xF1..=0xFC`, not SCSI opcodes

/// USB vendor/product of the SoC in Device mode.
pub const USB_VID: u16 = 0x0BDA;
pub const USB_PID: u16 = 0x1195;

/// `{7B56A5D6-CD10-4410-9F59-9A5E71269882}` — the SetupDi device interface
/// GUID the original tool enumerates with (read from `.rdata` at VA 0x596AC0).
pub const DEVICE_INTERFACE_GUID: [u8; 16] = [
    0xD6, 0xA5, 0x56, 0x7B, // Data1 (LE)
    0x10, 0xCD, // Data2 (LE)
    0x10, 0x44, // Data3 (LE)
    0x9F, 0x59, // Data4[0..2]
    0x9A, 0x5E, 0x71, 0x26, 0x98, 0x82,
];

/// `{23FA4AD3-B0C4-40C8-BDDA-28F67F2E70CA}` — driver class GUID from the INF.
pub const DRIVER_CLASS_GUID: &str = "{23FA4AD3-B0C4-40C8-BDDA-28F67F2E70CA}";

/// Maximum payload of a single CBW.
///
/// **256 KiB (0x40000).** This is not a guess: the historical debug log
/// contains 82 143 frames of `onceTransSize : 0x40000`, and across all 24 log
/// files the largest `CBW.dCBWDataTransferLength` ever emitted is exactly
/// `0x40000`. Neither `0x20000` nor `0x200000` occurs as a frame length.
///
/// (`WriteDevice` does compare against `0x20000` at 0x4059A3, but that is the
/// NAND "cover value" test near the top of the function, not a chunk cap.)
pub const MAX_USB_TRANSFER: usize = 0x4_0000;

/// The USB hwsetting blob is written to a *raw byte address*, not a sector.
pub const ADDR_USB_HWSETTING: u32 = 0x0150_0000;

// ---------------------------------------------------------------------------
// CBW / CSW framing
// ---------------------------------------------------------------------------

/// `'USBC'` little-endian.
pub const CBW_SIGNATURE: u32 = 0x4342_5355;
/// Fixed tag the original always sends.
pub const CBW_TAG: u32 = 0x1234_5678;

/// Host -> device (write) direction.
pub const CBW_FLAGS_WRITE: u8 = 0x00;
/// Device -> host (read) direction.
pub const CBW_FLAGS_READ: u8 = 0x80;

/// Total CBW frame length in bytes.
pub const CBW_LEN: usize = 43;
/// Offset of the embedded command block.
pub const CBW_CBWCB_OFFSET: usize = 0x0F;
/// Length of the embedded command block (PDB `_CBWCB`).
pub const CBW_CBWCB_LEN: usize = 28;

/// `iIndicator` values at CBW offset 0x0D.
///
/// The original builds this byte as
/// `((param16 & 3) | (param17 << 2)) << 4 | spare_nibble`, so the low nibble
/// carries the chunk position and the high nibble carries mode flags.
pub mod indicator {
    /// First chunk of a multi-chunk buffer.
    pub const FIRST: u8 = 0x1;
    /// A middle chunk.
    pub const MIDDLE: u8 = 0x0;
    /// Last (or only) chunk.
    pub const LAST: u8 = 0x3;
    /// The value the *device* reports back to mean "still busy".
    pub const BUSY: u8 = 0x2;
}

/// `'USBS'` little-endian.
pub const CSW_SIGNATURE: u32 = 0x5342_5355;
/// Total CSW frame length in bytes.
pub const CSW_LEN: usize = 50;
/// Offset of `dCSWTag`.
pub const CSW_TAG_OFFSET: usize = 0x04;
/// Offset of `bCSWStatus`.
///
/// Proven from disassembly: the frame base is `ebp-0x9c` and the bus float
/// uses `[ebp-0x8f]`, and `0x9c - 0x8f == 13`.
pub const CSW_STATUS_OFFSET: usize = 13;

// ---------------------------------------------------------------------------
// Transport retry policy (WriteDevice @0x004057D0)
// ---------------------------------------------------------------------------

/// Max CSW polling attempts.
pub const CSW_MAX_RETRY: u32 = 200;
/// Sleep between retries (the original uses `Sleep(200)`).
pub const CSW_RETRY_SLEEP_MS: u64 = 200;
/// Overall deadline for a single CSW exchange (the original compares > 20 s).
/// How long to poll for a status *between* chunks before carrying on.
///
/// Short on purpose: silence here means "not ready yet", not "failed", and the
/// host must keep feeding the device or a single-threaded firmware deadlocks on
/// its own unread reply. The full [`CSW_TIMEOUT_MS`] budget still applies to the
/// mandatory wait at the end of a round.
pub const CSW_POLL_BUDGET_MS: u64 = 2000;

pub const CSW_TIMEOUT_MS: u64 = 20_000;

/// The tool sleeps 1500 ms (`Sleep(0x5DC)`) **after writing the hwsetting blob
/// and before sending the `0xFA` DDR-enable frame** -- see
/// `usb_hw_setting_burner` @0x004274C0. USBPcap shows the same 1512 ms gap on
/// the wire. Without it the board acknowledges `0xFA` but never accepts the
/// following WRITE payload.
pub const HW_SETTING_SETTLE_MS: u64 = 1_500;

/// Pause after the `0xFA` CSW and before the next command.
///
/// Not in `usb_hw_setting_burner` itself: the original's ~6.9 ms gap there is
/// its GUI logging. Kept anyway so the wire timeline matches the capture and the
/// first WRITE does not chase the DDR-enable CSW in the same microsecond.
pub const DDR_POST_ENABLE_MS: u64 = 10;
/// The tool sleeps 4000 ms after the efuse pass.
pub const EFUSE_SETTLE_MS: u64 = 4_000;

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

/// The protocol addresses the flash in 512-byte sectors.
pub const SECTOR_SIZE: u64 = 512;

/// Bootloader members are laid out back-to-back in 512-byte sectors.
/// Verified against the historical debug log:
/// `next_lba = lba + ceil(size / 512)`.
pub mod lba {
    pub const HW_SETTING: u64 = 256; // hw_setting.bin  3200 B
    pub const UBOOT: u64 = 263; // uboot.bin     604128 B
    pub const FSBL: u64 = 1443; // fsbl.bin       72544 B
    pub const TEE: u64 = 1585; // tee.bin       507616 B
}

/// Factory area geometry.
pub const FACTORY_START_PAGE_A: u64 = 4352; // 0x220000
pub const FACTORY_START_PAGE_B: u64 = 8448; // 0x420000
pub const FACTORY_MAX_SIZE: u64 = 0x20_0000;

// ---------------------------------------------------------------------------
// hwsetting crypto (see PROTOCOL.md section 5)
// ---------------------------------------------------------------------------

/// Hard-coded AES-128 key (`?g_AES_USB_key@@3PAEA` in `.data`).
///
/// The hwsetting blobs are **AES-128-ECB**, not CBC. An earlier reading
/// suggested CBC with a zero IV because under CBC/IV=0 the first plaintext
/// block equals the ECB result; a statistical check settled it (ECB yields
/// ~40% register-window words, CBC yields noise).
pub const AES_KEY_USB: [u8; 16] = [
    0xab, 0xcd, 0xef, 0x12, 0x13, 0x57, 0x24, 0x68,
    0xa1, 0xb2, 0xc3, 0xd4, 0x90, 0x90, 0xba, 0xbe,
];

/// Terminator of the hwsetting instruction stream.
pub const HWCONFIG_TERMINATOR: u32 = 0xFFFF_FFFF;
