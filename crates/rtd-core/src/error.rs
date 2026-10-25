//! Error types, including the original tool's `ROR_*` result codes.

use thiserror::Error;

/// Return codes observed in the original binary (all have the form
/// `0x5245xxxx`, which is `'RE'` in little-endian ASCII).
///
/// The original returns these as `int`; `ROR_PASS` (0x52450064) is the only
/// success value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Ror {
    ReadUntarTempFail = 0x5245_0000,
    OpCodeFail = 0x5245_0001,
    OpenFileFail = 0x5245_0002,
    FileSizeFail = 0x5245_0003,
    ReadFileFail = 0x5245_0004,
    CswReadFail = 0x5245_0005,
    CswReadThirty = 0x5245_0006,
    CswStatFail = 0x5245_0007,
    CswWriterFail = 0x5245_0008,
    ReadDeviceFail = 0x5245_0009,
    CbwWriterFail = 0x5245_000a,
    TransmissionRwDataFail = 0x5245_000b,
    RemappingFail = 0x5245_000c,
    RemappingSizeFail = 0x5245_000d,
    RemappingMaxSizeFail = 0x5245_000e,
    RemappingOutOfRange = 0x5245_000f,
    RemappingFlashtypeFail = 0x5245_0010,
    FactoryFail = 0x5245_0011,
    FactoryReadFail = 0x5245_0012,
    EmmcWriteFail = 0x5245_0013,
    KeyBagNotFound = 0x5245_0014,
    CompareDataFail = 0x5245_0015,
    CreateBbTableFail = 0x5245_0016,
    NumberOfKeyNotEnough = 0x5245_0017,
    CustomizedFail = 0x5245_0018,
    Pass = 0x5245_0064,
}

impl Ror {
    /// Whether this code represents success (i.e. `ROR_PASS`).
    pub fn is_success(self) -> bool {
        self == Ror::Pass
    }
}

/// Transport-level command status (`CSW_STAT_TABLE`, PDB enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CswStatus {
    Pass = 0,
    /// Device reported failure; the tool retries.
    Fail = 1,
    /// Device is still working; the tool keeps polling.
    Busy = 2,
    /// NAND bad block during a write; triggers the remap path.
    WFail = 3,
    WKeyFail = 4,
    WKeyPass = 5,
    RKeyFail = 6,
}

impl CswStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => CswStatus::Pass,
            1 => CswStatus::Fail,
            2 => CswStatus::Busy,
            3 => CswStatus::WFail,
            4 => CswStatus::WKeyFail,
            5 => CswStatus::WKeyPass,
            6 => CswStatus::RKeyFail,
            _ => return None,
        })
    }

    /// Human-readable description matching the original's log wording.
    pub fn describe(self) -> &'static str {
        match self {
            CswStatus::Pass => "PASS",
            CswStatus::Fail => "FAIL",
            CswStatus::Busy => "BUSY",
            CswStatus::WFail => "nand flash write failed, because bad block",
            CswStatus::WKeyFail => "write key failed",
            CswStatus::WKeyPass => "write key pass",
            CswStatus::RKeyFail => "read key failed",
        }
    }
}

/// Top-level error type for the core library.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("device not found (looking for VID {vid:04x}:PID {pid:04x})")]
    DeviceNotFound { vid: u16, pid: u16 },

    #[error("the USB backend is unavailable: {0}")]
    BackendUnavailable(String),

    /// The CBW could not be sent.
    #[error("CBW write failed: {0}")]
    CbwWriteFailed(String),

    /// Reading the 50-byte CSW failed.
    #[error("CSW read failed")]
    CswReadFailed,

    /// The CSW signature or tag did not match.
    #[error("bad CSW signature/tag: sig={sig:#010x} tag={tag:#010x} (expected {expect_sig:#010x}/{expect_tag:#010x})")]
    CswBadSignature {
        sig: u32,
        tag: u32,
        expect_sig: u32,
        expect_tag: u32,
    },

    /// The device returned a status the tool does not retry on.
    #[error("device reported CSW status {status:?} ({desc})")]
    CswStatus {
        status: CswStatus,
        desc: &'static str,
    },

    /// The device never stopped reporting BUSY.
    #[error("CSW polling timed out after {attempts} attempts / {elapsed_ms} ms")]
    CswTimeout { attempts: u32, elapsed_ms: u64 },

    /// Every retry returned FAIL.
    #[error("CSW retry exhausted after {0} attempts")]
    CswRetryExhausted(u32),

    #[error("invalid chunk size {0}")]
    InvalidChunkSize(usize),

    #[error("image error: {0}")]
    Image(String),

    /// A burn plan could not be executed. The message lists every problem found,
    /// because a plan is validated as a whole before any bytes are sent.
    #[error("burn refused: {0}")]
    Burn(String),

    #[error("hwsetting error: {0}")]
    HwConfig(String),

    #[error("AES error: {0}")]
    Aes(String),
}

impl Error {
    /// Map to the original tool's numeric code, when one exists.
    pub fn to_ror(&self) -> Option<Ror> {
        Some(match self {
            Error::CbwWriteFailed(_) => Ror::CbwWriterFail,
            Error::CswReadFailed => Ror::CswReadFail,
            Error::CswBadSignature { .. } => Ror::CswStatFail,
            Error::CswStatus { status, .. } => match status {
                CswStatus::Fail => Ror::CswStatFail,
                CswStatus::WFail => Ror::RemappingFail,
                _ => Ror::CswStatFail,
            },
            Error::CswTimeout { .. } => Ror::CswReadThirty,
            Error::CswRetryExhausted(_) => Ror::CswReadThirty,
            Error::Image(_) => Ror::ReadUntarTempFail,
            Error::HwConfig(_) => Ror::OpCodeFail,
            _ => return None,
        })
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ror_values_match_the_original() {
        assert_eq!(Ror::ReadUntarTempFail as i32, 0x5245_0000);
        assert_eq!(Ror::EmmcWriteFail as i32, 0x5245_0013);
        assert_eq!(Ror::Pass as i32, 0x5245_0064);
        assert!(Ror::Pass.is_success());
    }

    #[test]
    fn csw_status_round_trips() {
        for v in 0u8..=6 {
            let s = CswStatus::from_u8(v).expect("known status");
            assert_eq!(s as u8, v);
        }
        assert!(CswStatus::from_u8(7).is_none());
        assert!(CswStatus::from_u8(0xFF).is_none());
    }

    #[test]
    fn status_maps_to_ror() {
        let e = Error::CswStatus {
            status: CswStatus::WFail,
            desc: "x",
        };
        assert_eq!(e.to_ror(), Some(Ror::RemappingFail));
    }
}
