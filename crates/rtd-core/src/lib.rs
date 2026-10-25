//! # rtd-core
//!
//! Core implementation of the RTD129x (RTD1295 / RTD1296) USB download
//! protocol, reconstructed from `rtumdfsample.exe`.
//!
//! The crate is deliberately UI-agnostic: the CLI and the GUI are thin
//! consumers. The authoritative specification lives in
//! `w2_reverse/spec/PROTOCOL.md` and `w2_reverse/spec/protocol.json`.
//!
//! ## Shape of the protocol
//!
//! The device exposes a **private** command set over a bulk pipe, framed like
//! SCSI but not SCSI:
//!
//! * a **43-byte CBW** carrying a **28-byte** command block (not 31/16)
//! * a **50-byte CSW** whose status byte sits at offset **13** (not 12)
//! * opcodes `0xF1..=0xFC`, all vendor-specific
//!
//! ## Example
//!
//! ```
//! use rtd_core::protocol::{Cbw, Opcode, cmd_type, indicator};
//!
//! let cbw = Cbw::new(
//!     Opcode::Write as u8,
//!     cmd_type::WRITE_CHUNK,
//!     0x0107,          // logical block address (512-byte sectors)
//!     0x40000,         // payload length for this chunk
//!     indicator::FIRST,
//!     0,               // write direction
//!     2,               // eMMC
//!     0, 0, 0, 0, 0,   // page size, block size, nand size, spare, ecc
//!     0xDEAD_BEEF,     // CRC32 of the chunk payload
//! );
//! let bytes = cbw.encode();
//! assert_eq!(bytes.len(), 43);
//! assert!(cbw.validate());
//! ```

#![deny(missing_debug_implementations)]
// Public items in this crate are documented; the wire structs additionally
// carry per-field offset comments (crucial for a binary format), so we allow
// the lint that would demand a second doc line on every variant.
#![allow(missing_docs)]

pub mod burn;
pub mod ddr;
pub mod device;
pub mod error;
pub mod hwconfig;
pub mod image;
pub mod protocol;
pub mod transport;

pub use burn::{BurnOptions, BurnPlan, BurnReport};
pub use ddr::{DdrType, HwSettingKind, HwSettingSearch};
pub use device::{mock, DeviceBackend};
pub use error::{CswStatus, Error, Result, Ror};
pub use transport::{Transport, TransportLog};
