//! Wire protocol: framing, opcodes and the flash geometry descriptor.

pub mod cbw;
pub mod consts;
pub mod csw;
pub mod flash_info;
pub mod opcode;

pub use cbw::{Cbw, CbwCb};
pub use consts::*;
pub use csw::Csw;
pub use flash_info::FlashInfo;
pub use opcode::{cmd_type, FlashType, Opcode};
