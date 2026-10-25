//! The private command set (`CBWCB.OPCode`).
//!
//! Every variant carries its meaning in a doc comment below.
//!
//! Eleven opcodes are used. Each maps to a handler in the original source,
//! recovered from the PDB source-line mapping.

/// Top-level opcode carried in `CBWCB[0]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// Secure-storage key burn — `se_storage_burner` (key_write.cpp:89).
    SeStorage = 0xF1,
    /// Single-write status — `single_burner` (single_write.cpp:32).
    SingleStatus = 0xF2,
    /// NAND page program with BBT remap — `nand_burner` (nand_write.cpp:32).
    NandWrite = 0xF3,
    /// **Primary bulk write** — `WriteDevice` (dev_api.cpp:104), 66 call sites.
    Write = 0xF4,
    /// USB hwsetting / DRAM init — `usb_hw_setting_burner` (rtumdfsampledlg.cpp:4643).
    UsbHwSetting = 0xF5,
    /// Write/read-back verification — `TestWriteDevice` (dev_api.cpp:828).
    WriteVerify = 0xF6,
    /// eFuse burn — `efuse_burner` (key_write.cpp:686).
    EfuseBurn = 0xF9,
    /// DDR enable, always with `Type = 0x06`.
    DdrEnable = 0xFA,
    /// Single-write data — `single_burner`.
    SingleData = 0xFB,
    /// Read verification — `TestReadDevice`.
    ReadVerify = 0xFC,
    /// Sense / channel poll (also the `bCBWCBLength` value 0x1C).
    Sense = 0x1C,
}

impl Opcode {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0xF1 => Opcode::SeStorage,
            0xF2 => Opcode::SingleStatus,
            0xF3 => Opcode::NandWrite,
            0xF4 => Opcode::Write,
            0xF5 => Opcode::UsbHwSetting,
            0xF6 => Opcode::WriteVerify,
            0xF9 => Opcode::EfuseBurn,
            0xFA => Opcode::DdrEnable,
            0xFB => Opcode::SingleData,
            0xFC => Opcode::ReadVerify,
            0x1C => Opcode::Sense,
            _ => return None,
        })
    }

    /// Short name for logs, matching what the original writes to its debug log.
    pub fn name(self) -> &'static str {
        match self {
            Opcode::SeStorage => "se_storage",
            Opcode::SingleStatus => "single_status",
            Opcode::NandWrite => "nand_write",
            Opcode::Write => "write",
            Opcode::UsbHwSetting => "usb_hwsetting",
            Opcode::WriteVerify => "write_verify",
            Opcode::EfuseBurn => "efuse_burn",
            Opcode::DdrEnable => "ddr_enable",
            Opcode::SingleData => "single_data",
            Opcode::ReadVerify => "read_verify",
            Opcode::Sense => "sense",
        }
    }
}

/// The `Type` byte (`CBWCB[1]`), i.e. the sub-command.
///
/// Only two values are used in the eMMC path.
pub mod cmd_type {
    /// Write one data chunk.
    pub const WRITE_CHUNK: u8 = 0x01;
    /// DDR enable step of the hwsetting sequence.
    pub const DDR_ENABLE: u8 = 0x06;
    /// "Generate ktee key" step used by `se_storage_burner`.
    pub const GEN_KTEE_KEY: u8 = 0x03;
    /// eFuse programmer/verify pass.
    pub const EFUSE: u8 = 0x05;
}

/// `flashType` values (`CBWCB[7]` and `FlashInfo.flashType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FlashType {
    Nand = 0,
    Nor = 1,
    Emmc = 2,
}

impl FlashType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => FlashType::Nand,
            1 => FlashType::Nor,
            2 => FlashType::Emmc,
            _ => return None,
        })
    }

    /// The string the original writes into `SYSTEM.ini` / the UI combo box.
    pub fn name(self) -> &'static str {
        match self {
            FlashType::Nand => "NAND",
            FlashType::Nor => "NOR",
            FlashType::Emmc => "EMMC",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eleven_opcodes_round_trip() {
        let all = [
            Opcode::SeStorage,
            Opcode::SingleStatus,
            Opcode::NandWrite,
            Opcode::Write,
            Opcode::UsbHwSetting,
            Opcode::WriteVerify,
            Opcode::EfuseBurn,
            Opcode::DdrEnable,
            Opcode::SingleData,
            Opcode::ReadVerify,
            Opcode::Sense,
        ];
        assert_eq!(all.len(), 11, "the original uses exactly 11 opcodes");
        for op in all {
            assert_eq!(Opcode::from_u8(op as u8), Some(op), "{op:?}");
        }
    }

    #[test]
    fn opcode_values_match_the_spec() {
        assert_eq!(Opcode::Write as u8, 0xF4);
        assert_eq!(Opcode::UsbHwSetting as u8, 0xF5);
        assert_eq!(Opcode::EfuseBurn as u8, 0xF9);
        assert_eq!(Opcode::DdrEnable as u8, 0xFA);
        assert_eq!(Opcode::Sense as u8, 0x1C);
    }

    #[test]
    fn unknown_opcode_is_rejected() {
        for v in [0x00u8, 0xF0, 0xF7, 0xF8, 0xFD, 0xFF] {
            assert!(Opcode::from_u8(v).is_none(), "{v:#x}");
        }
    }

    #[test]
    fn flash_types() {
        assert_eq!(FlashType::from_u8(2), Some(FlashType::Emmc));
        assert_eq!(FlashType::Emmc.name(), "EMMC");
        assert!(FlashType::from_u8(3).is_none());
    }
}
