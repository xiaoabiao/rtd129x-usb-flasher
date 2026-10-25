//! Image and configuration handling.
//!
//! * [`layout_txt`] — the partition table inside an image
//! * [`system_ini`] — the tool's configuration, including GBK decoding
//! * [`bootloader`] — `bootloader.tar` members and their flash placement
//! * [`install_img`] — unpacking `install.img` and detecting its project layout

pub mod bootloader;
pub mod install_img;
pub mod layout_txt;
pub mod system_ini;

pub use bootloader::{LoadedMember, Member};
pub use install_img::{ImageSummary, ProjectKind};
pub use layout_txt::Partition;
pub use system_ini::{Ini, SystemIni};
