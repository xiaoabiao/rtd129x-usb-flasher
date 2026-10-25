//! Device backends: the byte-pipe trait, a mock for tests, and the real USB
//! implementation behind a feature gate.
//!
//! The transport layer only needs a byte pipe with the semantics of
//! `WriteFile` / `ReadFile` on the vendor interface. Keeping that behind
//! [`DeviceBackend`] means:
//!
//! * the whole protocol is testable with [`mock::MockDevice`], no hardware;
//! * the real USB path lives in [`usb`] and is only compiled when the `usb`
//!   feature is enabled, so the core stays free of platform dependencies;
//! * the pure parts of device selection ([`filter`]) are unit-tested even
//!   without a USB stack present.
//!
//! # Two Windows paths
//!
//! On Windows the shipped board is bound to the `rtumdfdrv` **UMDF** driver, so
//! [`usb`] can list it but cannot open it (WinUSB sees no interfaces). [`windows`]
//! handles that case by opening the UMDF device interface with `CreateFile`.
//! Use [`backend`] to pick automatically.

pub mod filter;
pub mod mock;

#[cfg(feature = "usb")]
pub mod usb;

// The UMDF `CreateFile` backend. The module itself compiles everywhere so the
// device-path format stays unit-tested on every platform; only the backend is
// gated to Windows.
pub mod windows;

#[cfg(not(feature = "usb"))]
pub mod usb {
    //! Stub when the `usb` feature is disabled.
    //!
    //! Every entry point reports that the backend is unavailable rather than
    //! panicking, so a caller can present a clear message.

    use crate::error::{Error, Result};

    /// Why the backend is unavailable.
    ///
    /// Kept as an alias of [`super::USB_DISABLED`] for callers that referenced
    /// it directly.
    pub const UNAVAILABLE_REASON: &str = super::USB_DISABLED;

    /// Original text, retained for reference.
    #[allow(dead_code)]
    const _ORIGINAL: &str =
        "the `usb` feature is disabled at compile time (rebuild with --features usb)";

    /// A placeholder device list entry.
    #[derive(Debug, Clone)]
    pub struct UsbDeviceInfo {
        /// Bus number.
        pub bus: u8,
        /// Device address on the bus.
        pub address: u8,
        /// Vendor id.
        pub vendor_id: u16,
        /// Product id.
        pub product_id: u16,
        /// Serial string, if the device exposes one.
        pub serial: Option<String>,
    }

    /// Not available without the feature.
    pub fn list_devices() -> Result<Vec<UsbDeviceInfo>> {
        Err(Error::BackendUnavailable(UNAVAILABLE_REASON.to_string()))
    }
}

use crate::error::Result;

/// The message to show when a build has no USB backend.
///
/// This lives here rather than inside the `usb` module because Cargo unifies
/// features across a workspace: `rtd-core/usb` can be enabled by one crate while
/// another crate's own `usb` feature is off, so a constant that only exists in
/// one of the two module variants cannot be referenced safely.
pub const USB_DISABLED: &str =
    "the `usb` feature is disabled at compile time (rebuild with --features usb)";

/// A raw byte pipe to the device.
///
/// Implementors must guarantee that:
/// * `write_all` either writes everything or reports an error;
/// * `read` returns at least one byte on success (short reads are allowed and
///   the transport loops);
/// * `read` returning `Ok(0)` means "nothing available yet", not EOF, so the
///   transport can poll against its deadline.
/// `Send` is required so a backend can move onto the thread that runs the burn
/// (and onto the probe's read timeout thread).
pub trait DeviceBackend: std::fmt::Debug + Send {
    /// Write the whole buffer.
    fn write_all(&mut self, data: &[u8]) -> Result<()>;

    /// Read up to `buf.len()` bytes, returning how many were read.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Flush any buffering (the original calls `FlushFileBuffers`).
    fn flush(&mut self) -> Result<()>;

    /// A short description used in logs.
    fn describe(&self) -> String;
}

/// Forward through a boxed backend.
///
/// `device::open` returns `Box<dyn DeviceBackend>` because the concrete type is
/// chosen at runtime (UMDF vs WinUSB). Without this impl the box cannot be
/// handed to `Transport`, which is generic over `D: DeviceBackend`.
impl<T: DeviceBackend + ?Sized> DeviceBackend for Box<T> {
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        (**self).write_all(data)
    }
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        (**self).read(buf)
    }
    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }
    fn describe(&self) -> String {
        (**self).describe()
    }
}

pub use mock::MockDevice;

/// Open a device using the best backend for this platform.
///
/// On Windows the shipped board is bound to the `rtumdfdrv` UMDF driver, which
/// the WinUSB API cannot open, so [`windows::WindowsBackend`] is tried first and
/// [`usb::UsbBackend`] is the fallback for boards that *are* on WinUSB. Every
/// other platform uses [`usb`].
///
/// `key` selects a device by its serial; `None` takes the first one found.
///
/// Both attempts are reported when both fail, because "no interfaces" from
/// WinUSB and "CreateFile failed" from the UMDF path point at different fixes.
#[cfg(feature = "usb")]
#[cfg(feature = "usb")]
pub fn open(key: Option<&str>) -> Result<Box<dyn DeviceBackend>> {
    #[cfg(windows)]
    {
        let umdf = match key {
            Some(k) => windows::WindowsBackend::open_by_key(k),
            None => windows::WindowsBackend::open_first(),
        };
        match umdf {
            Ok(b) => return Ok(Box::new(b)),
            Err(umdf_err) => {
                let winusb = match key {
                    Some(k) => usb::UsbBackend::open_by_key(k),
                    None => usb::UsbBackend::open_first(),
                };
                return match winusb {
                    Ok(b) => Ok(Box::new(b)),
                    Err(winusb_err) => Err(crate::error::Error::BackendUnavailable(format!(
                        "could not open the device with either backend.\n  \
                         UMDF/CreateFile: {umdf_err}\n  \
                         WinUSB:          {winusb_err}"
                    ))),
                };
            }
        }
    }
    #[cfg(not(windows))]
    {
        match key {
            Some(k) => Ok(Box::new(usb::UsbBackend::open_by_key(k)?)),
            None => Ok(Box::new(usb::UsbBackend::open_first()?)),
        }
    }
}
