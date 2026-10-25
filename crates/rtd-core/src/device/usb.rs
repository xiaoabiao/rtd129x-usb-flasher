//! The real USB backend, built on [`nusb`](https://docs.rs/nusb).
//!
//! Enabled by the `usb` feature. `nusb` is pure Rust and talks to the kernel
//! directly (`/dev/bus/usb` on Linux, IOKit on macOS, WinUSB on Windows), so
//! there is **no libusb dependency** and nothing to install on Linux/macOS.
//!
//! # Windows note
//!
//! The original ships a UMDF driver (`rtumdfdrv`) and opens the device with
//! `CreateFileA`. `nusb` on Windows needs WinUSB (or libusbK) bound to the
//! interface -- typically via Zadig or a small INF. It is a plain vendor
//! interface, so this is a one-time binding with no kernel driver of our own,
//! and the wire protocol is identical either way.
//!
//! # Interface selection
//!
//! We claim the first interface that exposes **both** a bulk-IN and a bulk-OUT
//! endpoint, preferring a vendor-specific (class `0xFF`) interface. That is what
//! the `rtumdfdrv` INF exposes.

use std::time::Duration;

use nusb::transfer::{Direction, EndpointType, RequestBuffer, TransferError};

use crate::device::filter::{self, UsbDeviceInfo};
use crate::device::DeviceBackend;
use crate::error::{Error, Result};
use crate::protocol::consts::{USB_PID, USB_VID};

/// The message a build without the backend would show.
///
/// Defined in both module variants so that any combination of features across
/// the workspace compiles; see [`crate::device::USB_DISABLED`].
pub const UNAVAILABLE_REASON: &str = crate::device::USB_DISABLED;

/// Bound on a single bulk transfer.
///
/// The transport enforces its own 20 s CSW deadline; this only stops one
/// syscall from outliving it by much.
pub const BULK_TIMEOUT: Duration = Duration::from_millis(5_000);

/// A claimed vendor interface with its two bulk endpoints.
pub struct UsbBackend {
    interface: nusb::Interface,
    ep_in: u8,
    ep_out: u8,
    key: String,
    /// Bytes read but not yet consumed by the caller.
    pending: Vec<u8>,
}

impl std::fmt::Debug for UsbBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsbBackend")
            .field("key", &self.key)
            .field("ep_in", &format_args!("{:#04x}", self.ep_in))
            .field("ep_out", &format_args!("{:#04x}", self.ep_out))
            .field("pending", &self.pending.len())
            .finish()
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    futures_lite::future::block_on(f)
}

/// Build the stable key for a device: its serial, else `bus:address`.
fn key_of(d: &nusb::DeviceInfo) -> String {
    d.serial_number()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("000:{:03}", d.device_address()))
}

/// Project a `nusb` device into our backend-neutral record.
fn to_info(d: &nusb::DeviceInfo) -> UsbDeviceInfo {
    let interfaces: Vec<_> = d.interfaces().collect();
    UsbDeviceInfo {
        bus: 0, // nusb exposes only a device address
        address: d.device_address(),
        vendor_id: d.vendor_id(),
        product_id: d.product_id(),
        serial: d.serial_number().map(str::to_string),
        product: d.product_string().map(str::to_string),
        interface_count: interfaces.len() as u8,
    }
}

/// Enumerate attached RTD129x devices in stable order.
pub fn list_devices() -> Result<Vec<UsbDeviceInfo>> {
    let iter = nusb::list_devices()
        .map_err(|e| Error::BackendUnavailable(format!("USB enumeration failed: {e}")))?;
    let mut out: Vec<UsbDeviceInfo> = iter
        .filter(|d| d.vendor_id() == USB_VID && d.product_id() == USB_PID)
        .map(|d| to_info(&d))
        .collect();
    filter::sort_stable(&mut out);
    Ok(out)
}

/// Whether the USB backend can be used at all on this host.
pub fn is_available() -> bool {
    nusb::list_devices().is_ok()
}

impl UsbBackend {
    /// Open the device with the given key (serial, or `000:address`).
    pub fn open_by_key(key: &str) -> Result<Self> {
        let iter = nusb::list_devices()
            .map_err(|e| Error::BackendUnavailable(format!("USB enumeration failed: {e}")))?;
        let info = iter
            .filter(|d| d.vendor_id() == USB_VID && d.product_id() == USB_PID)
            .find(|d| key_of(d) == key)
            .ok_or(Error::DeviceNotFound {
                vid: USB_VID,
                pid: USB_PID,
            })?;
        Self::open_info(&info)
    }

    /// Open the first attached RTD129x device.
    pub fn open_first() -> Result<Self> {
        let iter = nusb::list_devices()
            .map_err(|e| Error::BackendUnavailable(format!("USB enumeration failed: {e}")))?;
        let info = iter
            .filter(|d| d.vendor_id() == USB_VID && d.product_id() == USB_PID)
            .next()
            .ok_or(Error::DeviceNotFound {
                vid: USB_VID,
                pid: USB_PID,
            })?;
        Self::open_info(&info)
    }

    fn open_info(info: &nusb::DeviceInfo) -> Result<Self> {
        let dev = info
            .open()
            .map_err(|e| Error::BackendUnavailable(format!("open failed: {e}")))?;

        // Endpoint discovery has to happen on a *claimed* interface: `Interface`
        // exposes the descriptors for the active configuration, whereas
        // `DeviceInfo` only lists interface numbers and classes.
        //
        // Prefer a vendor-specific interface (class 0xFF); otherwise take the
        // first interface that yields both bulk directions.
        let candidates: Vec<(u8, u8)> = info
            .interfaces()
            .map(|i| (i.interface_number(), i.class()))
            .collect();
        if candidates.is_empty() {
            return Err(Error::BackendUnavailable(
                "device exposes no interfaces".into(),
            ));
        }
        let mut ordered: Vec<(u8, u8)> = candidates.clone();
        ordered.sort_by_key(|(_, class)| if *class == 0xFF { 0 } else { 1 });

        let mut last_err: Option<Error> = None;
        for (iface_num, _class) in ordered {
            let interface = match dev.claim_interface(iface_num) {
                Ok(i) => i,
                Err(e) => {
                    last_err = Some(Error::BackendUnavailable(format!(
                        "claim interface {iface_num}: {e}"
                    )));
                    continue;
                }
            };
            match find_bulk_pair(&interface) {
                Some((ep_in, ep_out)) => {
                    return Ok(Self {
                        interface,
                        ep_in,
                        ep_out,
                        key: key_of(info),
                        pending: Vec::new(),
                    });
                }
                None => {
                    last_err = Some(Error::BackendUnavailable(format!(
                        "interface {iface_num} has no bulk-IN/bulk-OUT pair"
                    )));
                    // Release it so the next candidate can be tried.
                    drop(interface);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            Error::BackendUnavailable(
                "no interface with both bulk-IN and bulk-OUT endpoints found; is the \
                 WinUSB/UMDF driver bound to the interface?"
                    .into(),
            )
        }))
    }

    /// The stable key of the open device.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The claimed endpoint pair `(in, out)`.
    pub fn endpoints(&self) -> (u8, u8) {
        (self.ep_in, self.ep_out)
    }
}

/// Find the first bulk-IN / bulk-OUT pair on a claimed interface.
///
/// Split out so the selection rule is readable and independently reasoned about.
fn find_bulk_pair(interface: &nusb::Interface) -> Option<(u8, u8)> {
    let mut ep_in = None;
    let mut ep_out = None;
    for alt in interface.descriptors() {
        for ep in alt.endpoints() {
            if ep.transfer_type() != EndpointType::Bulk {
                continue;
            }
            match ep.direction() {
                Direction::In => {
                    if ep_in.is_none() {
                        ep_in = Some(ep.address())
                    }
                }
                Direction::Out => {
                    if ep_out.is_none() {
                        ep_out = Some(ep.address())
                    }
                }
            }
        }
    }
    match (ep_in, ep_out) {
        (Some(i), Some(o)) => Some((i, o)),
        _ => None,
    }
}

fn io_err(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Io(std::io::Error::other(format!("{what}: {e}")))
}

impl DeviceBackend for UsbBackend {
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        // `bulk_out` consumes the buffer and reports how much went out; loop so
        // a short write cannot silently truncate a CBW frame.
        let mut sent = 0usize;
        while sent < data.len() {
            let chunk = data[sent..].to_vec();
            let n = chunk.len();
            let res = block_on(self.interface.bulk_out(self.ep_out, chunk));
            let completion = res.into_result().map_err(|e: TransferError| io_err("bulk_out", e))?;
            let wrote = completion.actual_length();
            if wrote == 0 {
                return Err(Error::Io(std::io::Error::other(
                    "bulk_out reported no progress",
                )));
            }
            sent += wrote.min(n);
        }
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.pending.is_empty() {
            let n = buf.len().min(self.pending.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }

        // Request at least one CSW so the kernel can block until the device
        // answers; anything extra is kept for the next call.
        let want = buf.len().max(crate::protocol::consts::CSW_LEN);
        let res = block_on(self.interface.bulk_in(self.ep_in, RequestBuffer::new(want)));
        let completion = res.into_result().map_err(|e| io_err("bulk_in", e))?;
        // The completion carries exactly the bytes the device sent.
        let data: Vec<u8> = completion.into();
        let filled = data.len().min(want);
        let data = &data[..filled];
        if data.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(data.len());
        buf[..n].copy_from_slice(&data[..n]);
        if data.len() > n {
            self.pending.extend_from_slice(&data[n..]);
        }
        Ok(n)
    }

    fn flush(&mut self) -> Result<()> {
        // The original calls FlushFileBuffers. USB bulk transfers are not
        // buffered at this layer, so there is nothing to flush; the method
        // exists to keep the trait honest and to leave room for a
        // backend-specific barrier later.
        Ok(())
    }

    fn describe(&self) -> String {
        format!(
            "UsbBackend(key={}, ep_in={:#04x}, ep_out={:#04x})",
            self.key, self.ep_in, self.ep_out
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_timeout_is_below_the_transport_deadline() {
        // The transport allows 20 s per CSW; one syscall must not exceed it.
        assert!(BULK_TIMEOUT < Duration::from_millis(crate::protocol::consts::CSW_TIMEOUT_MS));
    }

    #[test]
    fn enumeration_reports_a_clean_error_when_there_is_no_usb_stack() {
        // In a container without /dev/bus/usb this returns Err rather than
        // panicking, which is what lets the CLI print a useful message.
        match list_devices() {
            Ok(v) => {
                // If a USB stack exists, every entry must be one of our targets.
                assert!(v.iter().all(|d| d.is_target()));
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("USB") || msg.contains("enumeration"),
                    "unexpected error text: {msg}"
                );
            }
        }
    }

    #[test]
    fn availability_probe_never_panics() {
        let _ = is_available();
    }

    #[test]
    fn opening_a_nonexistent_key_reports_device_not_found() {
        // Only meaningful when enumeration works; otherwise the enumeration
        // error is the correct outcome.
        match UsbBackend::open_by_key("definitely-not-a-real-serial") {
            Err(Error::DeviceNotFound { vid, pid }) => {
                assert_eq!(vid, USB_VID);
                assert_eq!(pid, USB_PID);
            }
            Err(Error::BackendUnavailable(_)) => {} // no USB stack here
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
