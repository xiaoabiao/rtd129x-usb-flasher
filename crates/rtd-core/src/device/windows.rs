//! Windows device backend: `CreateFile` on the RTUMDFDRV device interface.
//!
//! # Why not WinUSB
//!
//! The `rtumdfdrv64.inf` shipped with the original tool *does* pull in WinUSB,
//! but only as a **lower filter** with `UmdfDispatcher = WinUsb`: the UMDF driver
//! (`rtumdfdrv64.dll`, service `WUDFRd`, class `RTKCls`) is the *function*
//! driver and uses WinUSB internally. A user-mode application therefore cannot
//! drive the device through the WinUSB API -- `nusb` enumerates it but reports
//! **zero interfaces**, because the WinUSB device interface carries no
//! configuration descriptors for it to read.
//!
//! What does work is what the original tool does: open the UMDF device interface
//! with `CreateFile` and move bytes with `ReadFile` / `WriteFile`. Verified
//! against the real board:
//!
//! ```text
//! \\?\usb#vid_0bda&pid_1195#0357802115946#{7b56a5d6-cd10-4410-9f59-9a5e71269882}
//! ```
//!
//! # The original's open call
//!
//! `OpenDevice` @0x004047C0 decompiles to:
//!
//! ```c
//! CreateFileA(path, 0xc0000000, 3, NULL, 3, 0, NULL);
//! ```
//!
//! which is `GENERIC_READ | GENERIC_WRITE`, `FILE_SHARE_READ | FILE_SHARE_WRITE`,
//! `OPEN_EXISTING`, and **no** `FILE_FLAG_OVERLAPPED`. `PerformReadTest`
//! @0x00406F40 likewise calls `ReadFile(h, buf, len, &got, NULL)` synchronously.
//! So the I/O model is plain blocking I/O, which `std::fs::File` provides
//! directly.
//!
//! # Enumeration
//!
//! Interface paths embed the device serial, which cannot be guessed, so a list
//! is needed first. `nusb` already enumerates these devices correctly (it just
//! cannot *open* them), so it is reused purely as the enumerator.

#[cfg(all(windows, feature = "usb"))]
use std::fs::{File, OpenOptions};
#[cfg(all(windows, feature = "usb"))]
use std::io::{Read, Write};

#[cfg(all(windows, feature = "usb"))]
use crate::device::filter::UsbDeviceInfo;
#[cfg(all(windows, feature = "usb"))]
use crate::device::DeviceBackend;
#[cfg(all(windows, feature = "usb"))]
use crate::error::{Error, Result};
use crate::protocol::consts::{USB_PID, USB_VID};

/// Device interface GUID the `rtumdfdrv` UMDF driver registers.
///
/// Taken from the device path recorded in the original tool's own debug log, so
/// it is an observed value rather than a guess.
pub const RTUMDFDRV_INTERFACE_GUID: &str = "7b56a5d6-cd10-4410-9f59-9a5e71269882";

/// Build the interface path for a device serial.
///
/// Windows device paths are `\\?\<device-instance>#{interface-guid}`, with `#`
/// replacing `\`. Case does not matter to the object manager, but the serial
/// must match exactly.
pub fn device_path(serial: &str) -> String {
    format!(
        r"\\?\usb#vid_{USB_VID:04x}&pid_{USB_PID:04x}#{serial}#{{{RTUMDFDRV_INTERFACE_GUID}}}"
    )
}

/// Enumerate attached devices.
///
/// Uses `nusb` for the list only; see the module docs for why it cannot be used
/// to open them.
#[cfg(all(windows, feature = "usb"))]
pub fn list_devices() -> Result<Vec<UsbDeviceInfo>> {
    crate::device::usb::list_devices()
}

/// A device opened through its UMDF interface path.
#[cfg(all(windows, feature = "usb"))]
#[derive(Debug)]
pub struct WindowsBackend {
    file: File,
    key: String,
    path: String,
    /// The first `FlushFileBuffers` error, kept for the log. The call is a hint
    /// and never fails the burn; see `flush`.
    flush_error: Option<String>,
}

/// Whether an I/O error just means "the board has not answered yet".
///
/// `ReadFile` on the UMDF/WinUSB pipe returns `ERROR_SEM_TIMEOUT` (121) when the
/// device sends nothing within the pipe timeout. `PerformReadTest` in the
/// original treats that as "keep polling", and so do we. 995 is
/// `ERROR_OPERATION_ABORTED`, which surfaces the same way when the pipe is torn
/// down.
#[cfg(all(windows, feature = "usb"))]
fn is_retryable_io(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
    ) || matches!(e.raw_os_error(), Some(121) | Some(995))
}

#[cfg(all(windows, feature = "usb"))]
impl WindowsBackend {
    /// Open a device by its key (serial, or `000:address`).
    pub fn open_by_key(key: &str) -> Result<Self> {
        // Only a real serial can form a path; the `bus:address` fallback key is
        // not usable here, so resolve it back to a serial first.
        let serial = if key.contains(':') && key.len() <= 7 {
            list_devices()?
                .into_iter()
                .find(|d| d.key() == key)
                .and_then(|d| d.serial)
                .ok_or_else(|| {
                    Error::BackendUnavailable(format!(
                        "device {key} has no serial number; cannot form an interface path"
                    ))
                })?
        } else {
            key.to_string()
        };
        Self::open_serial(&serial)
    }

    /// Open the first attached device.
    pub fn open_first() -> Result<Self> {
        let dev = list_devices()?.into_iter().next().ok_or(Error::DeviceNotFound {
            vid: USB_VID,
            pid: USB_PID,
        })?;
        let serial = dev.serial.ok_or_else(|| {
            Error::BackendUnavailable(
                "device reports no serial number; cannot form an interface path".into(),
            )
        })?;
        Self::open_serial(&serial)
    }

    /// Open one specific serial.
    pub fn open_serial(serial: &str) -> Result<Self> {
        let path = device_path(serial);
        // `std::fs::OpenOptions` issues `CreateFileW` with
        // `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`, which is a
        // superset of what the original requests, and no overlapped flag -- so
        // reads and writes are synchronous, matching `ReadFile`/`WriteFile` in
        // the original.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| {
                Error::BackendUnavailable(format!(
                    "CreateFile failed on {path}: {e}\n\
                     Is the board plugged in and the rtumdfdrv driver installed?"
                ))
            })?;
        // The original does all I/O on this one handle, synchronously; there is
        // deliberately no reader thread (see `read`).
        Ok(Self {
            file,
            key: serial.to_string(),
            path,
            flush_error: None,
        })
    }

    /// The first `FlushFileBuffers` error, if the driver rejected it.
    ///
    /// The burn is unaffected -- `flush` is a hint -- but the text belongs in
    /// the log, because a driver that refuses it is worth knowing about.
    pub fn flush_error(&self) -> Option<&str> {
        self.flush_error.as_deref()
    }

    /// The interface path that was opened.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The device key (serial).
    pub fn key(&self) -> &str {
        &self.key
    }
}

#[cfg(all(windows, feature = "usb"))]
impl DeviceBackend for WindowsBackend {
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.file.write_all(data)?;
        Ok(())
    }

    /// One synchronous `ReadFile`, exactly like the original.
    ///
    /// `PerformReadTest` @0x00406F40 calls `ReadFile(h, buf, len, &got, NULL)`
    /// and loops on failure -- there is **no background reader thread** in the
    /// original. A 4096-byte reader issuing reads back to back was a real bug
    /// source: while it sat in a 10 s pipe timeout, the next payload `WriteFile`
    /// on the same handle could be starved, so a chunk the board was ready for
    /// looked like a device that had stopped consuming data. A USBPcap capture of
    /// our own failing burn showed exactly that pattern (10 s `0xC0010000` read
    /// timeouts interleaved with a payload write that took 70 s to get through).
    ///
    /// `Ok(0)` means "nothing available right now" (pipe timeout mapped to a
    /// non-error), which is what the transport's retry loop expects. It is not
    /// EOF.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.file.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if is_retryable_io(&e) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    fn flush(&mut self) -> Result<()> {
        // `FlushFileBuffers` is a buffering hint, not part of the protocol: the
        // bytes were handed to the driver by `WriteFile` already.
        //
        // There is a trap here. `FlushFileBuffers` fails with
        // `ERROR_NOT_SUPPORTED` on many device handles, and **Rust does not map
        // that code to `ErrorKind::Unsupported`** -- it surfaces as `Other` with
        // `raw_os_error() == Some(50)`. Matching on the kind alone therefore
        // misses it and turns a harmless hint into a failed burn.
        //
        // So: never fail here, whatever the error. Record the first one so a
        // genuine problem is still visible in the log.
        match self.file.sync_all() {
            Ok(()) => Ok(()),
            Err(e) => {
                if self.flush_error.is_none() {
                    self.flush_error = Some(format!("FlushFileBuffers: {e}（已忽略）"));
                }
                Ok(())
            }
        }
    }

    fn describe(&self) -> String {
        format!("WindowsBackend(serial={}, path={})", self.key, self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_path_matches_the_recorded_one() {
        // The exact string the original tool logged for the board under test.
        assert_eq!(
            device_path("0357802115946"),
            r"\\?\usb#vid_0bda&pid_1195#0357802115946#{7b56a5d6-cd10-4410-9f59-9a5e71269882}"
        );
    }

    #[test]
    fn device_path_uses_lowercase_hex_ids() {
        let p = device_path("X");
        assert!(p.contains("vid_0bda"), "{p}");
        assert!(p.contains("pid_1195"), "{p}");
        assert!(p.starts_with(r"\\?\usb#"), "{p}");
        assert!(p.ends_with('}'), "{p}");
    }

    /// `FlushFileBuffers` must never fail the burn.
    ///
    /// This pins the trap that broke a real flash: the call returns
    /// `ERROR_NOT_SUPPORTED` on device handles, and matching only on
    /// `ErrorKind::Unsupported` misses it -- Rust does not guarantee that
    /// mapping, and on the affected path the error surfaced as a raw os error
    /// that killed the transfer right after the first payload write.
    #[test]
    fn a_flush_failure_does_not_fail_the_burn() {
        let src = include_str!("windows.rs");
        // The tolerance must be unconditional: no `Err(e) => Err(..)` arm.
        let flush_body = src
            .split("fn flush(&mut self)")
            .nth(1)
            .and_then(|s| s.split("fn describe").next())
            .expect("flush body");
        assert!(
            !flush_body.contains("Err(Error::Io"),
            "flush must tolerate every error, not just ErrorKind::Unsupported"
        );
        assert!(
            flush_body.contains("self.flush_error = Some"),
            "flush should still record the first error for the log"
        );
    }

    #[test]
    fn the_guid_is_the_rtumdfdrv_one() {
        // 32 hex digits in 8-4-4-4-12 form, and specifically the value from the
        // original tool's log -- not the standard WinUSB GUID.
        let g = RTUMDFDRV_INTERFACE_GUID;
        assert_eq!(g.len(), 36);
        assert_eq!(g.matches('-').count(), 4);
        assert_ne!(
            g, "a5dcbf10-6530-11d2-901f-00c04fb951ed",
            "must not be the generic WinUSB interface GUID"
        );
        assert_eq!(g, "7b56a5d6-cd10-4410-9f59-9a5e71269882");
    }

    #[test]
    #[cfg(all(windows, feature = "usb"))]
    fn opening_a_bogus_serial_fails_with_an_actionable_message() {
        // No hardware needed: the path is well-formed but names no device.
        match WindowsBackend::open_serial("definitely-not-a-real-serial") {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("CreateFile failed") || msg.contains("rtumdfdrv"),
                    "message should explain what to check: {msg}"
                );
            }
            Ok(_) => panic!("opening a bogus serial must not succeed"),
        }
    }

    #[test]
    #[cfg(all(windows, feature = "usb"))]
    fn enumeration_never_panics() {
        match list_devices() {
            Ok(v) => assert!(v.iter().all(|d| d.is_target())),
            Err(e) => eprintln!("note: enumeration unavailable here: {e}"),
        }
    }
}
