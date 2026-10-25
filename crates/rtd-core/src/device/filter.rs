//! Pure device selection logic.
//!
//! These functions contain **no USB calls**, so they are fully unit-tested even
//! in an environment with no USB stack. The real backend in
//! [`super::usb`] feeds them [`UsbDeviceInfo`] values.
//!
//! # What the original looks for
//!
//! `ListDevice` @0x004047A0 calls `GetDeviceList(&GUID_DEVINTERFACE_RTUMDFDRV, …)`
//! with that single interface GUID, and the driver's INF matches
//! `USB\Vid_0bda&Pid_1195`. The device path it then opens looks like:
//!
//! ```text
//! \\?\usb#vid_0bda&pid_1195#0357802115946#{7b56a5d6-cd10-4410-9f59-9a5e71269882}
//! ```
//!
//! So the device is identified by the **VID/PID pair**, and the serial number
//! (the `0357802115946` segment) is what distinguishes boards when several are
//! attached. `MAX USB CONNECTION=8` in `SYSTEM.ini` is the tool's concurrency
//! limit.

use crate::protocol::consts::{USB_PID, USB_VID};

/// One candidate device, as the filter sees it.
///
/// This is a plain data record on purpose: it can be constructed in tests and
/// is also what the USB backend projects from `nusb`'s descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDeviceInfo {
    /// Bus number.
    pub bus: u8,
    /// Device address on that bus (changes on every re-plug).
    pub address: u8,
    /// Vendor id.
    pub vendor_id: u16,
    /// Product id.
    pub product_id: u16,
    /// Serial string, when the device exposes one.
    pub serial: Option<String>,
    /// Product string, when available.
    pub product: Option<String>,
    /// Number of interfaces the device exposes.
    pub interface_count: u8,
}

impl UsbDeviceInfo {
    /// A stable identity for logs and for keying per-device state.
    ///
    /// Prefers the serial number; falls back to `bus:address` which is only
    /// valid until the next re-plug.
    pub fn key(&self) -> String {
        match &self.serial {
            Some(s) if !s.is_empty() => s.clone(),
            _ => format!("{:03}:{:03}", self.bus, self.address),
        }
    }

    /// Whether this is the RTD129x download interface.
    pub fn is_target(&self) -> bool {
        self.vendor_id == USB_VID && self.product_id == USB_PID
    }

    /// A human-readable one-liner.
    pub fn describe(&self) -> String {
        format!(
            "{:04x}:{:04x} bus {} addr {}{}{}",
            self.vendor_id,
            self.product_id,
            self.bus,
            self.address,
            self.serial
                .as_ref()
                .map(|s| format!(" serial {s}"))
                .unwrap_or_default(),
            self.product
                .as_ref()
                .map(|p| format!(" [{p}]"))
                .unwrap_or_default(),
        )
    }
}

/// Filter a device list down to the RTD129x targets.
///
/// Order is preserved so a UI list stays stable.
pub fn select_targets<'a, I>(devices: I) -> Vec<&'a UsbDeviceInfo>
where
    I: IntoIterator<Item = &'a UsbDeviceInfo>,
{
    devices.into_iter().filter(|d| d.is_target()).collect()
}

/// Sort devices into a deterministic, human-friendly order.
///
/// Sorted by serial (so the order does not change when a device is re-plugged
/// and its bus address changes), then by `bus:address` for devices without one.
pub fn sort_stable(devices: &mut [UsbDeviceInfo]) {
    devices.sort_by(|a, b| match (&a.serial, &b.serial) {
        (Some(x), Some(y)) => x.cmp(y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => (a.bus, a.address).cmp(&(b.bus, b.address)),
    });
}

/// Why a requested device count cannot be honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitIssue {
    /// No target devices were found.
    NoneFound,
    /// More devices are attached than the configured limit allows.
    TooMany {
        /// How many target devices were found.
        found: usize,
        /// The configured limit.
        limit: usize,
    },
}

/// Check a discovered device count against the configured limit.
///
/// `SYSTEM.ini` ships `MAX USB CONNECTION=8`; the original runs one worker
/// thread per device.
pub fn check_limit(found: usize, limit: usize) -> Option<LimitIssue> {
    if found == 0 {
        return Some(LimitIssue::NoneFound);
    }
    if limit > 0 && found > limit {
        return Some(LimitIssue::TooMany { found, limit });
    }
    None
}

/// Cap a device list to the configured limit, keeping stable order.
pub fn apply_limit(devices: &mut Vec<UsbDeviceInfo>, limit: usize) -> usize {
    if limit == 0 || devices.len() <= limit {
        return 0;
    }
    let dropped = devices.len() - limit;
    devices.truncate(limit);
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(vid: u16, pid: u16, bus: u8, addr: u8, serial: Option<&str>) -> UsbDeviceInfo {
        UsbDeviceInfo {
            bus,
            address: addr,
            vendor_id: vid,
            product_id: pid,
            serial: serial.map(str::to_string),
            product: None,
            interface_count: 1,
        }
    }

    #[test]
    fn the_target_ids_come_from_the_driver_inf() {
        assert_eq!(USB_VID, 0x0BDA);
        assert_eq!(USB_PID, 0x1195);
    }

    #[test]
    fn only_the_target_pair_is_selected() {
        let all = vec![
            dev(0x0BDA, 0x1195, 1, 5, Some("A")), // target
            dev(0x0BDA, 0x8179, 1, 6, Some("B")), // Realtek ethernet, not target
            dev(0x1234, 0x1195, 1, 7, Some("C")), // wrong vendor
            dev(0x0BDA, 0x1195, 2, 9, None),      // target, no serial
        ];
        let picked = select_targets(&all);
        assert_eq!(picked.len(), 2);
        assert_eq!(picked[0].serial.as_deref(), Some("A"));
        assert!(picked[1].serial.is_none());
    }

    #[test]
    fn selection_preserves_input_order() {
        let all = vec![
            dev(0x0BDA, 0x1195, 3, 1, Some("zz")),
            dev(0x0BDA, 0x1195, 1, 2, Some("aa")),
        ];
        let picked = select_targets(&all);
        assert_eq!(picked[0].serial.as_deref(), Some("zz"));
        assert_eq!(picked[1].serial.as_deref(), Some("aa"));
    }

    #[test]
    fn stable_sort_prefers_serial_then_bus_address() {
        let mut all = vec![
            dev(0x0BDA, 0x1195, 9, 9, None),
            dev(0x0BDA, 0x1195, 2, 3, Some("bbb")),
            dev(0x0BDA, 0x1195, 1, 1, Some("aaa")),
            dev(0x0BDA, 0x1195, 4, 4, None),
        ];
        sort_stable(&mut all);
        let keys: Vec<String> = all.iter().map(|d| d.key()).collect();
        assert_eq!(keys, vec!["aaa", "bbb", "004:004", "009:009"]);
    }

    #[test]
    fn a_device_without_a_serial_still_has_a_key() {
        let d = dev(0x0BDA, 0x1195, 3, 7, None);
        assert_eq!(d.key(), "003:007");
        // and an empty serial is treated as absent
        let d = dev(0x0BDA, 0x1195, 3, 7, Some(""));
        assert_eq!(d.key(), "003:007");
    }

    #[test]
    fn describe_includes_the_ids_and_location() {
        let d = dev(0x0BDA, 0x1195, 1, 5, Some("0357802115946"));
        let s = d.describe();
        assert!(s.contains("0bda:1195"), "{s}");
        assert!(s.contains("0357802115946"), "{s}");
    }

    #[test]
    fn limit_reports_none_found_separately_from_too_many() {
        assert_eq!(check_limit(0, 8), Some(LimitIssue::NoneFound));
        assert_eq!(check_limit(1, 8), None);
        assert_eq!(check_limit(8, 8), None);
        assert_eq!(check_limit(9, 8), Some(LimitIssue::TooMany { found: 9, limit: 8 }));
        // limit 0 means "unlimited"
        assert_eq!(check_limit(100, 0), None);
        assert_eq!(check_limit(0, 0), Some(LimitIssue::NoneFound));
    }

    #[test]
    fn apply_limit_truncates_and_reports_dropped() {
        let mut v: Vec<UsbDeviceInfo> = (0..10)
            .map(|i| dev(0x0BDA, 0x1195, 1, i as u8, None))
            .collect();
        assert_eq!(apply_limit(&mut v, 8), 2);
        assert_eq!(v.len(), 8);

        let mut v: Vec<UsbDeviceInfo> = (0..3)
            .map(|i| dev(0x0BDA, 0x1195, 1, i as u8, None))
            .collect();
        assert_eq!(apply_limit(&mut v, 8), 0);
        assert_eq!(v.len(), 3);

        // limit 0 leaves everything
        let mut v: Vec<UsbDeviceInfo> = (0..5)
            .map(|i| dev(0x0BDA, 0x1195, 1, i as u8, None))
            .collect();
        assert_eq!(apply_limit(&mut v, 0), 0);
        assert_eq!(v.len(), 5);
    }

    #[test]
    fn the_shipped_limit_is_eight() {
        // SYSTEM.ini ships MAX USB CONNECTION=8; keep that as the default in
        // mind when wiring the CLI.
        const SHIPPED_LIMIT: usize = 8;
        assert_eq!(check_limit(9, SHIPPED_LIMIT), Some(LimitIssue::TooMany { found: 9, limit: 8 }));
    }
}
