//! What the running Windows system reports for `bme flash doctor`.
//!
//! Windows has no sysfs. The board identity comes from the registry copy of the SMBIOS
//! strings, and USB devices with their drivers come from SetupAPI. The reader is thin and
//! exists only on Windows; the data types and the parsing are plain, so tests build
//! [`WindowsFacts`] directly.

use std::collections::BTreeMap;

/// The registry key under `HKEY_LOCAL_MACHINE` holding the firmware's SMBIOS strings.
pub const BIOS_KEY: &str = r"HARDWARE\DESCRIPTION\System\BIOS";

/// The registry value under [`BIOS_KEY`] for each DMI field, named as on Linux.
///
/// These are the model-level strings Linux publishes in `/sys/class/dmi/id`; Windows keeps
/// no serial number or UUID under this key.
pub const DMI_REGISTRY_VALUES: [(&str, &str); 11] = [
    ("sys_vendor", "SystemManufacturer"),
    ("product_name", "SystemProductName"),
    ("product_version", "SystemVersion"),
    ("product_family", "SystemFamily"),
    ("product_sku", "SystemSKU"),
    ("board_vendor", "BaseBoardManufacturer"),
    ("board_name", "BaseBoardProduct"),
    ("board_version", "BaseBoardVersion"),
    ("bios_vendor", "BIOSVendor"),
    ("bios_version", "BIOSVersion"),
    ("bios_date", "BIOSReleaseDate"),
];

/// One present USB device node. Each interface of a composite device is a node of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDevice {
    /// Lowercase hexadecimal vendor id, e.g. `1a86`.
    pub vendor: String,
    /// Lowercase hexadecimal product id, e.g. `5512`.
    pub product: String,
    /// The driver service bound to the node (`WinUSB`, `CH341PAR`, `usbccgp`), if any.
    pub service: Option<String>,
}

/// The facts the flash diagnosis reads on Windows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsFacts {
    /// Whether the process holds an elevated (administrator) token; `None` when unreadable.
    pub elevated: Option<bool>,
    /// The readable, nonempty [`DMI_REGISTRY_VALUES`] by DMI field name.
    pub dmi: BTreeMap<&'static str, String>,
    /// Present USB device nodes.
    pub usb: Vec<UsbDevice>,
}

/// Vendor and product id of a USB device instance id.
///
/// Only the ids are kept: the rest of an instance id is often the device's serial number.
/// Example: `usb_ids(r"USB\VID_1A86&PID_5512\5&2A3B&0&4")` is `Some(("1a86", "5512"))`, and an
/// interface such as `USB\VID_0403&PID_6010&MI_00\6&1&0&0000` yields `("0403", "6010")`.
pub fn usb_ids(instance: &str) -> Option<(String, String)> {
    let hardware = instance.split('\\').nth(1)?.to_ascii_lowercase();
    let id = |prefix: &str| {
        let digits = hardware
            .split('&')
            .find_map(|part| part.strip_prefix(prefix))?;
        (digits.len() == 4 && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| digits.to_string())
    };
    Some((id("vid_")?, id("pid_")?))
}

/// Read the facts of the running system.
///
/// Example: `read().dmi.get("board_name")` is `Some("E5-MR9A PRO")` on the MR9A.
#[cfg(windows)]
pub fn read() -> WindowsFacts {
    WindowsFacts {
        elevated: system::elevated(),
        dmi: DMI_REGISTRY_VALUES
            .iter()
            .filter_map(|(field, value)| Some((*field, system::bios_string(value)?)))
            .collect(),
        usb: system::usb_devices(),
    }
}

#[cfg(windows)]
mod system {
    use super::{BIOS_KEY, UsbDevice, usb_ids};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        DIGCF_ALLCLASSES, DIGCF_PRESENT, SP_DEVINFO_DATA, SPDRP_SERVICE,
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
        SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// UTF-16 characters read from one registry string or device property; longer ones are skipped.
    const TEXT_UNITS: usize = 512;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    /// The text before the first NUL, trimmed; `None` when empty.
    fn text(units: &[u16]) -> Option<String> {
        let end = units
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(units.len());
        let text = String::from_utf16_lossy(&units[..end]).trim().to_string();
        (!text.is_empty()).then_some(text)
    }

    pub fn elevated() -> Option<bool> {
        let mut token: HANDLE = null_mut();
        // SAFETY: the current-process pseudo handle needs no closing; `token` receives a handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut written = 0u32;
        // SAFETY: the buffer is one TOKEN_ELEVATION and its exact size is passed.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&raw mut elevation).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut written,
            )
        };
        // SAFETY: `token` was opened above and is closed exactly once.
        unsafe { CloseHandle(token) };
        (read != 0).then_some(elevation.TokenIsElevated != 0)
    }

    pub fn bios_string(value: &str) -> Option<String> {
        let (key, value) = (wide(BIOS_KEY), wide(value));
        let mut buffer = [0u16; TEXT_UNITS];
        let mut bytes = size_of_val(&buffer) as u32;
        // SAFETY: key and value are NUL-terminated; `buffer` holds `bytes` bytes.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        (status == ERROR_SUCCESS).then(|| text(&buffer)).flatten()
    }

    pub fn usb_devices() -> Vec<UsbDevice> {
        let enumerator = wide("USB");
        // SAFETY: a null class with DIGCF_ALLCLASSES lists every class; the enumerator is
        // NUL-terminated and no window owns the call.
        let set = unsafe {
            SetupDiGetClassDevsW(
                null(),
                enumerator.as_ptr(),
                null_mut(),
                DIGCF_ALLCLASSES | DIGCF_PRESENT,
            )
        };
        if set == -1 {
            return Vec::new();
        }
        let mut devices = Vec::new();
        for index in 0.. {
            // SAFETY: SP_DEVINFO_DATA is plain data; zero is a valid value before cbSize is set.
            let mut node: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
            node.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
            // SAFETY: `set` is a live device information set and `node` has its size set.
            if unsafe { SetupDiEnumDeviceInfo(set, index, &mut node) } == 0 {
                break;
            }
            let mut instance = [0u16; TEXT_UNITS];
            // SAFETY: `instance` holds TEXT_UNITS characters, the size passed.
            let named = unsafe {
                SetupDiGetDeviceInstanceIdW(
                    set,
                    &node,
                    instance.as_mut_ptr(),
                    TEXT_UNITS as u32,
                    null_mut(),
                )
            };
            let Some((vendor, product)) = (named != 0)
                .then(|| text(&instance))
                .flatten()
                .and_then(|instance| usb_ids(&instance))
            else {
                continue;
            };
            let mut service = [0u16; TEXT_UNITS];
            // SAFETY: `service` holds the number of bytes passed.
            let serviced = unsafe {
                SetupDiGetDeviceRegistryPropertyW(
                    set,
                    &node,
                    SPDRP_SERVICE,
                    null_mut(),
                    service.as_mut_ptr().cast(),
                    size_of_val(&service) as u32,
                    null_mut(),
                )
            };
            devices.push(UsbDevice {
                vendor,
                product,
                service: (serviced != 0).then(|| text(&service)).flatten(),
            });
        }
        // SAFETY: `set` came from SetupDiGetClassDevsW and is destroyed exactly once.
        unsafe { SetupDiDestroyDeviceInfoList(set) };
        devices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_ids_keep_only_vendor_and_product() {
        for (instance, expected) in [
            (r"USB\VID_1A86&PID_5512\5&2A3B&0&4", Some(("1a86", "5512"))),
            (
                r"USB\VID_0403&PID_6010&MI_00\6&1&0&0000",
                Some(("0403", "6010")),
            ),
            (r"usb\vid_0483&pid_dada\SERIAL123", Some(("0483", "dada"))),
            (r"USB\ROOT_HUB30\4&1&0", None),
            (r"USB\VID_1A86&PID_55\5&2", None),
            (r"USB\VID_ZZZZ&PID_5512\5&2", None),
            ("", None),
        ] {
            let received = usb_ids(instance);
            let expected =
                expected.map(|(vendor, product)| (vendor.to_string(), product.to_string()));
            assert_eq!(
                received, expected,
                "usb_ids({instance:?}): expected {expected:?} | received {received:?}"
            );
        }
    }

    #[test]
    fn dmi_registry_values_map_each_field_once() {
        let mut fields: Vec<&str> = DMI_REGISTRY_VALUES
            .iter()
            .map(|(field, _)| *field)
            .collect();
        fields.sort_unstable();
        fields.dedup();
        assert_eq!(
            fields.len(),
            DMI_REGISTRY_VALUES.len(),
            "DMI_REGISTRY_VALUES: expected unique DMI fields | received a repeated one"
        );
        for (field, _) in DMI_REGISTRY_VALUES {
            assert!(
                crate::identity::DMI_IDENTITY_FIELDS.contains(&field),
                "DMI field {field:?}: expected one of DMI_IDENTITY_FIELDS | received an unknown name"
            );
        }
    }

    /// The real reader against the running system: CI's Windows runner has a process token
    /// and a firmware identity, so both must come back.
    #[cfg(windows)]
    #[test]
    fn reading_the_running_system_returns_elevation_and_identity() {
        let facts = read();
        assert!(
            facts.elevated.is_some(),
            "elevated: expected Some(true | false) | received None"
        );
        assert!(
            facts.dmi.contains_key("bios_vendor"),
            "dmi: expected a bios_vendor entry | received {:?}",
            facts.dmi.keys().collect::<Vec<_>>()
        );
    }
}
