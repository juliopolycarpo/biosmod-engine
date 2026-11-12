//! Which machine and which boot a reading belongs to.

use crate::files::{HostFiles, read_trimmed};
use biosmod_core::{Code, Error, Result};
use std::collections::BTreeMap;

pub const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
pub const KERNEL_RELEASE_PATH: &str = "/proc/sys/kernel/osrelease";
pub const KERNEL_VERSION_PATH: &str = "/proc/version";
pub const DMI_ROOT: &str = "/sys/class/dmi/id";

/// DMI fields that describe the model, never the unit: serial numbers, UUIDs and
/// asset tags are root-only on Linux and deliberately absent.
pub const DMI_IDENTITY_FIELDS: [&str; 14] = [
    "sys_vendor",
    "product_name",
    "product_version",
    "product_family",
    "product_sku",
    "board_vendor",
    "board_name",
    "board_version",
    "bios_vendor",
    "bios_version",
    "bios_date",
    "bios_release",
    "chassis_vendor",
    "chassis_type",
];

/// The readable DMI `fields` by name, from `/sys/class/dmi/id`. Fields that are missing,
/// unreadable or empty are left out.
///
/// Intent: one reader for every command that identifies the board, so the flash
/// diagnosis and the receipts cannot disagree about what DMI says.
///
/// Example: `read_dmi_fields(&files, &["board_name"])["board_name"]` is `"E5-MR9A PRO"` on the MR9A.
pub fn read_dmi_fields(
    files: &dyn HostFiles,
    fields: &[&'static str],
) -> BTreeMap<&'static str, String> {
    fields
        .iter()
        .filter_map(|field| {
            read_trimmed(files, &format!("{DMI_ROOT}/{field}")).map(|value| (*field, value))
        })
        .collect()
}

/// Boot, kernel and board identity as the running system reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentity {
    pub boot_id: String,
    pub kernel_release: String,
    /// `/proc/version`, when readable.
    pub kernel_version: Option<String>,
    /// The readable [`DMI_IDENTITY_FIELDS`] by name.
    pub dmi: BTreeMap<&'static str, String>,
}

impl HostIdentity {
    /// Read the identity; the boot ID and kernel release are required because a
    /// receipt without them cannot be tied to a boot.
    ///
    /// Example: `HostIdentity::read(&RootedFiles::system())?.dmi["board_name"]`.
    pub fn read(files: &dyn HostFiles) -> Result<HostIdentity> {
        let required = |path: &str| {
            read_trimmed(files, path).ok_or_else(|| {
                Error::new(
                    Code::Io,
                    format!("{path}: expected a readable nonempty file | received nothing"),
                )
            })
        };
        let dmi = read_dmi_fields(files, &DMI_IDENTITY_FIELDS);
        Ok(HostIdentity {
            boot_id: required(BOOT_ID_PATH)?,
            kernel_release: required(KERNEL_RELEASE_PATH)?,
            kernel_version: read_trimmed(files, KERNEL_VERSION_PATH),
            dmi,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::FakeSysfs;

    #[test]
    fn reads_boot_kernel_and_model_fields_but_not_serials() {
        let sysfs = FakeSysfs::mr9a().file("sys/class/dmi/id/product_serial", "SECRET\n");
        let identity = HostIdentity::read(&sysfs.files()).unwrap();
        assert_eq!(identity.boot_id, FakeSysfs::BOOT_ID);
        assert_eq!(identity.kernel_release, "7.0.0-42-generic");
        assert_eq!(identity.dmi["board_name"], "E5-MR9A PRO");
        assert!(!identity.dmi.contains_key("product_serial"));
        assert!(identity.kernel_version.is_some());
    }

    #[test]
    fn read_dmi_fields_returns_only_the_requested_readable_fields() {
        let sysfs = FakeSysfs::mr9a().file("sys/class/dmi/id/bios_date", "\n");
        let files = sysfs.files();
        let fields = read_dmi_fields(&files, &["board_name", "bios_date", "absent"]);
        assert_eq!(fields.len(), 1, "{fields:?}");
        assert_eq!(fields["board_name"], "E5-MR9A PRO");
    }

    #[test]
    fn read_dmi_fields_trims_values_and_returns_exactly_what_is_asked_for() {
        let sysfs = FakeSysfs::mr9a()
            .file("sys/class/dmi/id/bios_vendor", "  American Megatrends \n")
            .file("sys/class/dmi/id/product_serial", "SECRET\n");
        let files = sysfs.files();
        let fields = read_dmi_fields(&files, &["bios_vendor"]);
        assert_eq!(
            fields.into_iter().collect::<Vec<_>>(),
            [("bios_vendor", "American Megatrends".to_string())],
            "(read_dmi_fields): expected one trimmed field and nothing unrequested"
        );
        assert!(read_dmi_fields(&files, &[]).is_empty());
    }

    #[test]
    fn a_missing_boot_id_names_the_file() {
        let sysfs = FakeSysfs::new().file("proc/sys/kernel/osrelease", "7.0\n");
        let error = HostIdentity::read(&sysfs.files()).unwrap_err();
        assert_eq!(error.code, Code::Io);
        assert!(
            error.message.starts_with(BOOT_ID_PATH),
            "(identity): expected a message naming {BOOT_ID_PATH} | received {error}"
        );
    }
}
