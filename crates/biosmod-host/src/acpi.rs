//! `diag acpi capture`: the firmware tables the running kernel published, the
//! sleep states it offers and what it logged about sleeping.

use crate::HostSurfaces;
use crate::bundle::{Bundle, BundleBuilder};
use crate::files::{EntryKind, HostFiles};
use crate::identity::HostIdentity;
use crate::receipt::Receipt;
use biosmod_core::{Code, Error, Result};
use std::collections::BTreeMap;
use std::io::ErrorKind;

pub const TABLES_ROOT: &str = "/sys/firmware/acpi/tables";
pub const MEM_SLEEP_PATH: &str = "/sys/power/mem_sleep";
pub const STATE_PATH: &str = "/sys/power/state";
/// `tables/`, `tables/dynamic/` and `tables/data/` are the deepest the kernel goes.
const MAX_DEPTH: usize = 4;

/// Copy the ACPI tables, sleep states, sleep-related kernel messages, boot and
/// kernel identity and DMI model fields into a sealed bundle.
///
/// Reading the tables needs root, so a non-root user is refused before anything
/// is read. Tables keep their sysfs names (`DSDT`, `SSDT1`, `dynamic/SSDT3`,
/// `data/BERT`), so they pair with ACPI modules extracted from an image.
///
/// Example: `capture(&surfaces)?.get("acpi/tables/DSDT")` is the running DSDT.
pub fn capture(host: &HostSurfaces) -> Result<Bundle> {
    if !host.privilege.is_root() {
        return Err(Error::new(
            Code::HostRefused,
            format!(
                "diag acpi capture: expected effective user root | received {} (the tables are root-only; run as root)",
                host.privilege
                    .effective_user()
                    .map_or("none".to_string(), |uid| format!("uid {uid}"))
            ),
        ));
    }
    let identity = HostIdentity::read(host.files)?;
    let at = host.clock.now();
    let mut builder = BundleBuilder::new();

    let mut table_names = Vec::new();
    copy_tree(
        host.files,
        TABLES_ROOT,
        "acpi/tables",
        0,
        &mut builder,
        &mut table_names,
    )?;
    if table_names.is_empty() {
        return Err(Error::new(
            Code::TargetNotFound,
            format!("{TABLES_ROOT}: expected at least one ACPI table | received none"),
        ));
    }

    let mut sleep_states = BTreeMap::new();
    for path in [MEM_SLEEP_PATH, STATE_PATH] {
        let name = format!("power/{}", path.rsplit('/').next().unwrap_or(path));
        match host.files.read(path) {
            Ok(bytes) => {
                sleep_states.insert(
                    name.clone(),
                    String::from_utf8_lossy(&bytes).trim().to_string(),
                );
                builder.add(&name, bytes)?;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => builder.skip(path, "not present"),
            Err(e) => return Err(Error::new(Code::Io, format!("{path}: {e}"))),
        }
    }

    let sleep_lines: Vec<String> = host
        .kernel_log
        .records()?
        .iter()
        .filter(|record| record.is_sleep_related())
        .map(|record| record.render())
        .collect();
    let mut log = sleep_lines.join("\n");
    if !log.is_empty() {
        log.push('\n');
    }
    builder.add("kernel/sleep.log", log.into_bytes())?;

    builder.add(
        "identity/boot_id",
        format!("{}\n", identity.boot_id).into_bytes(),
    )?;
    builder.add(
        "identity/osrelease",
        format!("{}\n", identity.kernel_release).into_bytes(),
    )?;
    if let Some(version) = &identity.kernel_version {
        builder.add("identity/version", format!("{version}\n").into_bytes())?;
    }
    for (field, value) in &identity.dmi {
        builder.add(&format!("dmi/{field}"), format!("{value}\n").into_bytes())?;
    }

    let mut observations = vec![format!(
        "{} ACPI table files copied: {}.",
        table_names.len(),
        table_names.join(", ")
    )];
    for (name, text) in &sleep_states {
        observations.push(format!("{name}: {text}"));
    }
    observations.push(format!(
        "{} sleep-related kernel messages kept.",
        sleep_lines.len()
    ));
    Ok(builder.seal(
        &identity,
        at,
        Receipt {
            command: "diag acpi capture",
            title: format!(
                "ACPI tables and sleep state of {}",
                identity.dmi.get("board_name").map_or("the host", String::as_str)
            ),
            observations,
            limits: "Reads the tables the kernel published at this boot; they can differ from the image on the chip (the firmware patches tables at POST and the OS may load dynamic ones). The kernel messages cover only what the ring buffer still held.".into(),
            digests: BTreeMap::new(),
        },
    ))
}

/// Tables that hold a per-unit Windows licence key (MSDM) or OEM licence (SLIC):
/// identifying data a shared capture must not carry.
///
/// Example: `is_per_unit_table("MSDM")` is `true`; `is_per_unit_table("DSDT")` is `false`.
fn is_per_unit_table(name: &str) -> bool {
    matches!(name, "MSDM" | "SLIC")
}

/// Copy every regular file below `dir`, depth-first in name order, under `prefix`.
/// Symlinks and other entries are recorded as skipped.
fn copy_tree(
    files: &dyn HostFiles,
    dir: &str,
    prefix: &str,
    depth: usize,
    builder: &mut BundleBuilder,
    copied: &mut Vec<String>,
) -> Result<()> {
    let entries = files.entries(dir).map_err(|e| {
        let code = if e.kind() == ErrorKind::NotFound {
            Code::TargetNotFound
        } else {
            Code::Io
        };
        Error::new(code, format!("{dir}: {e}"))
    })?;
    for entry in entries {
        let path = format!("{dir}/{}", entry.name);
        let target = format!("{prefix}/{}", entry.name);
        match entry.kind {
            EntryKind::File if is_per_unit_table(&entry.name) => {
                builder.skip(&path, "per-unit licence data");
            }
            EntryKind::File => {
                let bytes = files
                    .read(&path)
                    .map_err(|e| Error::new(Code::Io, format!("{path}: {e}")))?;
                copied.push(target.trim_start_matches("acpi/tables/").to_string());
                builder.add(&target, bytes)?;
            }
            EntryKind::Directory if depth < MAX_DEPTH => {
                copy_tree(files, &path, &target, depth + 1, builder, copied)?;
            }
            EntryKind::Directory => builder.skip(&path, format!("deeper than {MAX_DEPTH} levels")),
            EntryKind::Other => builder.skip(&path, "not a regular file or directory"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{EVIDENCE_FILE, MANIFEST_FILE};
    use crate::testkit::{FakeKernelLog, FakePrivilege, FakeSysfs, FixedClock};
    use biosmod_core::util::Digest256;

    fn host_with_tables() -> FakeSysfs {
        FakeSysfs::mr9a()
            .file("sys/firmware/acpi/tables/DSDT", b"DSDT-bytes")
            .file("sys/firmware/acpi/tables/FACP", b"FACP-bytes")
            .file("sys/firmware/acpi/tables/dynamic/SSDT3", b"SSDT3-bytes")
            .file("sys/firmware/acpi/tables/data/BERT", b"BERT-bytes")
            .file("sys/power/mem_sleep", "[s2idle]\n")
            .file("sys/power/state", "freeze mem disk\n")
    }

    fn kernel_log() -> FakeKernelLog {
        FakeKernelLog::new()
            .message(1_000_000, "usb 1-1: new device")
            .message(5_140_900, "PM: suspend entry (deep)")
            .message(
                5_141_000,
                "ACPI: PM: Preparing to enter system sleep state S3",
            )
    }

    fn run(sysfs: &FakeSysfs, privilege: &FakePrivilege) -> Result<Bundle> {
        let files = sysfs.files();
        let log = kernel_log();
        capture(&HostSurfaces {
            files: &files,
            kernel_log: &log,
            privilege,
            clock: &FixedClock,
        })
    }

    fn manifest_of(bundle: &Bundle) -> serde_json::Value {
        serde_json::from_slice(bundle.get(MANIFEST_FILE).unwrap()).unwrap()
    }

    #[test]
    fn captures_every_table_including_dynamic_and_data() {
        let bundle = run(&host_with_tables(), &FakePrivilege::root()).unwrap();
        for (path, bytes) in [
            ("acpi/tables/DSDT", &b"DSDT-bytes"[..]),
            ("acpi/tables/FACP", b"FACP-bytes"),
            ("acpi/tables/dynamic/SSDT3", b"SSDT3-bytes"),
            ("acpi/tables/data/BERT", b"BERT-bytes"),
            ("power/mem_sleep", b"[s2idle]\n"),
            ("power/state", b"freeze mem disk\n"),
        ] {
            assert_eq!(bundle.get(path), Some(bytes), "captured {path}");
        }
    }

    #[test]
    fn records_identity_and_only_sleep_messages() {
        let bundle = run(&host_with_tables(), &FakePrivilege::root()).unwrap();
        assert_eq!(
            bundle.get("identity/boot_id").unwrap(),
            format!("{}\n", FakeSysfs::BOOT_ID).as_bytes()
        );
        assert_eq!(
            bundle.get("identity/osrelease"),
            Some(&b"7.0.0-42-generic\n"[..])
        );
        assert_eq!(bundle.get("dmi/board_name"), Some(&b"E5-MR9A PRO\n"[..]));
        let log = String::from_utf8(bundle.get("kernel/sleep.log").unwrap().to_vec()).unwrap();
        assert_eq!(
            log,
            "[    5.140900] PM: suspend entry (deep)\n[    5.141000] ACPI: PM: Preparing to enter system sleep state S3\n"
        );
    }

    #[test]
    fn manifest_digests_match_the_files_and_evidence_binds_the_manifest() {
        let bundle = run(&host_with_tables(), &FakePrivilege::root()).unwrap();
        let manifest = manifest_of(&bundle);
        let listed = manifest["files"].as_array().unwrap();
        assert_eq!(
            listed.len(),
            bundle.files.len() - 2,
            "every captured file is listed"
        );
        for entry in listed {
            let path = entry["path"].as_str().unwrap();
            assert_eq!(
                entry["sha256"].as_str().unwrap(),
                Digest256::of(bundle.get(path).unwrap()).to_string(),
                "sha256 of {path}"
            );
        }
        let evidence: serde_json::Value =
            serde_json::from_slice(bundle.get(EVIDENCE_FILE).unwrap()).unwrap();
        assert_eq!(evidence["schema"], "bme.evidence/1");
        assert_eq!(evidence["kind"], "hardware-observation");
        assert_eq!(evidence["host"]["boot_id"], FakeSysfs::BOOT_ID);
        assert_eq!(
            evidence["host"]["digests"][MANIFEST_FILE],
            Digest256::of(bundle.get(MANIFEST_FILE).unwrap()).to_string()
        );
    }

    #[test]
    fn per_unit_licence_tables_are_skipped_with_a_reason() {
        let sysfs = host_with_tables()
            .file("sys/firmware/acpi/tables/MSDM", b"WINDOWS-PRODUCT-KEY")
            .file("sys/firmware/acpi/tables/SLIC", b"OEM-LICENCE")
            .file(
                "sys/firmware/acpi/tables/dynamic/MSDM",
                b"WINDOWS-PRODUCT-KEY",
            );
        let bundle = run(&sysfs, &FakePrivilege::root()).unwrap();
        for table in ["MSDM", "SLIC", "dynamic/MSDM"] {
            assert_eq!(bundle.get(&format!("acpi/tables/{table}")), None, "{table}");
        }
        for file in &bundle.files {
            let text = String::from_utf8_lossy(&file.bytes);
            assert!(!text.contains("WINDOWS-PRODUCT-KEY"), "{}", file.path);
            assert!(!text.contains("OEM-LICENCE"), "{}", file.path);
        }
        let manifest = manifest_of(&bundle);
        let skipped: Vec<(&str, &str)> = manifest["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| (s["path"].as_str().unwrap(), s["reason"].as_str().unwrap()))
            .collect();
        for path in [
            "/sys/firmware/acpi/tables/MSDM",
            "/sys/firmware/acpi/tables/SLIC",
            "/sys/firmware/acpi/tables/dynamic/MSDM",
        ] {
            assert!(
                skipped.contains(&(path, "per-unit licence data")),
                "(skipped): expected {path} | received {skipped:?}"
            );
        }
        // The other tables are untouched.
        assert_eq!(bundle.get("acpi/tables/DSDT"), Some(&b"DSDT-bytes"[..]));
    }

    #[test]
    fn licence_table_names_are_matched_exactly() {
        assert!(is_per_unit_table("MSDM") && is_per_unit_table("SLIC"));
        assert!(
            !is_per_unit_table("SLIT") && !is_per_unit_table("MSDM1") && !is_per_unit_table("msdm")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_and_named_in_the_manifest() {
        let sysfs = host_with_tables();
        std::os::unix::fs::symlink("DSDT", sysfs.path("sys/firmware/acpi/tables/LINK")).unwrap();
        let bundle = run(&sysfs, &FakePrivilege::root()).unwrap();
        assert_eq!(bundle.get("acpi/tables/LINK"), None);
        assert_eq!(
            manifest_of(&bundle)["skipped"][0]["path"],
            "/sys/firmware/acpi/tables/LINK"
        );
    }

    #[test]
    fn a_missing_sleep_file_is_skipped_not_fatal() {
        let sysfs = FakeSysfs::mr9a().file("sys/firmware/acpi/tables/DSDT", b"x");
        let bundle = run(&sysfs, &FakePrivilege::root()).unwrap();
        assert_eq!(manifest_of(&bundle)["skipped"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn refuses_non_root_before_reading_and_names_the_user() {
        let error = run(&host_with_tables(), &FakePrivilege::user(1000)).unwrap_err();
        assert_eq!(error.code, Code::HostRefused);
        assert!(
            error
                .message
                .starts_with("diag acpi capture: expected effective user root | received uid 1000"),
            "{error}"
        );
    }

    #[test]
    fn a_host_without_acpi_tables_is_reported_not_captured_empty() {
        let error = run(&FakeSysfs::mr9a(), &FakePrivilege::root()).unwrap_err();
        assert_eq!(error.code, Code::TargetNotFound);
        assert!(error.message.starts_with(TABLES_ROOT), "{error}");
    }
}
