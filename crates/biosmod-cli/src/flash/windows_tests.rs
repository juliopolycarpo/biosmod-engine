//! Flash commands on Windows. The facts are plain [`WindowsFacts`] values and flashrom is
//! `FakeUsbFlashrom`, so these tests run on every platform and never reach a programmer.

use super::host::{board_matches, is_internal};
use super::*;
use crate::toolchain::{Finished, Invocation, Runner};
use biosmod_host::windows::{UsbDevice, WindowsFacts};
use std::cell::RefCell;

/// A flashrom whose every chip access prints `output` and exits with `status`.
struct FakeUsbFlashrom {
    output: &'static str,
    status: i32,
    calls: RefCell<Vec<String>>,
}

impl FakeUsbFlashrom {
    /// A CH341A with a 16 MiB chip under the clip.
    fn answering() -> FakeUsbFlashrom {
        FakeUsbFlashrom {
            output: "Found Winbond flash chip \"W25Q128.V\" (16384 kB, SPI) on ch341a_spi.\n",
            status: 0,
            calls: RefCell::new(Vec::new()),
        }
    }

    /// A programmer libusb cannot open because Windows bound the vendor driver to it.
    fn refused_by_driver() -> FakeUsbFlashrom {
        FakeUsbFlashrom {
            output: "Failed to claim interface 0: 'LIBUSB_ERROR_NOT_SUPPORTED'\nUnable to initialize ch341a_spi\n",
            status: 1,
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl Runner for FakeUsbFlashrom {
    fn run(&self, invocation: &Invocation) -> Result<Finished> {
        let words = invocation.words();
        self.calls.borrow_mut().push(words.join(" "));
        if words == ["--version"] {
            return Ok(Finished {
                status: Some(0),
                stdout: "flashrom v1.6.0 on Windows 10.0 (x86_64)\n".into(),
                ..Finished::default()
            });
        }
        Ok(Finished {
            status: Some(self.status),
            stdout: self.output.into(),
            ..Finished::default()
        })
    }
}

fn usb(vendor: &str, product: &str, service: Option<&str>) -> UsbDevice {
    UsbDevice {
        vendor: vendor.into(),
        product: product.into(),
        service: service.map(str::to_string),
    }
}

/// The MR9A as Windows reports it, with `usb` plugged in.
fn mr9a_windows(usb: Vec<UsbDevice>) -> Host {
    let dmi = [
        ("board_vendor", "MACHINIST"),
        ("board_name", "E5-MR9A PRO"),
        ("board_version", "V1.2"),
        ("bios_vendor", "American Megatrends Inc."),
        ("bios_version", "5.11"),
        ("bios_date", "03/22/2023"),
        ("product_sku", "Default string"),
    ]
    .into_iter()
    .map(|(field, value)| (field, value.to_string()))
    .collect();
    Host {
        root: PathBuf::from("/nonexistent/bme-test-sysfs"),
        os: "windows",
        euid: None,
        windows: Some(WindowsFacts {
            elevated: Some(false),
            dmi,
            usb,
        }),
    }
}

fn no_variables(_: &str) -> Option<OsString> {
    None
}

fn windows_env<'a>(flashrom: &'a FakeUsbFlashrom, host: Host) -> Env<'a> {
    Env {
        runner: flashrom,
        host,
        flashrom: Some(PathBuf::from(r"C:\msys64\ucrt64\bin\flashrom.exe")),
        flashrom_flag: None,
        out: Out {
            json: true,
            quiet: true,
        },
        variable: &no_variables,
        boards: Vec::new(),
    }
}

fn target_args(programmer: &str) -> FlashTargetArgs {
    FlashTargetArgs {
        programmer: programmer.into(),
        chip: None,
        flashrom: None,
    }
}

/// The check named `name` from a doctor reply, as `(state, detail)`.
fn check(reply: &Reply, name: &str) -> Option<(String, String)> {
    reply.data["checks"]
        .as_array()?
        .iter()
        .find(|check| check["check"] == name)
        .map(|check| {
            (
                check["state"].as_str().unwrap_or_default().to_string(),
                check["detail"].as_str().unwrap_or_default().to_string(),
            )
        })
}

fn expect_check(reply: &Reply, name: &str) -> (String, String) {
    check(reply, name).unwrap_or_else(|| {
        panic!(
            "(flash doctor) check {name}: expected a line | received checks {}",
            reply.data["checks"]
        )
    })
}

#[test]
fn internal_names_the_chipset_programmer_with_or_without_parameters() {
    for (programmer, expected) in [
        ("internal", true),
        ("internal:laptop=this_is_not_a_laptop", true),
        ("ch341a_spi", false),
        ("linux_mtd:dev=0", false),
    ] {
        assert_eq!(
            is_internal(programmer),
            expected,
            "is_internal({programmer:?}): expected {expected}"
        );
    }
}

#[test]
fn doctor_on_windows_passes_a_ch341a_bound_to_winusb() {
    let flashrom = FakeUsbFlashrom::answering();
    let env = windows_env(
        &flashrom,
        mr9a_windows(vec![usb("1a86", "5512", Some("WinUSB"))]),
    );
    let reply = doctor(&env, "ch341a_spi").unwrap();
    assert_eq!(reply.data["platform"], "windows");
    assert_eq!(
        reply.data["ready"], true,
        "(flash doctor): expected ready | received {}",
        reply.data["checks"]
    );
    assert_eq!(expect_check(&reply, "platform").0, "pass");
    assert_eq!(
        expect_check(&reply, "usb-programmer"),
        (
            "pass".into(),
            "CH341A (1a86:5512): --programmer ch341a_spi".into()
        )
    );
    assert_eq!(expect_check(&reply, "privileges").0, "info");
    for linux_only in [
        "kernel-lockdown",
        "secure-boot",
        "internal-access",
        "bios-write-protection",
        "mtd",
    ] {
        assert!(
            check(&reply, linux_only).is_none(),
            "(flash doctor on windows) check {linux_only}: expected none | received {:?}",
            check(&reply, linux_only)
        );
    }
    assert_eq!(reply.data["system"]["board_name"], "E5-MR9A PRO");
    assert!(
        reply
            .text
            .contains("Next: bme flash probe, then bme flash backup -o dump.bin"),
        "(flash doctor on windows): expected next steps without sudo | received {}",
        reply.text
    );
}

#[test]
fn doctor_on_windows_fails_the_internal_programmer() {
    let flashrom = FakeUsbFlashrom::answering();
    let env = windows_env(&flashrom, mr9a_windows(Vec::new()));
    let reply = doctor(&env, "internal").unwrap();
    assert_eq!(reply.data["ready"], false);
    let (state, detail) = expect_check(&reply, "platform");
    assert_eq!(state, "fail");
    assert!(
        detail.starts_with("windows: expected an external programmer | received internal"),
        "platform: expected the internal programmer refused | received {detail}"
    );
    assert_eq!(expect_check(&reply, "usb-programmer").0, "info");
}

#[test]
fn a_programmer_under_its_vendor_driver_warns_with_zadig() {
    let flashrom = FakeUsbFlashrom::answering();
    let env = windows_env(
        &flashrom,
        mr9a_windows(vec![usb("1a86", "5512", Some("CH341PAR"))]),
    );
    let reply = doctor(&env, "ch341a_spi").unwrap();
    let (state, detail) = expect_check(&reply, "usb-programmer");
    assert_eq!(
        state, "warn",
        "usb-programmer: expected warn | received {detail}"
    );
    assert_eq!(
        detail,
        "CH341A (1a86:5512) uses driver CH341PAR; expected WinUSB for flashrom: bind WinUSB to it with Zadig (zadig.akeo.ie)"
    );

    let env = windows_env(&flashrom, mr9a_windows(vec![usb("1a86", "5512", None)]));
    let (_, detail) = expect_check(&doctor(&env, "ch341a_spi").unwrap(), "usb-programmer");
    assert!(
        detail.starts_with("CH341A (1a86:5512) has no driver;"),
        "usb-programmer without a driver: expected `has no driver` | received {detail}"
    );
}

#[test]
fn a_composite_programmer_is_reachable_through_one_winusb_interface() {
    let flashrom = FakeUsbFlashrom::answering();
    let ft2232h = |interface_driver| {
        vec![
            usb("0403", "6010", Some("usbccgp")),
            usb("0403", "6010", Some(interface_driver)),
            usb("0403", "6010", Some("FTDIBUS")),
        ]
    };
    let env = windows_env(&flashrom, mr9a_windows(ft2232h("WinUSB")));
    assert_eq!(
        expect_check(
            &doctor(&env, "ft2232_spi:type=2232H").unwrap(),
            "usb-programmer"
        )
        .0,
        "pass"
    );
    let env = windows_env(&flashrom, mr9a_windows(ft2232h("FTDIBUS")));
    let (state, detail) = expect_check(
        &doctor(&env, "ft2232_spi:type=2232H").unwrap(),
        "usb-programmer",
    );
    assert_eq!(state, "warn");
    assert!(
        detail.starts_with("FTDI FT2232H (0403:6010) uses driver FTDIBUS;"),
        "usb-programmer: expected the composite parent driver left out | received {detail}"
    );
}

#[test]
fn a_missing_flashrom_on_windows_points_to_msys2() {
    let flashrom = FakeUsbFlashrom::answering();
    let mut env = windows_env(&flashrom, mr9a_windows(Vec::new()));
    env.flashrom = None;
    let (state, detail) = expect_check(&doctor(&env, "ch341a_spi").unwrap(), "flashrom");
    assert_eq!(state, "fail");
    assert!(
        detail.starts_with("not found in PATH or the MSYS2 directories; install it (MSYS2: pacman -S mingw-w64-ucrt-x86_64-flashrom)"),
        "flashrom: expected the MSYS2 install command | received {detail}"
    );
    let error = probe(&env, &target_args("ch341a_spi")).unwrap_err();
    assert_eq!(error.code, Code::ToolUnavailable);
    assert!(
        error
            .message
            .starts_with("flashrom: expected an executable in PATH or the MSYS2 directories"),
        "{error}"
    );
}

#[test]
fn chip_commands_on_windows_refuse_internal_and_run_external_programmers() {
    let flashrom = FakeUsbFlashrom::answering();
    let env = windows_env(&flashrom, mr9a_windows(Vec::new()));
    let error = dispatch(&env, FlashCommand::Probe(target_args("internal"))).unwrap_err();
    assert_eq!(error.code, Code::PlatformUnsupported, "{error}");
    assert!(
        error.message.starts_with(
            "flash probe -p internal: expected an external programmer on windows | received the internal programmer"
        ),
        "{error}"
    );
    assert!(
        flashrom.calls.borrow().is_empty(),
        "flashrom: expected no run for the internal programmer | received {:?}",
        flashrom.calls.borrow()
    );

    let reply = dispatch(&env, FlashCommand::Probe(target_args("ch341a_spi"))).unwrap();
    assert_eq!(reply.data["chips"][0]["name"], "W25Q128.V");
    assert!(
        reply
            .text
            .contains("Next: bme flash backup --programmer ch341a_spi -o dump.bin"),
        "(flash probe on windows): expected the next step without sudo | received {}",
        reply.text
    );
}

#[test]
fn a_libusb_refusal_on_windows_names_zadig_instead_of_sudo() {
    let flashrom = FakeUsbFlashrom::refused_by_driver();
    let env = windows_env(&flashrom, mr9a_windows(Vec::new()));
    let error = probe(&env, &target_args("ch341a_spi")).unwrap_err();
    assert_eq!(error.code, Code::ToolFailed);
    assert!(
        error.message.contains("bind WinUSB to it with Zadig"),
        "(flash probe): expected the Zadig hint | received {error}"
    );
    assert!(
        !error.message.contains("sudo"),
        "(flash probe on windows): expected no sudo hint | received {error}"
    );
}

#[test]
fn windows_dmi_keeps_the_flash_fields_and_matches_the_catalog_board() {
    let host = mr9a_windows(Vec::new());
    let dmi = host.dmi();
    assert_eq!(
        dmi.get("product_sku"),
        None,
        "dmi: expected only the flash diagnosis fields | received {dmi:?}"
    );
    assert_eq!(dmi.get("bios_version").map(String::as_str), Some("5.11"));
    assert!(board_matches(&dmi, "Machinist", "E5-MR9A PRO"));
}
