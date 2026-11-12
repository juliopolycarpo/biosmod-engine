//! `diag superio read`: identify a Super I/O chip by ID and read its logical
//! devices and hardware-monitor registers.
//!
//! The chips and their register maps are data in `data/superio.json`; adding an
//! ITE IT87xx, a Fintek F718xx or an NCT67xx means adding an entry, not code. A
//! chip whose ID no entry claims is refused.
//!
//! # What is written
//!
//! Only access selectors, in this order, and each is put back:
//!
//! 1. the entry key to the configuration index port (enters configuration mode);
//! 2. the configuration index (a register number), the logical device number
//!    register (`ldn_register`, restored afterwards) and nothing else;
//! 3. the exit key to the index port;
//! 4. in the hardware monitor, the index register, and the bank register (restored
//!    afterwards).
//!
//! No fan, sensor or NVRAM register is ever written. The chip ID is read before
//! anything but the index and the entry key has been written, so probing an address
//! where no chip answers changes nothing beyond the entry key.

use crate::HostSurfaces;
use crate::bundle::{Bundle, BundleBuilder};
use crate::identity::HostIdentity;
use crate::ports::PortIo;
use crate::privilege::require_root;
use crate::receipt::Receipt;
use biosmod_core::{Code, Error, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;

const TABLE: &str = include_str!("../data/superio.json");

fn hex(text: &str) -> std::result::Result<u32, String> {
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("{text:?}: expected a 0x-prefixed hexadecimal number"))?;
    u32::from_str_radix(digits, 16).map_err(|e| format!("{text:?}: {e}"))
}

fn hex_u8<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<u8, D::Error> {
    let text = String::deserialize(deserializer)?;
    hex(&text)
        .and_then(|value| {
            u8::try_from(value).map_err(|_| format!("{text:?}: expected at most 0xFF"))
        })
        .map_err(serde::de::Error::custom)
}

fn hex_u16<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<u16, D::Error> {
    let text = String::deserialize(deserializer)?;
    hex(&text)
        .and_then(|value| {
            u16::try_from(value).map_err(|_| format!("{text:?}: expected at most 0xFFFF"))
        })
        .map_err(serde::de::Error::custom)
}

fn hex_u8_list<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|text| {
            hex(text).and_then(|v| {
                u8::try_from(v).map_err(|_| format!("{text:?}: expected at most 0xFF"))
            })
        })
        .collect::<std::result::Result<_, _>>()
        .map_err(serde::de::Error::custom)
}

fn hex_u16_list<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u16>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|text| {
            hex(text).and_then(|v| {
                u16::try_from(v).map_err(|_| format!("{text:?}: expected at most 0xFFFF"))
            })
        })
        .collect::<std::result::Result<_, _>>()
        .map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TableFile {
    format: u32,
    chips: Vec<ChipMap>,
}

/// How a chip announces itself.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdMatch {
    /// The high and low byte registers.
    #[serde(deserialize_with = "hex_u8_list")]
    pub registers: Vec<u8>,
    #[serde(deserialize_with = "hex_u16")]
    pub value: u16,
    /// Bits of the ID that identify the chip; the rest is the silicon revision.
    #[serde(deserialize_with = "hex_u16")]
    pub mask: u16,
}

/// One logical device the chip has.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalDeviceMap {
    #[serde(deserialize_with = "hex_u8")]
    pub ldn: u8,
    pub name: String,
    /// Whether the device has an I/O base address in the base registers.
    pub has_base: bool,
}

/// The registers of one hardware-monitor bank.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BankMap {
    pub bank: u8,
    #[serde(deserialize_with = "hex_u8_list")]
    pub registers: Vec<u8>,
}

/// The indexed hardware-monitor interface and what to read in it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareMonitorMap {
    /// The logical device holding its base address.
    #[serde(deserialize_with = "hex_u8")]
    pub ldn: u8,
    /// Index and data ports are `base + index_offset` and `base + data_offset`.
    pub index_offset: u16,
    pub data_offset: u16,
    #[serde(deserialize_with = "hex_u8")]
    pub bank_register: u8,
    /// Bits of the bank register that select the bank; the others are kept.
    #[serde(deserialize_with = "hex_u8")]
    pub bank_mask: u8,
    pub banks: Vec<BankMap>,
}

/// A supported chip family and its register map.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChipMap {
    pub vendor: String,
    pub name: String,
    /// Configuration index ports to probe; the data port is the next one.
    #[serde(deserialize_with = "hex_u16_list")]
    pub config_ports: Vec<u16>,
    /// Bytes written to the index port to enter configuration mode.
    #[serde(deserialize_with = "hex_u8_list")]
    pub unlock: Vec<u8>,
    /// Byte written to the index port to leave it.
    #[serde(deserialize_with = "hex_u8")]
    pub lock: u8,
    pub id: IdMatch,
    #[serde(deserialize_with = "hex_u8")]
    pub ldn_register: u8,
    #[serde(deserialize_with = "hex_u8")]
    pub activation_register: u8,
    /// High and low byte of a logical device's I/O base.
    #[serde(deserialize_with = "hex_u8_list")]
    pub base_registers: Vec<u8>,
    pub logical_devices: Vec<LogicalDeviceMap>,
    pub hardware_monitor: Option<HardwareMonitorMap>,
    /// The document the map was written from.
    pub source: String,
}

impl ChipMap {
    fn id_matches(&self, id: u16) -> bool {
        id & self.id.mask == self.id.value
    }

    fn check(&self) -> std::result::Result<(), String> {
        let at = &self.name;
        if self.config_ports.is_empty() || self.unlock.is_empty() {
            return Err(format!(
                "{at}: expected config ports and an unlock sequence"
            ));
        }
        if self.id.registers.len() != 2 || self.base_registers.len() != 2 {
            return Err(format!("{at}: expected two ID and two base registers"));
        }
        if self.id.value & self.id.mask != self.id.value {
            return Err(format!("{at}: ID value has bits outside its mask"));
        }
        if let Some(hwm) = &self.hardware_monitor {
            if hwm.index_offset == hwm.data_offset {
                return Err(format!(
                    "{at}: hardware monitor index and data offsets are equal"
                ));
            }
            if hwm.banks.iter().any(|bank| bank.bank & !hwm.bank_mask != 0) {
                return Err(format!("{at}: a bank number does not fit the bank mask"));
            }
            if !self
                .logical_devices
                .iter()
                .any(|device| device.ldn == hwm.ldn && device.has_base)
            {
                return Err(format!(
                    "{at}: hardware monitor LDN is not a listed device with a base"
                ));
            }
        }
        if self.source.trim().is_empty() {
            return Err(format!("{at}: expected a source reference"));
        }
        Ok(())
    }
}

/// Parse and check a chip table.
///
/// Example: `parse_table(include_str!("../data/superio.json"))?[0].name == "NCT5532D"`.
pub fn parse_table(text: &str) -> Result<Vec<ChipMap>> {
    let file: TableFile = serde_json::from_str(text)
        .map_err(|e| Error::new(Code::Internal, format!("super I/O table: {e}")))?;
    if file.format != 1 {
        return Err(Error::new(
            Code::Internal,
            format!(
                "super I/O table format: expected 1 | received {}",
                file.format
            ),
        ));
    }
    for chip in &file.chips {
        chip.check()
            .map_err(|e| Error::new(Code::Internal, format!("super I/O table: {e}")))?;
    }
    Ok(file.chips)
}

/// The chips this build knows.
///
/// Example: `builtin().iter().any(|chip| chip.name == "NCT5532D")`.
pub fn builtin() -> &'static [ChipMap] {
    static CHIPS: OnceLock<Vec<ChipMap>> = OnceLock::new();
    CHIPS.get_or_init(|| parse_table(TABLE).expect("the bundled super I/O table is valid"))
}

/// One logical device as the chip reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogicalDeviceReading {
    pub ldn: u8,
    pub name: String,
    pub active: u8,
    /// `0x`-prefixed I/O base, for devices that have one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
}

/// What one run found, in the field names of the hand-made `live-controller.json`
/// (`chip_id`, `hwm_active`, `hwm_base`, `registers`) plus the detail around them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuperIoReading {
    pub vendor: String,
    pub chip: String,
    pub chip_id: String,
    pub config_port: String,
    pub logical_devices: Vec<LogicalDeviceReading>,
    pub hwm_active: Option<u8>,
    pub hwm_base: Option<String>,
    /// Bank number, then two-digit register, to value.
    pub registers: BTreeMap<String, BTreeMap<String, u8>>,
}

fn config_read(ports: &mut dyn PortIo, port: u16, register: u8) -> Result<u8> {
    ports.write(port, register)?;
    ports.read(port + 1)
}

/// The only data-port write of the configuration protocol: the LDN selector.
fn select_ldn(ports: &mut dyn PortIo, port: u16, chip: &ChipMap, ldn: u8) -> Result<()> {
    ports.write(port, chip.ldn_register)?;
    ports.write(port + 1, ldn)
}

/// Run `restore` after `result` and report both failures when both happen.
fn finish<T>(result: Result<T>, restore: Result<()>, what: &str) -> Result<T> {
    match (result, restore) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(restore)) => Err(restore.context(format!("{what} was not restored"))),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(restore)) => Err(Error::new(
            error.code,
            format!(
                "{}; {what} was not restored: {}",
                error.message, restore.message
            ),
        )),
    }
}

/// What probing one configuration port found.
enum Probe<'a> {
    /// No chip answered (the ID read back all ones or zeros).
    Absent,
    /// A chip answered with an ID no table entry claims.
    Unknown(u16),
    Known {
        chip: &'a ChipMap,
        id: u16,
        logical_devices: Vec<LogicalDeviceReading>,
        hardware_monitor_base: Option<(u8, u16)>,
    },
}

/// Enter configuration mode at `port`, probe, and leave it again.
fn probe<'a>(
    ports: &mut dyn PortIo,
    port: u16,
    entry: &ChipMap,
    chips: &'a [ChipMap],
) -> Result<Probe<'a>> {
    for key in &entry.unlock {
        ports.write(port, *key)?;
    }
    let outcome = probe_in_configuration_mode(ports, port, entry, chips);
    let exit = ports.write(port, entry.lock);
    finish(outcome, exit, "configuration mode")
}

fn probe_in_configuration_mode<'a>(
    ports: &mut dyn PortIo,
    port: u16,
    entry: &ChipMap,
    chips: &'a [ChipMap],
) -> Result<Probe<'a>> {
    let high = config_read(ports, port, entry.id.registers[0])?;
    let low = config_read(ports, port, entry.id.registers[1])?;
    let id = u16::from_be_bytes([high, low]);
    if id == 0xFFFF || id == 0 {
        return Ok(Probe::Absent);
    }
    let Some(chip) = chips.iter().find(|chip| {
        chip.config_ports.contains(&port) && chip.unlock == entry.unlock && chip.id_matches(id)
    }) else {
        return Ok(Probe::Unknown(id));
    };
    // From here on the LDN selector changes, so put it back whatever happens.
    let saved_ldn = config_read(ports, port, chip.ldn_register)?;
    let read = read_logical_devices(ports, port, chip);
    let restore = select_ldn(ports, port, chip, saved_ldn);
    let (logical_devices, hardware_monitor_base) =
        finish(read, restore, "logical device selection")?;
    Ok(Probe::Known {
        chip,
        id,
        logical_devices,
        hardware_monitor_base,
    })
}

type LogicalDevices = (Vec<LogicalDeviceReading>, Option<(u8, u16)>);

fn read_logical_devices(
    ports: &mut dyn PortIo,
    port: u16,
    chip: &ChipMap,
) -> Result<LogicalDevices> {
    let mut readings = Vec::new();
    let mut monitor = None;
    for device in &chip.logical_devices {
        select_ldn(ports, port, chip, device.ldn)?;
        let active = config_read(ports, port, chip.activation_register)?;
        let base = if device.has_base {
            let high = config_read(ports, port, chip.base_registers[0])?;
            let low = config_read(ports, port, chip.base_registers[1])?;
            Some(u16::from_be_bytes([high, low]))
        } else {
            None
        };
        if chip
            .hardware_monitor
            .as_ref()
            .is_some_and(|hwm| hwm.ldn == device.ldn)
        {
            monitor = Some((active, base.unwrap_or(0)));
        }
        readings.push(LogicalDeviceReading {
            ldn: device.ldn,
            name: device.name.clone(),
            active,
            base: base.map(|base| format!("{base:#x}")),
        });
    }
    Ok((readings, monitor))
}

/// Read every listed register of every listed bank through the index and data
/// ports, keeping the bank register's other bits and restoring it afterwards.
fn read_banks(
    ports: &mut dyn PortIo,
    index: u16,
    data: u16,
    hwm: &HardwareMonitorMap,
) -> Result<BTreeMap<String, BTreeMap<String, u8>>> {
    ports.write(index, hwm.bank_register)?;
    let original = ports.read(data)?;
    let read = (|| {
        let mut banks = BTreeMap::new();
        for bank in &hwm.banks {
            ports.write(index, hwm.bank_register)?;
            ports.write(data, (original & !hwm.bank_mask) | bank.bank)?;
            let mut values = BTreeMap::new();
            for register in &bank.registers {
                ports.write(index, *register)?;
                values.insert(format!("{register:02x}"), ports.read(data)?);
            }
            banks.insert(bank.bank.to_string(), values);
        }
        Ok(banks)
    })();
    let restore = ports
        .write(index, hwm.bank_register)
        .and_then(|()| ports.write(data, original));
    finish(read, restore, "hardware monitor bank selection")
}

/// Find a supported chip on the configuration ports of `chips` and read it.
///
/// Refuses a chip whose ID no entry claims, with the ID in the message, and fails
/// when no chip answers at any port.
///
/// Example: `read(&mut DevPort::open(...)?, builtin())?.chip_id == "0xc562"` on the MR9A.
pub fn read(ports: &mut dyn PortIo, chips: &[ChipMap]) -> Result<SuperIoReading> {
    let mut tried: Vec<(u16, &ChipMap)> = Vec::new();
    for chip in chips {
        for port in &chip.config_ports {
            if !tried
                .iter()
                .any(|(seen, entry)| seen == port && entry.unlock == chip.unlock)
            {
                tried.push((*port, chip));
            }
        }
    }
    for (port, entry) in tried {
        match probe(ports, port, entry, chips)? {
            Probe::Absent => continue,
            Probe::Unknown(id) => {
                return Err(Error::new(
                    Code::HostRefused,
                    format!(
                        "super I/O chip ID at port {port:#x}: expected one of {} | received {id:#06x}",
                        known_ids(chips)
                    ),
                ));
            }
            Probe::Known {
                chip,
                id,
                logical_devices,
                hardware_monitor_base,
            } => {
                return finish_reading(
                    ports,
                    port,
                    chip,
                    id,
                    logical_devices,
                    hardware_monitor_base,
                );
            }
        }
    }
    Err(Error::new(
        Code::TargetNotFound,
        format!(
            "super I/O chip: expected an ID answer at {} | received none",
            ports_tried(chips)
        ),
    ))
}

fn finish_reading(
    ports: &mut dyn PortIo,
    port: u16,
    chip: &ChipMap,
    id: u16,
    logical_devices: Vec<LogicalDeviceReading>,
    hardware_monitor_base: Option<(u8, u16)>,
) -> Result<SuperIoReading> {
    let mut reading = SuperIoReading {
        vendor: chip.vendor.clone(),
        chip: chip.name.clone(),
        chip_id: format!("{id:#06x}"),
        config_port: format!("{port:#x}"),
        logical_devices,
        hwm_active: None,
        hwm_base: None,
        registers: BTreeMap::new(),
    };
    let Some(hwm) = &chip.hardware_monitor else {
        return Ok(reading);
    };
    let (active, base) = hardware_monitor_base.unwrap_or((0, 0));
    if active & 1 == 0 || base == 0 || base > u16::MAX - hwm.data_offset.max(hwm.index_offset) {
        return Err(Error::new(
            Code::TargetNotFound,
            format!(
                "{} hardware monitor LDN {:#04x}: expected active with a usable base | received active {active} base {base:#x}",
                chip.name, hwm.ldn
            ),
        ));
    }
    reading.hwm_active = Some(active);
    reading.hwm_base = Some(format!("{base:#x}"));
    reading.registers = read_banks(ports, base + hwm.index_offset, base + hwm.data_offset, hwm)?;
    Ok(reading)
}

fn known_ids(chips: &[ChipMap]) -> String {
    chips
        .iter()
        .map(|chip| {
            format!(
                "{} ({:#06x}/{:#06x})",
                chip.name, chip.id.value, chip.id.mask
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn ports_tried(chips: &[ChipMap]) -> String {
    let mut ports: Vec<u16> = chips
        .iter()
        .flat_map(|chip| chip.config_ports.clone())
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
        .iter()
        .map(|port| format!("{port:#x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A reading and the bundle that preserves it.
#[derive(Debug)]
pub struct SuperIoCapture {
    pub reading: SuperIoReading,
    pub bundle: Bundle,
}

/// Read the chip and seal the reading, manifest and receipt into a bundle.
///
/// Needs root: a non-root user is refused before any port is touched.
///
/// Example: `capture(&surfaces, &mut ports, builtin())?.bundle.get("superio.json")`.
pub fn capture(
    host: &HostSurfaces,
    ports: &mut dyn PortIo,
    chips: &[ChipMap],
) -> Result<SuperIoCapture> {
    require_root(host.privilege, "diag superio read")?;
    let identity = HostIdentity::read(host.files)?;
    let at = host.clock.now();
    let reading = read(ports, chips)?;
    let mut builder = BundleBuilder::new();
    builder.add("superio.json", biosmod_core::json::pretty(&reading))?;
    let register_count: usize = reading.registers.values().map(BTreeMap::len).sum();
    let mut observations = vec![format!(
        "{} {} (ID {}) answered on configuration port {}; {} logical devices read.",
        reading.vendor,
        reading.chip,
        reading.chip_id,
        reading.config_port,
        reading.logical_devices.len()
    )];
    if let Some(base) = &reading.hwm_base {
        observations.push(format!(
            "Hardware monitor active at {base}: {register_count} registers read in banks {}.",
            reading
                .registers
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    observations.push("Logical device and hardware-monitor bank selections were restored.".into());
    let bundle = builder.seal(
        &identity,
        at,
        Receipt {
            command: "diag superio read",
            title: format!("{} {} Super I/O registers", reading.vendor, reading.chip),
            observations,
            limits: "A snapshot of the registers at one instant: temperatures, fan speeds and duty cycles move. The register meanings come from the chip's map, not from this board's wiring; which header a fan channel drives is not established.".into(),
            digests: BTreeMap::new(),
        },
    );
    Ok(SuperIoCapture { reading, bundle })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{EVIDENCE_FILE, MANIFEST_FILE};
    use crate::testkit::{
        FakeKernelLog, FakePrivilege, FakeSuperIoPorts, FakeSysfs, FixedClock,
        MR9A_LIVE_CONTROLLER, PortOp, RecordingPorts,
    };

    fn assert_restored(fake: &FakeSuperIoPorts) {
        assert!(
            fake.violations.is_empty(),
            "(fake violations): expected none | received {:?}",
            fake.violations
        );
        assert!(
            fake.is_locked(),
            "(configuration mode): expected exited | received entered"
        );
        assert_eq!(
            fake.selected_ldn(),
            FakeSuperIoPorts::INITIAL_LDN,
            "(logical device selection): expected restored"
        );
        assert_eq!(
            fake.bank_register(),
            FakeSuperIoPorts::INITIAL_BANK_REGISTER,
            "(hardware monitor bank register): expected restored"
        );
    }

    #[test]
    fn the_bundled_table_parses_and_names_its_sources() {
        let chips = builtin();
        let chip = chips
            .iter()
            .find(|chip| chip.name == "NCT5532D")
            .expect("NCT5532D entry");
        assert_eq!(
            (chip.vendor.as_str(), chip.id.value, chip.id.mask),
            ("Nuvoton", 0xC560, 0xFFF0)
        );
        assert!(chip.source.contains("datasheet"), "source: {}", chip.source);
        assert!(chip.id_matches(0xC561) && chip.id_matches(0xC562) && !chip.id_matches(0xC571));
    }

    #[test]
    fn malformed_tables_name_the_problem() {
        let table = TABLE.to_string();
        for (from, to, expected) in [
            (
                "\"0xC560\"",
                "\"C560\"",
                "expected a 0x-prefixed hexadecimal number",
            ),
            (
                "\"0xFFF0\"",
                "\"0xF0F0\"",
                "ID value has bits outside its mask",
            ),
            (
                "\"index_offset\": 5",
                "\"index_offset\": 6",
                "index and data offsets are equal",
            ),
        ] {
            let error = parse_table(&table.replace(from, to)).unwrap_err();
            assert!(
                error.message.contains(expected),
                "(table): expected {expected:?} | received {error}"
            );
        }
        let error = parse_table(&table.replace("\"format\": 1", "\"format\": 2")).unwrap_err();
        assert!(error.message.contains("expected 1 | received 2"), "{error}");
    }

    #[test]
    fn reproduces_the_recorded_mr9a_controller_and_restores_the_selectors() {
        let mut ports = FakeSuperIoPorts::mr9a_nct5532d();
        let reading = read(&mut ports, builtin()).unwrap();
        let live: serde_json::Value = serde_json::from_str(MR9A_LIVE_CONTROLLER).unwrap();
        assert_eq!(reading.chip_id, live["chip_id"].as_str().unwrap());
        assert_eq!(
            reading.hwm_active,
            live["hwm_active"].as_u64().map(|v| v as u8)
        );
        assert_eq!(reading.hwm_base.as_deref(), live["hwm_base"].as_str());
        assert_eq!(reading.config_port, "0x2e");
        for (bank, registers) in live["registers"].as_object().unwrap() {
            for (register, value) in registers.as_object().unwrap() {
                assert_eq!(
                    reading.registers[bank][register].to_string(),
                    value.to_string(),
                    "bank {bank} register {register}"
                );
            }
        }
        assert_restored(&ports);
        let hwm = reading
            .logical_devices
            .iter()
            .find(|device| device.ldn == 0x0B)
            .unwrap();
        assert_eq!((hwm.active, hwm.base.as_deref()), (1, Some("0xa20")));
    }

    #[test]
    fn only_selector_writes_reach_the_chip() {
        let mut ports = FakeSuperIoPorts::mr9a_nct5532d();
        read(&mut ports, builtin()).unwrap();
        let data_writes: Vec<(u16, u8)> = ports
            .trace
            .iter()
            .filter_map(|op| match op {
                PortOp::Write(port, value) if matches!(*port, 0x2F | 0xA26) => {
                    Some((*port, *value))
                }
                _ => None,
            })
            .collect();
        assert!(
            data_writes
                .iter()
                .filter(|(port, _)| *port == 0x2F)
                .all(
                    |(_, ldn)| builtin()[0].logical_devices.iter().any(|d| d.ldn == *ldn)
                        || *ldn == FakeSuperIoPorts::INITIAL_LDN
                ),
            "(configuration data writes): expected only logical device numbers | received {data_writes:?}"
        );
        assert!(
            data_writes
                .iter()
                .filter(|(port, _)| *port == 0xA26)
                .all(|(_, value)| value & 0xF0 == FakeSuperIoPorts::INITIAL_BANK_REGISTER & 0xF0),
            "(monitor data writes): expected only bank selections keeping the high bits | received {data_writes:?}"
        );
    }

    #[test]
    fn finds_a_chip_on_the_second_configuration_port() {
        let mut ports = FakeSuperIoPorts::mr9a_nct5532d().at_port(0x4E);
        let reading = read(&mut ports, builtin()).unwrap();
        assert_eq!(reading.config_port, "0x4e");
        assert_restored(&ports);
    }

    #[test]
    fn a_revision_nibble_does_not_stop_detection() {
        let mut ports = FakeSuperIoPorts::mr9a_nct5532d().with_chip_id(0xC561);
        assert_eq!(read(&mut ports, builtin()).unwrap().chip_id, "0xc561");
    }

    #[test]
    fn an_unknown_chip_id_is_refused_without_changing_any_selector() {
        let mut ports = FakeSuperIoPorts::mr9a_nct5532d().with_chip_id(0x8728);
        let error = read(&mut ports, builtin()).unwrap_err();
        assert_eq!(error.code, Code::HostRefused, "{error}");
        assert!(
            error.message.contains("received 0x8728")
                && error.message.contains("NCT5532D (0xc560/0xfff0)"),
            "{error}"
        );
        assert_restored(&ports);
        assert!(
            !ports.trace.contains(&PortOp::Write(0x2F, 0x07)),
            "(trace): expected no selector write after an unknown ID"
        );
    }

    #[test]
    fn a_failure_halfway_through_the_monitor_still_restores_the_bank() {
        for fail_at in [1, 5, 40] {
            let mut ports = FakeSuperIoPorts::mr9a_nct5532d().failing_hwm_read(fail_at);
            let error = read(&mut ports, builtin()).unwrap_err();
            assert!(
                error.message.contains("injected failure"),
                "(read {fail_at}): {error}"
            );
            assert_restored(&ports);
        }
    }

    #[test]
    fn an_inactive_monitor_is_reported_with_its_state_and_leaves_selectors_alone() {
        let mut ports = FakeSuperIoPorts::mr9a_nct5532d().with_inactive_hardware_monitor();
        let error = read(&mut ports, builtin()).unwrap_err();
        assert_eq!(error.code, Code::TargetNotFound, "{error}");
        assert!(
            error.message.contains("received active 0 base 0xa20"),
            "{error}"
        );
        assert_restored(&ports);
    }

    #[test]
    fn no_answer_on_any_port_touches_only_index_ports() {
        let mut ports = RecordingPorts::new();
        let error = read(&mut ports, builtin()).unwrap_err();
        assert_eq!(error.code, Code::TargetNotFound, "{error}");
        assert!(error.message.contains("0x2e, 0x4e"), "{error}");
        let data_writes: Vec<_> = ports
            .log
            .iter()
            .filter(|op| matches!(op, PortOp::Write(0x2F | 0x4F, _)))
            .collect();
        assert!(
            data_writes.is_empty(),
            "(probe of an empty bus): expected no data-port writes | received {data_writes:?}"
        );
    }

    fn surfaces<'a>(
        files: &'a crate::RootedFiles,
        log: &'a FakeKernelLog,
        privilege: &'a FakePrivilege,
    ) -> HostSurfaces<'a> {
        HostSurfaces {
            files,
            kernel_log: log,
            privilege,
            clock: &FixedClock,
        }
    }

    #[test]
    fn capture_refuses_non_root_before_any_port_access() {
        let sysfs = FakeSysfs::mr9a();
        let (files, log) = (sysfs.files(), FakeKernelLog::new());
        let privilege = FakePrivilege::user(1000);
        let mut ports = RecordingPorts::new();
        let error =
            capture(&surfaces(&files, &log, &privilege), &mut ports, builtin()).unwrap_err();
        assert_eq!(error.code, Code::HostRefused, "{error}");
        assert!(error.message.contains("received uid 1000"), "{error}");
        assert!(
            ports.log.is_empty(),
            "(port log): expected empty | received {:?}",
            ports.log
        );
    }

    #[test]
    fn capture_seals_the_reading_with_an_evidence_receipt() {
        let sysfs = FakeSysfs::mr9a();
        let (files, log) = (sysfs.files(), FakeKernelLog::new());
        let privilege = FakePrivilege::root();
        let mut ports = FakeSuperIoPorts::mr9a_nct5532d();
        let bundle = capture(&surfaces(&files, &log, &privilege), &mut ports, builtin())
            .unwrap()
            .bundle;
        let reading: serde_json::Value =
            serde_json::from_slice(bundle.get("superio.json").unwrap()).unwrap();
        assert_eq!(reading["chip"], "NCT5532D");
        assert_eq!(reading["registers"]["2"]["02"], 69);
        let evidence: serde_json::Value =
            serde_json::from_slice(bundle.get(EVIDENCE_FILE).unwrap()).unwrap();
        assert_eq!(evidence["host"]["command"], "diag superio read");
        assert_eq!(evidence["host"]["boot_id"], FakeSysfs::BOOT_ID);
        assert!(bundle.get(MANIFEST_FILE).is_some());
        assert_restored(&ports);
    }
}
