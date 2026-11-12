//! The `bme.scenario/1` document: one entry point of one module replayed against modeled hardware.
//!
//! A scenario names the module by SHA-256 and carries no vendor bytes. `bme replay run` checks
//! the digest, replays the entry point in the managed runtime and reports each expectation.
//! Parsing is strict (unknown fields and duplicate keys are rejected); [`validate`] covers what
//! types cannot: identifiers, bitness, device references and operand symbols.
//!
//! Example: [`parse`] on `{"schema":"bme.scenario/1","id":"x",...}` yields a [`Scenario`].

use crate::error::{Code, Error, Result};
use crate::util::{Digest256, Guid, HexBytes};
use schemars::JsonSchema;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// Document identifier of this format.
pub const SCENARIO_SCHEMA: &str = "bme.scenario/1";

/// Names an entry argument or a binding may use instead of a number.
pub const SYMBOLS: [&str; 6] = [
    "image-base",
    "system-table",
    "boot-services",
    "runtime-services",
    "smm-table",
    "pei-services",
];

/// Service slot names per services kind. The runtime's tables (`services.py`) and a Python
/// test check the same file, so the two lists cannot drift apart.
const SERVICE_NAMES: &str = include_str!("../../../tools/replay/service-names.json");

/// Names of the service slots a module can call for `kind`, as `service-calls` may count them.
///
/// Example: `service_names(ServicesKind::Dxe)` contains `GetVariable`; `Pei` contains `LocatePpi`.
pub fn service_names(kind: ServicesKind) -> Vec<String> {
    static ALL: std::sync::OnceLock<std::collections::BTreeMap<String, Vec<String>>> =
        std::sync::OnceLock::new();
    let all = ALL.get_or_init(|| {
        serde_json::from_str(SERVICE_NAMES).expect("service-names.json is a map of name lists")
    });
    let key = match kind {
        ServicesKind::Dxe => "dxe",
        ServicesKind::Smm => "smm",
        ServicesKind::Pei => "pei",
    };
    all[key].clone()
}

/// Device kinds the runtime's library models.
pub const DEVICE_KINDS: [&str; 3] = ["port-registers", "indexed-registers", "mmio-registers"];

/// An integer written as a JSON number or a `0x` string.
///
/// Example: `5720` and `"0x1658"` are the same `Word`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Word(pub u64);

impl Serialize for Word {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:#x}", self.0))
    }
}

fn word_from_value<E: de::Error>(value: &Value) -> std::result::Result<Word, E> {
    match value {
        Value::Number(n) => n
            .as_u64()
            .map(Word)
            .ok_or_else(|| E::custom(format!("number {n}: expected an unsigned integer"))),
        Value::String(text) => text
            .strip_prefix("0x")
            .and_then(|digits| u64::from_str_radix(digits, 16).ok())
            .map(Word)
            .ok_or_else(|| {
                E::custom(format!(
                    "number {text:?}: expected 0x followed by hex digits"
                ))
            }),
        other => Err(E::custom(format!(
            "number {other}: expected an integer or a 0x string"
        ))),
    }
}

impl<'de> Deserialize<'de> for Word {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Word, D::Error> {
        word_from_value(&Value::deserialize(deserializer)?)
    }
}

impl JsonSchema for Word {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Word".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "Unsigned integer as a JSON number or a 0x hex string",
            "oneOf": [
                {"type": "integer", "minimum": 0},
                {"type": "string", "pattern": "^0x[0-9a-fA-F]{1,16}$"}
            ]
        })
    }
}

/// An entry argument: a [`Word`] or one of [`SYMBOLS`].
///
/// Example: `"runtime-services"` passes the address of the modeled runtime services table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Value(Word),
    Symbol(String),
}

impl Serialize for Operand {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Operand::Value(word) => word.serialize(serializer),
            Operand::Symbol(name) => serializer.serialize_str(name),
        }
    }
}

impl<'de> Deserialize<'de> for Operand {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Operand, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match &value {
            Value::String(name) if SYMBOLS.contains(&name.as_str()) => {
                Ok(Operand::Symbol(name.clone()))
            }
            _ => word_from_value(&value).map(Operand::Value),
        }
    }
}

impl JsonSchema for Operand {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Operand".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A Word, or the name of an address the runtime provides",
            "oneOf": [
                {"type": "integer", "minimum": 0},
                {"type": "string", "pattern": "^0x[0-9a-fA-F]{1,16}$"},
                {"type": "string", "enum": SYMBOLS}
            ]
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub schema: String,
    /// Identifier, 1-64 characters of `[A-Za-z0-9._-]`.
    pub id: String,
    pub description: String,
    pub module: ScenarioModule,
    pub entry: ScenarioEntry,
    /// Where service tables come from; omit for a routine that calls none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<ScenarioServices>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hardware: Vec<ScenarioDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variables: Vec<ScenarioVariable>,
    /// Instruction budget of the call.
    pub budget: u64,
    pub expect: Vec<Expectation>,
}

/// The module under test, by digest only.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioModule {
    /// Label for records, such as `SioDxeInit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub sha256: Digest256,
    /// 32 or 64; checked against the image header.
    pub bitness: u8,
    /// Load address; the runtime default when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Word>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioEntry {
    /// Entry point as an RVA inside the image.
    pub rva: Word,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<Operand>,
}

/// Service tables the module may call, and where it finds them.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioServices {
    pub kind: ServicesKind,
    /// Pointer-sized image fields to fill before the call, such as a driver's `gRT`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bind: Vec<ScenarioBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ServicesKind {
    Dxe,
    Smm,
    Pei,
}

impl ServicesKind {
    /// Symbols this kind of service provides besides `image-base`.
    pub fn symbols(self) -> &'static [&'static str] {
        match self {
            ServicesKind::Dxe => &["system-table", "boot-services", "runtime-services"],
            ServicesKind::Smm => &["smm-table"],
            ServicesKind::Pei => &["pei-services"],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioBinding {
    /// RVA of the pointer-sized field.
    pub rva: Word,
    /// One of the symbols of the services kind.
    pub to: String,
}

/// A named hardware model from the runtime's library.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioDevice {
    /// Unique name; expectations refer to it.
    pub name: String,
    /// `port-registers`, `indexed-registers` or `mmio-registers`.
    pub kind: String,
    /// MMIO base address; only `mmio-registers`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Word>,
    /// MMIO window size; only `mmio-registers`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<Word>,
    /// Options of the model, as the runtime documents them.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    #[schemars(with = "serde_json::Map<String, Value>")]
    pub options: Map<String, Value>,
}

/// A UEFI variable present before the call.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioVariable {
    pub name: String,
    pub guid: Guid,
    pub data: HexBytes,
    /// Variable attributes; 7 (NV, BS, RT) when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<u32>,
}

/// One pass/fail check after the call returned.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Expectation {
    /// The routine returned this value in RAX or EAX.
    Return { equals: Word },
    /// An indexed register of an `indexed-registers` device holds a value (after `mask`).
    Register {
        device: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bank: Option<Word>,
        index: Word,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mask: Option<Word>,
        equals: Word,
    },
    /// A `port-registers` port holds a value.
    Port {
        device: String,
        port: Word,
        equals: Word,
    },
    /// A UEFI variable holds exactly these bytes.
    Variable {
        name: String,
        guid: Guid,
        equals: HexBytes,
    },
    /// The module called a service this many times.
    ServiceCalls { service: String, count: Word },
}

fn invalid(message: String) -> Error {
    Error::new(Code::ScenarioInvalid, message)
}

/// Re-code an error from the shared JSON and identifier checks, which report catalog documents.
fn scenario_error(mut error: Error) -> Error {
    error.code = Code::ScenarioInvalid;
    error
}

/// Parse and validate a scenario file.
///
/// Example: a document with an unknown field fails naming it; one that parses but refers to
/// an undeclared device fails with `expectation 0: device "hwm": expected a declared ...`.
pub fn parse(bytes: &[u8], what: &str) -> Result<Scenario> {
    let scenario: Scenario = crate::json::parse_strict(bytes, what).map_err(scenario_error)?;
    validate(&scenario).map_err(|e| e.context(what))?;
    Ok(scenario)
}

/// Semantic checks of a parsed scenario.
///
/// Example: bitness 16 fails with `module bitness: expected 32 | 64 | received 16`.
pub fn validate(scenario: &Scenario) -> Result<()> {
    if scenario.schema != SCENARIO_SCHEMA {
        return Err(invalid(format!(
            "schema: expected {SCENARIO_SCHEMA} | received {}",
            scenario.schema
        )));
    }
    crate::validation::identifier(&scenario.id, "scenario id").map_err(scenario_error)?;
    if ![32, 64].contains(&scenario.module.bitness) {
        return Err(invalid(format!(
            "module bitness: expected 32 | 64 | received {}",
            scenario.module.bitness
        )));
    }
    if scenario.budget == 0 {
        return Err(invalid(
            "budget: expected at least 1 instruction | received 0".into(),
        ));
    }
    if scenario.expect.is_empty() {
        return Err(invalid(
            "expect: expected at least one expectation | received none".into(),
        ));
    }
    let symbols = symbols_of(scenario);
    for (index, arg) in scenario.entry.args.iter().enumerate() {
        if let Operand::Symbol(name) = arg
            && !symbols.contains(&name.as_str())
        {
            return Err(invalid(format!(
                "entry argument {index}: expected a symbol from {symbols:?} | received {name:?}"
            )));
        }
    }
    if let Some(services) = &scenario.services {
        for bind in &services.bind {
            if !symbols.contains(&bind.to.as_str()) {
                return Err(invalid(format!(
                    "binding at {:#x}: expected a symbol from {symbols:?} | received {:?}",
                    bind.rva.0, bind.to
                )));
            }
        }
    }
    devices(scenario)?;
    for (index, expectation) in scenario.expect.iter().enumerate() {
        expectation_refs(scenario, expectation)
            .map_err(|e| e.context(format!("expectation {index}")))?;
    }
    Ok(())
}

fn symbols_of(scenario: &Scenario) -> Vec<&'static str> {
    let mut symbols = vec!["image-base"];
    if let Some(services) = &scenario.services {
        symbols.extend(services.kind.symbols());
    }
    symbols
}

fn devices(scenario: &Scenario) -> Result<()> {
    let mut seen = BTreeSet::new();
    for device in &scenario.hardware {
        crate::validation::identifier(&device.name, "hardware name").map_err(scenario_error)?;
        if !seen.insert(device.name.as_str()) {
            return Err(invalid(format!(
                "hardware {:?}: expected a unique name | received a duplicate",
                device.name
            )));
        }
        if !DEVICE_KINDS.contains(&device.kind.as_str()) {
            return Err(invalid(format!(
                "hardware {:?} kind: expected one of {DEVICE_KINDS:?} | received {:?}",
                device.name, device.kind
            )));
        }
        let mmio = device.kind == "mmio-registers";
        let ok = if mmio {
            device.base.is_some() && device.size.is_some()
        } else {
            device.base.is_none() && device.size.is_none()
        };
        if !ok {
            return Err(invalid(format!(
                "hardware {:?}: expected base and size exactly for mmio-registers | received kind {} with base {:?} and size {:?}",
                device.name,
                device.kind,
                device.base.map(|w| w.0),
                device.size.map(|w| w.0)
            )));
        }
    }
    Ok(())
}

fn expectation_refs(scenario: &Scenario, expectation: &Expectation) -> Result<()> {
    let (device, wanted) = match expectation {
        Expectation::Register { device, .. } => (device, "indexed-registers"),
        Expectation::Port { device, .. } => (device, "port-registers"),
        // A module may create the variable with SetVariable, so it needs no declaration.
        Expectation::Variable { .. } => return Ok(()),
        Expectation::ServiceCalls { service, .. } => {
            let Some(services) = &scenario.services else {
                return Err(invalid(format!(
                    "service {service:?}: expected a services block | received none"
                )));
            };
            let names = service_names(services.kind);
            return if names.contains(service) {
                Ok(())
            } else {
                Err(invalid(format!(
                    "service {service:?}: expected one of the {:?} services {names:?} | received {service:?}",
                    services.kind
                )))
            };
        }
        Expectation::Return { .. } => return Ok(()),
    };
    match scenario.hardware.iter().find(|d| d.name == *device) {
        Some(found) if found.kind == wanted => Ok(()),
        Some(found) => Err(invalid(format!(
            "device {device:?}: expected kind {wanted} | received {}",
            found.kind
        ))),
        None => Err(invalid(format!(
            "device {device:?}: expected a declared {wanted} device | received none"
        ))),
    }
}

#[cfg(test)]
mod tests;
