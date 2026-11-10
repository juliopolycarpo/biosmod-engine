//! `version`, `capabilities`, `schema` and `guide`.

use crate::output::{PROTOCOL, Reply, exit};
use biosmod_core::{Code, Error, Result, schema};
use serde_json::{Value, json};

/// Built-in documentation topics (the same files as docs/guide/).
pub const GUIDES: &[(&str, &str, &str)] = &[
    (
        "workflow",
        "scan, plan, patch and verify an image",
        include_str!("../../../../docs/guide/workflow.md"),
    ),
    (
        "flashing",
        "what to do before and after writing a chip",
        include_str!("../../../../docs/guide/flashing.md"),
    ),
    (
        "recovery",
        "getting a board back after a bad flash",
        include_str!("../../../../docs/guide/recovery.md"),
    ),
    (
        "catalogs",
        "catalog layout, records and indexing",
        include_str!("../../../../docs/guide/catalogs.md"),
    ),
    (
        "trust",
        "sources, signatures, snapshots and plans",
        include_str!("../../../../docs/guide/trust.md"),
    ),
    (
        "porting",
        "moving a fix to another firmware build",
        include_str!("../../../../docs/guide/porting.md"),
    ),
    (
        "agents",
        "the JSON protocol for scripts and agents",
        include_str!("../../../../docs/guide/agents.md"),
    ),
    (
        "breadcrumbs",
        "the MR9A MRC checkpoint diagnostic",
        include_str!("../../../../docs/guide/breadcrumbs.md"),
    ),
    (
        "ghidra",
        "installing and running the analysis toolchain",
        include_str!("../../../../docs/guide/ghidra.md"),
    ),
];

/// JSON Schema of the stdout envelope.
pub const ENVELOPE_SCHEMA: &str = include_str!("../../../../schemas/envelope.schema.json");

pub fn version() -> Reply {
    let codec = biosmod_core::codec::identity();
    let data = json!({"engine": biosmod_core::VERSION, "protocol": PROTOCOL, "codec": codec, "build_fingerprint": biosmod_core::plan::document::EngineId::current().build_fingerprint, "target": std::env::consts::OS, "arch": std::env::consts::ARCH});
    Reply::new(
        data,
        format!(
            "bme {} (protocol {PROTOCOL}, {codec})\n",
            biosmod_core::VERSION
        ),
    )
}

fn commands() -> Value {
    json!([
        {"name": "inspect", "writes": [], "network": false, "summary": "volumes, files, descriptor regions"},
        {"name": "scan", "writes": [], "network": false, "summary": "firmware detection and patch states"},
        {"name": "plan", "writes": ["plan file"], "network": false, "summary": "compatibility command for saving a plan"},
        {"name": "export", "writes": ["patch recipe"], "network": false, "summary": "save an exact recipe for patch IDs or recommendations"},
        {"name": "patch", "writes": ["image", "manifest"], "network": false, "summary": "build a verified copy from patch IDs, recommendations or a saved recipe"},
        {"name": "patch --dry-run", "writes": [], "network": false, "summary": "build and validate in memory without publishing files"},
        {"name": "verify", "writes": [], "network": false, "summary": "independent check of an input/output pair"},
        {"name": "extract", "writes": ["module"], "network": false, "summary": "write one PE32 or ACPI module"},
        {"name": "replace", "writes": ["image", "manifest"], "network": false, "summary": "put an edited module back"},
        {"name": "derive", "writes": [], "network": false, "summary": "draft a variant by unique signature matching"},
        {"name": "catalog validate|index|show|import-x99fix", "writes": ["catalog files (index, import)"], "network": false},
        {"name": "catalog add|list|remove", "writes": ["config"], "network": false},
        {"name": "catalog update", "writes": ["source snapshot"], "network": true},
        {"name": "tools doctor|paths", "writes": [], "network": false},
        {"name": "tools setup ghidra", "writes": ["tool install", "cache"], "network": true},
        {"name": "tools analyze", "writes": ["Ghidra project", "exports"], "network": false},
        {"name": "diag breadcrumbs decode|read", "writes": [], "network": false, "summary": "read uses ports 72h/73h only"},
        {"name": "dev synthetic", "writes": ["synthetic image and catalog"], "network": false},
        {"name": "version|capabilities|schema|guide", "writes": [], "network": false}
    ])
}

pub fn capabilities() -> Reply {
    let codes: Vec<Value> = Code::ALL.iter().map(|c| json!({"code": c.as_str(), "meaning": c.meaning(), "exit": crate::output::code_for(*c)})).collect();
    let data = json!({
        "engine": biosmod_core::VERSION,
        "protocol": PROTOCOL,
        "desktop_workflow": 1,
        "direct_patch_workflow": 1,
        "codec": biosmod_core::codec::identity(),
        "commands": commands(),
        "documents": schema::NAMES.iter().map(|(name, id)| json!({"name": name, "schema": id})).collect::<Vec<_>>(),
        "formats": {
            "containers": ["Intel flash descriptor images", "bare BIOS regions", "EFI firmware volumes (FFS2/FFS3)"],
            "sections": ["FV image", "GUID-defined LZMA (EE4E5898)", "GUID-defined CRC32 (FC1BCDB2)", "PE32", "TE", "raw", "UI"],
            "leaves": ["pe32", "acpi-table"],
            "rebuild": ["equal-size and appended hunks", "LZMA re-encoding byte-identical to liblzma", "free-space file reflow; XIP files never move"],
            "unsupported": ["compression sections (type 01: EFI standard, Tiano)", "other GUID-defined encodings such as Brotli", "capsule and signed update formats", "moving execute-in-place files"]
        },
        "limits": {"image_bytes": crate::commands::MAX_IMAGE_BYTES, "catalog_file_bytes": biosmod_core::catalog::MAX_FILE_BYTES, "catalog_files": biosmod_core::catalog::MAX_FILES},
        "verification_required_checks": super::firmware::REQUIRED_VERIFICATION_CHECKS,
        "exit_codes": {"ok": exit::OK, "failed": exit::FAILED, "usage": exit::USAGE, "publication_incomplete": exit::INCOMPLETE},
        "error_codes": codes,
        "guarantees": [
            "never reads or writes a flash chip",
            "outputs are new files; inputs are never modified",
            "firmware commands never use the network",
            "every output is re-parsed and compared outside an allowlist before publication"
        ]
    });
    let text = format!(
        "bme {} protocol {PROTOCOL}\nUse `bme capabilities --json` for the machine-readable list of commands, documents, formats, limits and error codes.\n",
        biosmod_core::VERSION
    );
    Reply::new(data, text)
}

pub fn schema(name: Option<&str>) -> Result<Reply> {
    let Some(name) = name else {
        let mut names: Vec<&str> = schema::NAMES.iter().map(|(n, _)| *n).collect();
        names.push("envelope");
        return Ok(Reply::new(
            json!({"schemas": names}),
            format!("{}\n", names.join("\n")),
        ));
    };
    let value: Value = if name == "envelope" {
        serde_json::from_str(ENVELOPE_SCHEMA).expect("bundled envelope schema is JSON")
    } else {
        schema::generate(name).ok_or_else(|| {
            Error::new(
                Code::Usage,
                format!(
                    "schema {name:?}: expected one of {} or envelope",
                    schema::NAMES
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })?
    };
    let text = String::from_utf8(biosmod_core::json::pretty(&value)).expect("JSON is UTF-8");
    Ok(Reply::new(value, text))
}

pub fn guide(topic: Option<&str>) -> Result<Reply> {
    let Some(topic) = topic else {
        let text: String = GUIDES
            .iter()
            .map(|(name, summary, _)| format!("{name:<12} {summary}\n"))
            .collect();
        let topics: Vec<Value> = GUIDES
            .iter()
            .map(|(name, summary, _)| json!({"topic": name, "summary": summary}))
            .collect();
        return Ok(Reply::new(
            json!({"topics": topics}),
            text + "\nRead one with: bme guide <topic>\n",
        ));
    };
    let (_, _, body) = GUIDES
        .iter()
        .find(|(name, _, _)| *name == topic)
        .ok_or_else(|| {
            Error::new(
                Code::Usage,
                format!(
                    "guide {topic:?}: expected one of {}",
                    GUIDES.iter().map(|g| g.0).collect::<Vec<_>>().join(", ")
                ),
            )
        })?;
    Ok(Reply::new(json!({"topic": topic, "markdown": body}), *body))
}

#[cfg(test)]
mod tests {
    #[test]
    fn capabilities_advertise_verification_checks() {
        let data = super::capabilities().data;
        let checks = &data["verification_required_checks"];
        assert!(
            checks.as_array().is_some_and(|items| !items.is_empty()),
            "capabilities verification_required_checks: expected a nonempty array | received {checks}"
        );
    }

    #[test]
    fn capabilities_advertise_guarded_desktop_workflow() {
        assert_eq!(super::capabilities().data["desktop_workflow"], 1);
    }
}
