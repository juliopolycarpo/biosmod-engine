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
        "backing up and writing the chip, in the OS or with a programmer",
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
        "publishing",
        "signing a catalog release and the URL users register",
        include_str!("../../../../docs/guide/publishing.md"),
    ),
    (
        "cases",
        "recording an investigation and starting on an unknown board",
        include_str!("../../../../docs/guide/cases.md"),
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
        "ifr",
        "decoding Setup forms: question offsets, options, defaults, conditions",
        include_str!("../../../../docs/guide/ifr.md"),
    ),
    (
        "nvram",
        "reading NVRAM variable stores: record states, defaults, Setup fields, size checks",
        include_str!("../../../../docs/guide/nvram.md"),
    ),
    (
        "diagnostics",
        "capturing what the running machine reports (ACPI tables, sleep state)",
        include_str!("../../../../docs/guide/diagnostics.md"),
    ),
    (
        "ghidra",
        "installing and running the analysis toolchain",
        include_str!("../../../../docs/guide/ghidra.md"),
    ),
    (
        "replay",
        "the Python runtime that replays firmware against simulated hardware",
        include_str!("../../../../docs/guide/replay.md"),
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
        {"name": "ifr", "writes": [], "network": false, "summary": "decode Setup forms (UEFI IFR): questions, varstore offsets, options, defaults, conditions"},
        {"name": "nvram", "writes": ["variable data (--dump -o)"], "network": false, "summary": "list NVRAM variables (AMI NVAR, EDK II VSS) with record state, GUID, size and hash; --field compares a Setup question's stored value with its IFR default"},
        {"name": "inspect", "writes": [], "network": false, "summary": "volumes, files, descriptor regions; --acpi lists stored ACPI tables"},
        {"name": "scan", "writes": [], "network": false, "summary": "firmware detection and patch states"},
        {"name": "plan", "writes": ["plan file"], "network": false, "summary": "compatibility command for saving a plan"},
        {"name": "export", "writes": ["patch recipe"], "network": false, "summary": "save an exact recipe for patch IDs or recommendations"},
        {"name": "patch", "writes": ["image", "manifest"], "network": false, "summary": "build a verified copy from patch IDs, recommendations or a saved recipe"},
        {"name": "patch --dry-run", "writes": [], "network": false, "summary": "build and validate in memory without publishing files"},
        {"name": "verify", "writes": [], "network": false, "summary": "independent check of an input/output pair"},
        {"name": "extract", "writes": ["module"], "network": false, "summary": "write one PE32 or ACPI module; ACPI tables can be picked by --signature, --oem-table-id or --sha256"},
        {"name": "replace", "writes": ["image", "manifest"], "network": false, "summary": "put an edited module back"},
        {"name": "derive", "writes": [], "network": false, "summary": "draft a variant by unique signature matching"},
        {"name": "compare", "writes": [], "network": false, "summary": "pair two images' modules by GUID; identical, identical after relocation, or different with changed ranges"},
        {"name": "compare --functions", "writes": [], "network": false, "summary": "pair the functions of two tools analyze exports; identical, normalized-identical, changed with instruction ranges, unmatched; heuristic pairs are candidates"},
        {"name": "compare --acpi", "writes": [], "network": false, "summary": "pair ACPI tables of two ROMs, .aml files or diag acpi capture directories by signature and OEM table ID; added, removed and changed methods and names"},
        {"name": "compare --acpi --disassemble", "writes": ["method diffs"], "network": false, "summary": "also run iasl (optional) and write one unified ASL diff per changed method"},
        {"name": "catalog init", "writes": ["device repository directory"], "network": false, "summary": "new directory with an empty catalog, notes directories, a .gitignore that keeps firmware images out of git and a .github/workflows/validate.yml that runs `catalog index --check` and `catalog validate`; `--repository URL` records the https URL of the repository that holds it; does not run git"},
        {"name": "catalog split", "writes": ["device repository directory"], "network": false, "summary": "new device repository (the `catalog init` scaffold, workflow included) with one board's records cut from a catalog directory or `official`; keeps the not-applicable verdicts of the board's builds; `--repository URL` records where the new catalog lives; lists the patches, findings, evidence and provenance files left out"},
        {"name": "catalog merge --check", "writes": [], "network": false, "summary": "report whether two or more catalogs agree on the records they share; names the record, field, both values and both catalogs on a difference; reports whether the sources a catalog pins still match, naming the pinned commit of a moved one"},
        {"name": "catalog merge -o", "writes": ["catalog directory"], "network": false, "summary": "new catalog directory that unions the records of two or more catalogs and lists them in `sources` with their digest, `repository` and checked-out git commit"},
        {"name": "catalog validate|index|show|import-x99fix", "writes": ["catalog files (index, import)"], "network": false},
        {"name": "catalog add|list|remove", "writes": ["config"], "network": false},
        {"name": "catalog update", "writes": ["source snapshot"], "network": true},
        {"name": "case init", "writes": ["case directory"], "network": false, "summary": "hash a dump, scan it with detectors and draft an unreviewed board profile and firmware build"},
        {"name": "case record", "writes": ["case artifacts", "case.json", "the command's own outputs"], "network": false, "summary": "run a bme command in-process and store its JSON output and output files with digests, argv and versions"},
        {"name": "case status", "writes": [], "network": false, "summary": "verify inputs and artifacts; CASE_DRIFT when one is changed or missing; stale results are reported"},
        {"name": "case export", "writes": ["catalog submission directory"], "network": false, "summary": "board, build, findings and evidence from a case as a catalog bme catalog validate accepts"},
        {"name": "tools doctor|paths", "writes": [], "network": false, "summary": "doctor also checks the replay runtime once installed; `doctor replay` requires it"},
        {"name": "tools status", "writes": [], "network": false, "summary": "every tool's version, location and install command; a missing tool is a row, not a failure"},
        {"name": "tools set|unset", "writes": ["config"], "network": false, "summary": "choose an existing Ghidra directory, flashrom executable or replay Python environment"},
        {"name": "tools setup ghidra", "writes": ["tool install", "cache"], "network": true},
        {"name": "tools setup replay", "writes": ["Python environment"], "network": true, "summary": "create a virtual environment with hash-locked Unicorn, Capstone and pefile; --offline --wheelhouse installs from local wheels"},
        {"name": "replay run", "writes": ["result.jsonl", "evidence.json"], "network": false, "summary": "replay a bme.scenario/1 file against the module it names by SHA-256, report pass/fail per expectation and record an offline-validation evidence record; exits REPLAY_FAILED when an expectation fails; requires `tools setup replay`"},
        {"name": "replay script", "writes": ["result.jsonl", "evidence.json"], "network": false, "summary": "run a Python harness against firmware modules in the replay runtime and record an offline-validation evidence record; requires `tools setup replay`"},
        {"name": "tools analyze", "writes": ["Ghidra project", "exports"], "network": false},
        {"name": "diag breadcrumbs decode|read", "writes": [], "network": false, "summary": "read uses ports 72h/73h only"},
        {"name": "diag acpi capture", "writes": ["capture directory"], "network": false, "summary": "copy ACPI tables, sleep states and sleep kernel messages into a hashed bundle with an evidence record (Linux, root)"},
        {"name": "diag smbios", "writes": ["capture directory (optional)"], "network": false, "summary": "decode the firmware's SMBIOS table: BIOS, system, baseboard and memory devices with slot widths and speeds; without root only model-level DMI fields, with memory devices reported unavailable (Linux)"},
        {"name": "diag suspend pm-test", "writes": ["/sys/power/pm_test and /sys/power/state (pm_test restored to none)", "capture directory"], "network": false, "summary": "run one kernel suspend test stage that stops at its checkpoint without sleeping the machine, and report the suspend counters; requires --i-understand-this-suspends (Linux, root)"},
        {"name": "diag superio read", "writes": ["Super I/O access selectors (restored)", "capture directory (optional)"], "network": false, "summary": "identify a Super I/O chip by ID and read its logical devices and hardware-monitor registers; refuses unknown chips; when a kernel hwmon driver owns the chip it reads that driver's sysfs files and touches no port, or with --unbound-only refuses naming the module to unload (Linux, root)"},
        {"name": "flash doctor", "writes": [], "network": false, "summary": "read-only system diagnosis for chip access (sysfs, flashrom version)"},
        {"name": "flash probe", "writes": [], "network": false, "summary": "detect the flash chip through flashrom"},
        {"name": "flash backup", "writes": ["chip dump"], "network": false, "summary": "read the chip twice and save identical reads as a new file"},
        {"name": "flash write", "writes": ["flash chip"], "network": false, "summary": "write an image after matching a backup against the chip; requires --confirm <image sha256>"},
        {"name": "flash write --dry-run", "writes": [], "network": false, "summary": "run every write check, including the chip comparison, without writing"},
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
        "flash_workflow": 1,
        "tools_workflow": 1,
        "case_workflow": 1,
        "tools": crate::toolchain::TOOL_IDS,
        "codec": biosmod_core::codec::identity(),
        "commands": commands(),
        "documents": schema::NAMES.iter().map(|(name, id)| json!({"name": name, "schema": id})).collect::<Vec<_>>(),
        "formats": {
            "containers": ["Intel flash descriptor images", "bare BIOS regions", "EFI firmware volumes (FFS2/FFS3)"],
            "sections": ["FV image", "GUID-defined LZMA (EE4E5898)", "GUID-defined CRC32 (FC1BCDB0)", "compression section type 01 (EFI 1.1 and Tiano, decode only)", "GUID-defined Brotli (3D532050, decode only)", "GUID-defined LZMA F86 (D42AE6BD, decode only)", "PE32", "TE", "raw", "UI"],
            "leaves": ["pe32", "acpi-table"],
            "variable_stores": ["AMI NVAR (records, chains, GUID table, StdDefaults/MfgDefaults)", "EDK II VSS/VSS2 and $VSS (plain and authenticated headers); read-only"],
            "acpi_inventory": "checksum-valid ACPI tables in PE32, TE and raw sections (stored set, not the runtime-published set)",
            "rebuild": ["equal-size and appended hunks", "LZMA re-encoding byte-identical to liblzma (the only encoding rebuilt)", "free-space file reflow; XIP files never move"],
            "unsupported": ["rebuilding modules inside EFI 1.1, Tiano, Brotli or LZMA F86 sections (FORMAT_UNSUPPORTED)", "compression sections of other types", "other GUID-defined encodings", "Insyde and Phoenix vendor variants", "capsule and signed update formats", "moving execute-in-place files"]
        },
        "limits": {"image_bytes": crate::commands::MAX_IMAGE_BYTES, "catalog_file_bytes": biosmod_core::catalog::MAX_FILE_BYTES, "catalog_files": biosmod_core::catalog::MAX_FILES},
        "verification_required_checks": super::firmware::REQUIRED_VERIFICATION_CHECKS,
        "exit_codes": {"ok": exit::OK, "failed": exit::FAILED, "usage": exit::USAGE, "publication_incomplete": exit::INCOMPLETE},
        "error_codes": codes,
        "guarantees": [
            "diag commands read the running machine and write only a new capture directory, except where their summary says otherwise",
            "only the flash commands access a flash chip, through flashrom; flash write is the only command that changes one",
            "flash write requires a backup equal to the chip, an image that parses and the image SHA-256 as confirmation, then reads the chip back",
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
    fn capabilities_advertise_the_case_workflow_and_its_commands() {
        let data = super::capabilities().data;
        assert_eq!(data["case_workflow"], 1);
        let names: Vec<&str> = data["commands"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["name"].as_str())
            .collect();
        for expected in ["case init", "case record", "case status", "case export"] {
            assert!(
                names.contains(&expected),
                "(commands): expected {expected:?} | received {names:?}"
            );
        }
        let codes = data["error_codes"].as_array().unwrap();
        assert!(
            codes.iter().any(|c| c["code"] == "CASE_DRIFT"),
            "(error_codes): expected CASE_DRIFT"
        );
    }

    #[test]
    fn capabilities_list_every_tool_row_in_report_order() {
        let data = super::capabilities().data;
        assert_eq!(
            data["tools"],
            serde_json::json!(crate::toolchain::TOOL_IDS),
            "(capabilities tools): expected the tool id constant"
        );
    }

    #[test]
    fn guide_publishing_is_listed_and_returns_its_page() {
        let listed = super::guide(None).unwrap().data;
        let topics: Vec<&str> = listed["topics"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["topic"].as_str())
            .collect();
        assert!(
            topics.contains(&"publishing"),
            "(guide topics): expected publishing | received {topics:?}"
        );
        let page = super::guide(Some("publishing")).unwrap().data;
        let markdown = page["markdown"].as_str().unwrap();
        assert!(
            markdown.starts_with("# Publish a catalog\n"),
            "(guide publishing): expected the page title | received {:?}",
            markdown.lines().next()
        );
    }

    #[test]
    fn guide_topics_are_unique_and_each_page_starts_with_a_title() {
        let mut seen = std::collections::BTreeSet::new();
        for (name, _, body) in super::GUIDES {
            assert!(seen.insert(*name), "(guide topics): duplicate {name:?}");
            assert!(
                body.starts_with("# "),
                "(guide {name}): expected a title line | received {:?}",
                body.lines().next()
            );
        }
    }

    #[test]
    fn capabilities_advertise_guarded_desktop_workflow() {
        assert_eq!(super::capabilities().data["desktop_workflow"], 1);
    }
}
