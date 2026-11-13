//! JSON Schemas generated from the document types, so they cannot drift from the parser.
//!
//! Semantic rules (references, geometry, hashes) live in [`crate::validation`];
//! a document can match its schema and still be rejected there.

use crate::case::Case;
use crate::catalog::{Board, Evidence, Finding, Manifest, Patch};
use crate::draft::FirmwareDraft;
use crate::plan::document::{OutputManifest, PlanDocument};
use serde_json::Value;

/// Schema names with the document identifier each describes.
pub const NAMES: &[(&str, &str)] = &[
    ("catalog", crate::catalog::CATALOG_SCHEMA),
    ("board", crate::catalog::BOARD_SCHEMA),
    ("patch", crate::catalog::PATCH_SCHEMA),
    ("finding", crate::catalog::FINDING_SCHEMA),
    ("evidence", crate::catalog::EVIDENCE_SCHEMA),
    ("plan", crate::plan::document::PLAN_SCHEMA),
    ("manifest", crate::plan::document::MANIFEST_SCHEMA),
    ("case", crate::case::CASE_SCHEMA),
    ("firmware-draft", crate::draft::FIRMWARE_DRAFT_SCHEMA),
];

fn finish<T: schemars::JsonSchema>(id: &str) -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(T)).expect("schema serializes");
    schema["$id"] = Value::String(format!(
        "https://github.com/juliopolycarpo/biosmod-engine/schemas/{}.schema.json",
        id.replace('/', "-")
    ));
    schema["properties"]["schema"]["const"] = Value::String(id.to_string());
    schema
}

/// Generate the schema called `name` (see [`NAMES`]).
///
/// Example: `biosmod_core::schema::generate("patch").unwrap()["title"] == "Patch"`
pub fn generate(name: &str) -> Option<Value> {
    let id = NAMES.iter().find(|(n, _)| *n == name)?.1;
    Some(match name {
        "catalog" => finish::<Manifest>(id),
        "board" => finish::<Board>(id),
        "patch" => finish::<Patch>(id),
        "finding" => finish::<Finding>(id),
        "evidence" => finish::<Evidence>(id),
        "plan" => finish::<PlanDocument>(id),
        "case" => finish::<Case>(id),
        "firmware-draft" => finish::<FirmwareDraft>(id),
        _ => finish::<OutputManifest>(id),
    })
}
