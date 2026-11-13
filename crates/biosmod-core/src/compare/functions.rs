//! Compare the functions of two `tools analyze` JSON exports.
//!
//! Pairing runs in three stages, each only over functions the earlier stages
//! left unmatched:
//!
//! 1. exact byte hash of the instruction bytes: `identical`;
//! 2. hash of operand-normalized instruction text, which masks flow targets,
//!    resolved image addresses and Ghidra's address-derived labels:
//!    `normalized-identical`;
//! 3. call-graph position: an unmatched function that calls or is called by an
//!    already matched pair is paired with the unmatched neighbor of the other
//!    side that shares the most anchors and resembles it most; unmatched entry
//!    points (functions nothing in the module calls) may pair with each other.
//!    These pairs are heuristic and carry `candidate: true` for review.
//!
//! A hash stage pairs a hash only when both sides hold the same number of
//! functions with it (paired in RVA order); an ambiguous hash is left to the
//! next stage. Pairs whose normalized instructions still differ are `changed`
//! and report the differing instruction ranges.
//!
//! Example: `let report = compare_functions(&parse_export(&a, "A.json")?, &parse_export(&b, "B.json")?);`

use crate::error::{Code, Error, Result};
use crate::util::sha256_hex;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Smallest instruction-sequence similarity (0..=1) a call-graph candidate needs.
pub const MIN_CANDIDATE_SIMILARITY: f64 = 0.5;
/// Largest `a * b` cell count of a longest-common-subsequence table.
const MAX_DIFF_CELLS: usize = 16_000_000;

#[derive(Deserialize)]
struct RawExport {
    #[serde(default)]
    program: String,
    #[serde(default)]
    image_base: String,
    #[serde(default)]
    blocks: Vec<RawBlock>,
    functions: Option<Vec<RawFunction>>,
}

#[derive(Deserialize)]
struct RawBlock {
    #[serde(default)]
    start: String,
    #[serde(default)]
    size: u64,
}

#[derive(Deserialize)]
struct RawFunction {
    #[serde(default)]
    name: String,
    rva: String,
    #[serde(default)]
    calls: Vec<RawCall>,
    instructions: Option<Vec<RawInstruction>>,
}

#[derive(Deserialize)]
struct RawCall {
    rva: String,
}

#[derive(Deserialize)]
struct RawInstruction {
    rva: String,
    bytes: String,
    #[serde(default)]
    mnemonic: String,
    #[serde(default)]
    text: String,
}

/// One instruction of an exported function.
#[derive(Debug, Clone)]
struct Instruction {
    rva: u64,
    length: u64,
    bytes: String,
    /// Operand-normalized text.
    normalized: String,
}

/// One exported function with the hashes the matcher uses.
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub rva: u64,
    callees: Vec<u64>,
    instructions: Vec<Instruction>,
    exact_hash: String,
    normalized_hash: String,
}

impl Function {
    /// Number of instructions.
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}

/// A parsed `tools analyze` export (`<module>.json`).
#[derive(Debug, Clone)]
pub struct FunctionExport {
    pub program: String,
    pub image_base: u64,
    functions: Vec<Function>,
}

impl FunctionExport {
    /// Exported functions in RVA order.
    pub fn functions(&self) -> &[Function] {
        &self.functions
    }
}

fn parse_hex(text: &str, what: &str) -> Result<u64> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(digits, 16).map_err(|_| {
        Error::new(
            Code::FormatInvalid,
            format!("{what}: expected hexadecimal like 0x1a2b | received {text:?}"),
        )
    })
}

/// Hex digits of a Ghidra address such as `00401000` or `ram:00401000`.
fn address_value(text: &str) -> Option<u64> {
    u64::from_str_radix(text.rsplit(':').next()?, 16).ok()
}

/// x86 register names Ghidra prints as an indirect flow operand.
fn is_register(operand: &str) -> bool {
    let lower = operand.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "ax" | "bx"
            | "cx"
            | "dx"
            | "si"
            | "di"
            | "bp"
            | "sp"
            | "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
    ) || (lower.starts_with('r')
        && lower.len() > 1
        && lower[1..]
            .trim_end_matches(['d', 'w', 'b'])
            .parse::<u8>()
            .is_ok())
}

/// Whether the mnemonic transfers control (call, jump, conditional jump, loop).
fn is_flow(mnemonic: &str) -> bool {
    let upper = mnemonic.to_ascii_uppercase();
    upper == "CALL" || upper.starts_with('J') || upper.starts_with("LOOP")
}

/// Ghidra labels derived from an address, e.g. `FUN_00401234`.
const ADDRESS_LABELS: [&str; 7] = ["FUN_", "DAT_", "LAB_", "PTR_", "UNK_", "SUB_", "EXT_"];

/// Replace address-derived labels and in-image hex literals so rebased builds compare equal.
fn mask_addresses(text: &str, image: std::ops::Range<u64>) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < bytes.len() {
        let rest = &text[at..];
        if let Some(label) = ADDRESS_LABELS.iter().find(|l| rest.starts_with(**l)) {
            let digits = rest[label.len()..]
                .bytes()
                .take_while(u8::is_ascii_hexdigit)
                .count();
            if digits >= 8 {
                out.push_str(label);
                out.push_str("ADDRESS");
                at += label.len() + digits;
                continue;
            }
        }
        if let Some(hex) = rest.strip_prefix("0x") {
            let digits = hex.bytes().take_while(u8::is_ascii_hexdigit).count();
            let literal = &rest[..2 + digits];
            match u64::from_str_radix(&hex[..digits], 16) {
                Ok(value) if digits > 0 && image.contains(&value) => out.push_str("IMAGE_ADDRESS"),
                _ => out.push_str(literal),
            }
            at += literal.len();
            continue;
        }
        let ch = rest.chars().next().expect("non-empty remainder");
        out.push(ch);
        at += ch.len_utf8();
    }
    out
}

/// Normalize one instruction's text: direct flow targets, resolved image
/// addresses and address-derived labels are masked; registers, sizes and
/// ordinary immediates stay.
///
/// Example: `normalize_instruction("CALL", "CALL 0x00401234", 0x400000..0x500000)` is `"CALL FLOW_TARGET"`.
pub fn normalize_instruction(mnemonic: &str, text: &str, image: std::ops::Range<u64>) -> String {
    let (head, operand) = text.split_once(' ').unwrap_or((text, ""));
    let operand = operand.trim();
    if is_flow(mnemonic)
        && !operand.is_empty()
        && !operand.contains('[')
        && !is_register(operand)
        && !operand.contains(' ')
    {
        return format!("{head} FLOW_TARGET");
    }
    mask_addresses(text, image)
}

/// Parse a `tools analyze` JSON export.
///
/// `what` names the input in errors. Every function needs `rva` and
/// `instructions` (each with `rva` and `bytes`); exports lacking them are rejected.
///
/// Example: `let export = parse_export(&std::fs::read("Module.json")?, "Module.json")?;`
pub fn parse_export(json: &[u8], what: &str) -> Result<FunctionExport> {
    let raw: RawExport = serde_json::from_slice(json).map_err(|e| {
        Error::new(
            Code::FormatInvalid,
            format!("{what}: expected a bme tools analyze JSON export | received {e}"),
        )
    })?;
    let raw_functions = raw.functions.ok_or_else(|| {
        Error::new(
            Code::FormatInvalid,
            format!("{what}: expected a \"functions\" array | received none"),
        )
    })?;
    let image_base = if raw.image_base.is_empty() {
        0
    } else {
        parse_hex(&raw.image_base, &format!("{what} image_base"))?
    };
    let extent_end = raw
        .blocks
        .iter()
        .filter_map(|b| address_value(&b.start).map(|start| start.saturating_add(b.size)))
        .max()
        .unwrap_or(0);
    let mut functions = Vec::with_capacity(raw_functions.len());
    for function in raw_functions {
        let rva = parse_hex(
            &function.rva,
            &format!("{what} function {} rva", function.name),
        )?;
        let instructions = function.instructions.ok_or_else(|| {
            Error::new(
                Code::FormatInvalid,
                format!(
                    "{what} function {} at {:#x}: expected an \"instructions\" list | received none (re-export with a current `bme tools analyze`)",
                    function.name, rva
                ),
            )
        })?;
        let mut parsed = Vec::with_capacity(instructions.len());
        let mut last_rva = 0u64;
        for mut ins in instructions {
            let at = parse_hex(&ins.rva, &format!("{what} instruction rva"))?;
            // Lowercase so the exact hash does not depend on how a tool cased its hex.
            ins.bytes.make_ascii_lowercase();
            if ins.bytes.len() % 2 != 0 || !ins.bytes.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::new(
                    Code::FormatInvalid,
                    format!(
                        "{what} instruction at {at:#x}: expected even-length hex bytes | received {:?}",
                        ins.bytes
                    ),
                ));
            }
            let length = ins.bytes.len() as u64 / 2;
            let end = at.checked_add(length).ok_or_else(|| {
                Error::new(
                    Code::FormatInvalid,
                    format!(
                        "{what} instruction at {at:#x}: expected rva + {length} bytes to fit in 64 bits | received an overflow"
                    ),
                )
            })?;
            last_rva = last_rva.max(end);
            parsed.push((at, length, ins));
        }
        let mut callees = Vec::with_capacity(function.calls.len());
        for call in &function.calls {
            callees.push(parse_hex(&call.rva, &format!("{what} call rva"))?);
        }
        functions.push((rva, function.name, callees, parsed, last_rva));
    }
    // Image addresses are `image_base + rva`; without block data fall back to the last instruction.
    let image_size = functions
        .iter()
        .map(|f| f.4)
        .max()
        .unwrap_or(0)
        .max(extent_end.saturating_sub(image_base));
    // An export without a base has no linked addresses to mask.
    let image = if image_base == 0 {
        0..0
    } else {
        image_base..image_base.saturating_add(image_size)
    };
    let mut built: Vec<Function> = functions
        .into_iter()
        .map(|(rva, name, callees, parsed, _)| {
            let instructions: Vec<Instruction> = parsed
                .into_iter()
                .map(|(rva, length, ins)| Instruction {
                    rva,
                    length,
                    normalized: normalize_instruction(&ins.mnemonic, &ins.text, image.clone()),
                    bytes: ins.bytes,
                })
                .collect();
            let exact_hash = sha256_hex(
                instructions
                    .iter()
                    .map(|i| i.bytes.as_str())
                    .collect::<String>()
                    .as_bytes(),
            );
            let normalized_hash = sha256_hex(
                instructions
                    .iter()
                    .map(|i| i.normalized.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
                    .as_bytes(),
            );
            Function {
                name,
                rva,
                callees,
                instructions,
                exact_hash,
                normalized_hash,
            }
        })
        .collect();
    built.sort_by_key(|f| f.rva);
    if let Some(pair) = built.windows(2).find(|w| w[0].rva == w[1].rva) {
        return Err(Error::new(
            Code::FormatInvalid,
            format!(
                "{what} function rva {:#x}: expected unique | received {} and {}",
                pair[0].rva, pair[0].name, pair[1].name
            ),
        ));
    }
    Ok(FunctionExport {
        program: raw.program,
        image_base,
        functions: built,
    })
}

/// How a pair relates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FunctionVerdict {
    /// Same instruction bytes.
    Identical,
    /// Same instructions once flow targets and image addresses are masked.
    NormalizedIdentical,
    /// Normalized instructions differ.
    Changed,
}

/// Which stage paired the functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchMethod {
    ExactBytes,
    NormalizedBytes,
    CallGraph,
}

fn hex_u64<S: Serializer>(value: &u64, serializer: S) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("{value:#x}"))
}

fn hex_opt<S: Serializer>(
    value: &Option<u64>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_str(&format!("{value:#x}")),
        None => serializer.serialize_none(),
    }
}

/// A run of instructions on one side of a changed region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstructionRange {
    /// Index of the first instruction in the function's instruction list.
    pub first: usize,
    /// Instructions in the run; zero for a pure insertion on the other side.
    pub count: usize,
    /// RVA of the first instruction in the run, absent for an empty run past the end.
    #[serde(serialize_with = "hex_opt")]
    pub rva_start: Option<u64>,
    /// RVA just past the last instruction of the run.
    #[serde(serialize_with = "hex_opt")]
    pub rva_end: Option<u64>,
}

/// One changed region: the same position in A and in B.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangedRange {
    pub a: InstructionRange,
    pub b: InstructionRange,
}

/// A matched function pair.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionPair {
    pub name_a: String,
    pub name_b: String,
    #[serde(serialize_with = "hex_u64")]
    pub rva_a: u64,
    #[serde(serialize_with = "hex_u64")]
    pub rva_b: u64,
    pub verdict: FunctionVerdict,
    pub method: MatchMethod,
    /// Heuristic pair that needs review (call-graph position).
    pub candidate: bool,
    /// Instruction-sequence similarity for candidates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity: Option<f64>,
    pub instructions_a: usize,
    pub instructions_b: usize,
    pub changed_ranges: Vec<ChangedRange>,
}

/// A function no stage paired.
#[derive(Debug, Clone, Serialize)]
pub struct UnmatchedFunction {
    pub name: String,
    #[serde(serialize_with = "hex_u64")]
    pub rva: u64,
    pub instructions: usize,
}

/// Counts over a function comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FunctionSummary {
    pub functions_a: usize,
    pub functions_b: usize,
    pub identical: usize,
    pub normalized_identical: usize,
    pub changed: usize,
    pub candidates: usize,
    pub unmatched_a: usize,
    pub unmatched_b: usize,
}

/// The full function report.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionComparison {
    pub program_a: String,
    pub program_b: String,
    pub summary: FunctionSummary,
    pub pairs: Vec<FunctionPair>,
    pub unmatched_a: Vec<UnmatchedFunction>,
    pub unmatched_b: Vec<UnmatchedFunction>,
}

fn line_ids(function: &Function, table: &mut HashMap<String, u32>) -> Vec<u32> {
    function
        .instructions
        .iter()
        .map(|i| {
            let next = table.len() as u32;
            *table.entry(i.normalized.clone()).or_insert(next)
        })
        .collect()
}

/// Longest-common-subsequence table over the trimmed middle of two sequences.
fn lcs_table(a: &[u32], b: &[u32]) -> Option<Vec<Vec<u32>>> {
    if a.len().saturating_mul(b.len()) > MAX_DIFF_CELLS {
        return None;
    }
    let mut table = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            table[i][j] = if a[i] == b[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }
    Some(table)
}

/// Common prefix and suffix lengths (suffix limited to what the prefix left).
fn trim_common(a: &[u32], b: &[u32]) -> (usize, usize) {
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    (prefix, suffix)
}

/// Similarity `2 * common / (len a + len b)` of two sequences, or 0 when too large to score.
///
/// Example: `similarity(&[1, 2, 3], &[1, 9, 3])` is `2.0 / 3.0`.
pub fn similarity(a: &[u32], b: &[u32]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let (prefix, suffix) = trim_common(a, b);
    let (ma, mb) = (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix]);
    let Some(table) = lcs_table(ma, mb) else {
        return 0.0;
    };
    let common = prefix + suffix + table[0][0] as usize;
    2.0 * common as f64 / (a.len() + b.len()) as f64
}

/// Differing regions between two normalized instruction sequences.
fn changed_instruction_ranges(
    fa: &Function,
    fb: &Function,
    a: &[u32],
    b: &[u32],
) -> Vec<ChangedRange> {
    let (prefix, suffix) = trim_common(a, b);
    let (ma, mb) = (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix]);
    // Runs as (a_start, a_len, b_start, b_len) in whole-sequence indices.
    let mut runs: Vec<(usize, usize, usize, usize)> = Vec::new();
    match lcs_table(ma, mb) {
        None => runs.push((prefix, ma.len(), prefix, mb.len())),
        Some(table) => {
            let (mut i, mut j) = (0, 0);
            let mut open: Option<(usize, usize)> = None;
            while i < ma.len() || j < mb.len() {
                if i < ma.len() && j < mb.len() && ma[i] == mb[j] {
                    if let Some((si, sj)) = open.take() {
                        runs.push((prefix + si, i - si, prefix + sj, j - sj));
                    }
                    i += 1;
                    j += 1;
                    continue;
                }
                open.get_or_insert((i, j));
                if j >= mb.len() || (i < ma.len() && table[i + 1][j] >= table[i][j + 1]) {
                    i += 1;
                } else {
                    j += 1;
                }
            }
            if let Some((si, sj)) = open {
                runs.push((prefix + si, i - si, prefix + sj, j - sj));
            }
        }
    }
    let range = |f: &Function, first: usize, count: usize| {
        let ins = &f.instructions;
        InstructionRange {
            first,
            count,
            rva_start: ins.get(first).map(|i| i.rva),
            rva_end: if count > 0 {
                ins.get(first + count - 1)
                    .map(|i| i.rva.saturating_add(i.length))
            } else {
                ins.get(first).map(|i| i.rva)
            },
        }
    };
    runs.into_iter()
        .map(|(sa, la, sb, lb)| ChangedRange {
            a: range(fa, sa, la),
            b: range(fb, sb, lb),
        })
        .collect()
}

/// Pair functions whose `key` is shared by the same number of unmatched functions on each side.
fn pair_by_hash<'a>(
    a: &'a FunctionExport,
    b: &'a FunctionExport,
    matched_a: &BTreeSet<usize>,
    matched_b: &BTreeSet<usize>,
    key: impl Fn(&'a Function) -> &'a str,
) -> Vec<(usize, usize)> {
    let mut left: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut right: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, f) in a
        .functions
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched_a.contains(i))
    {
        left.entry(key(f)).or_default().push(i);
    }
    for (j, f) in b
        .functions
        .iter()
        .enumerate()
        .filter(|(j, _)| !matched_b.contains(j))
    {
        right.entry(key(f)).or_default().push(j);
    }
    let mut pairs = Vec::new();
    for (hash, xs) in &left {
        if let Some(ys) = right.get(hash)
            && xs.len() == ys.len()
        {
            pairs.extend(xs.iter().copied().zip(ys.iter().copied()));
        }
    }
    pairs
}

/// Reverse call graph: callee index to caller indices.
fn callers_of(export: &FunctionExport, index_of: &HashMap<u64, usize>) -> Vec<Vec<usize>> {
    let mut callers = vec![Vec::new(); export.functions.len()];
    for (caller, function) in export.functions.iter().enumerate() {
        for callee in &function.callees {
            if let Some(&target) = index_of.get(callee)
                && !callers[target].contains(&caller)
            {
                callers[target].push(caller);
            }
        }
    }
    callers
}

/// Forward call graph as indices (unknown callees dropped).
fn callees_of(export: &FunctionExport, index_of: &HashMap<u64, usize>) -> Vec<Vec<usize>> {
    export
        .functions
        .iter()
        .map(|f| {
            let mut targets: Vec<usize> = f
                .callees
                .iter()
                .filter_map(|c| index_of.get(c).copied())
                .collect();
            targets.sort_unstable();
            targets.dedup();
            targets
        })
        .collect()
}

/// Compare two exports function by function.
///
/// Example: `let report = compare_functions(&a, &b); assert_eq!(report.summary.unmatched_a, report.unmatched_a.len());`
pub fn compare_functions(a: &FunctionExport, b: &FunctionExport) -> FunctionComparison {
    let mut matched_a: BTreeSet<usize> = BTreeSet::new();
    let mut matched_b: BTreeSet<usize> = BTreeSet::new();
    let mut found: Vec<(usize, usize, MatchMethod, Option<f64>)> = Vec::new();
    for (method, by_exact) in [
        (MatchMethod::ExactBytes, true),
        (MatchMethod::NormalizedBytes, false),
    ] {
        let pairs = pair_by_hash(a, b, &matched_a, &matched_b, |f| {
            if by_exact {
                &f.exact_hash
            } else {
                &f.normalized_hash
            }
        });
        for (i, j) in pairs {
            matched_a.insert(i);
            matched_b.insert(j);
            found.push((i, j, method, None));
        }
    }
    let index_a: HashMap<u64, usize> = a
        .functions
        .iter()
        .enumerate()
        .map(|(i, f)| (f.rva, i))
        .collect();
    let index_b: HashMap<u64, usize> = b
        .functions
        .iter()
        .enumerate()
        .map(|(i, f)| (f.rva, i))
        .collect();
    let (calls_a, calls_b) = (callees_of(a, &index_a), callees_of(b, &index_b));
    let (callers_a, callers_b) = (callers_of(a, &index_a), callers_of(b, &index_b));
    let mut ids: HashMap<String, u32> = HashMap::new();
    let lines_a: Vec<Vec<u32>> = a.functions.iter().map(|f| line_ids(f, &mut ids)).collect();
    let lines_b: Vec<Vec<u32>> = b.functions.iter().map(|f| line_ids(f, &mut ids)).collect();
    loop {
        // Anchors: matched pairs whose unmatched neighbors can pair across.
        let mut votes: BTreeMap<(usize, usize), usize> = BTreeMap::new();
        for &(x, y, _, _) in &found {
            for (na, nb) in [(&calls_a[x], &calls_b[y]), (&callers_a[x], &callers_b[y])] {
                for &i in na.iter().filter(|i| !matched_a.contains(i)) {
                    for &j in nb.iter().filter(|j| !matched_b.contains(j)) {
                        *votes.entry((i, j)).or_default() += 1;
                    }
                }
            }
        }
        // Entry points (nothing in the module calls them) pair with each other without an anchor.
        for i in
            (0..a.functions.len()).filter(|i| callers_a[*i].is_empty() && !matched_a.contains(i))
        {
            for j in (0..b.functions.len())
                .filter(|j| callers_b[*j].is_empty() && !matched_b.contains(j))
            {
                votes.entry((i, j)).or_default();
            }
        }
        let mut scored: Vec<(usize, f64, usize, usize)> = votes
            .into_iter()
            .filter_map(|((i, j), n)| {
                let score = similarity(&lines_a[i], &lines_b[j]);
                (score >= MIN_CANDIDATE_SIMILARITY).then_some((n, score, i, j))
            })
            .collect();
        scored.sort_by(|x, y| {
            y.0.cmp(&x.0)
                .then(y.1.total_cmp(&x.1))
                .then((x.2, x.3).cmp(&(y.2, y.3)))
        });
        let mut progressed = false;
        for (_, score, i, j) in scored {
            if matched_a.contains(&i) || matched_b.contains(&j) {
                continue;
            }
            matched_a.insert(i);
            matched_b.insert(j);
            found.push((i, j, MatchMethod::CallGraph, Some(score)));
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
    found.sort_by_key(|&(i, ..)| a.functions[i].rva);
    let mut report = FunctionComparison {
        program_a: a.program.clone(),
        program_b: b.program.clone(),
        summary: FunctionSummary {
            functions_a: a.functions.len(),
            functions_b: b.functions.len(),
            ..FunctionSummary::default()
        },
        pairs: Vec::new(),
        unmatched_a: Vec::new(),
        unmatched_b: Vec::new(),
    };
    for (i, j, method, score) in found {
        let (fa, fb) = (&a.functions[i], &b.functions[j]);
        let verdict = if fa.exact_hash == fb.exact_hash {
            FunctionVerdict::Identical
        } else if fa.normalized_hash == fb.normalized_hash {
            FunctionVerdict::NormalizedIdentical
        } else {
            FunctionVerdict::Changed
        };
        let changed_ranges = if verdict == FunctionVerdict::Changed {
            changed_instruction_ranges(fa, fb, &lines_a[i], &lines_b[j])
        } else {
            Vec::new()
        };
        match verdict {
            FunctionVerdict::Identical => report.summary.identical += 1,
            FunctionVerdict::NormalizedIdentical => report.summary.normalized_identical += 1,
            FunctionVerdict::Changed => report.summary.changed += 1,
        }
        let candidate = method == MatchMethod::CallGraph;
        report.summary.candidates += usize::from(candidate);
        report.pairs.push(FunctionPair {
            name_a: fa.name.clone(),
            name_b: fb.name.clone(),
            rva_a: fa.rva,
            rva_b: fb.rva,
            verdict,
            method,
            candidate,
            similarity: score,
            instructions_a: fa.instructions.len(),
            instructions_b: fb.instructions.len(),
            changed_ranges,
        });
    }
    let leftovers =
        |export: &FunctionExport, matched: &BTreeSet<usize>| -> Vec<UnmatchedFunction> {
            export
                .functions
                .iter()
                .enumerate()
                .filter(|(i, _)| !matched.contains(i))
                .map(|(_, f)| UnmatchedFunction {
                    name: f.name.clone(),
                    rva: f.rva,
                    instructions: f.instructions.len(),
                })
                .collect()
        };
    report.unmatched_a = leftovers(a, &matched_a);
    report.unmatched_b = leftovers(b, &matched_b);
    report.summary.unmatched_a = report.unmatched_a.len();
    report.summary.unmatched_b = report.unmatched_b.len();
    report
}

/// Hand-written export fixtures for tests: a named fake of Ghidra's `ExportFirmware` output.
#[cfg(test)]
pub(crate) mod fixture {
    use serde_json::{Value, json};

    /// One instruction: its bytes and Ghidra text; the mnemonic is the text's first word.
    pub fn ins(rva: u64, bytes: &str, text: &str) -> Value {
        json!({"rva": format!("{rva:#x}"), "bytes": bytes, "mnemonic": text.split(' ').next().unwrap(), "text": text})
    }

    /// A function with its instructions and the RVAs it calls.
    pub fn function(name: &str, rva: u64, calls: &[u64], instructions: Vec<Value>) -> Value {
        json!({
            "name": name, "rva": format!("{rva:#x}"),
            "calls": calls.iter().map(|c| json!({"rva": format!("{c:#x}")})).collect::<Vec<_>>(),
            "instructions": instructions,
        })
    }

    /// A whole export linked at `base`, 0x1000 bytes long.
    pub fn export(program: &str, base: u64, functions: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "program": program, "image_base": format!("{base:#010x}"),
            "blocks": [{"name": ".text", "start": format!("{base:08x}"), "size": 0x1000}],
            "functions": functions,
        }))
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{export, function, ins};
    use super::*;

    fn parse(bytes: &[u8]) -> FunctionExport {
        parse_export(bytes, "fixture.json").expect("fixture parses")
    }

    /// `callee(base + rva)` linked at `base`: flow bytes and printed target change with the base.
    fn caller(rva: u64, base: u64, callee: u64) -> Vec<serde_json::Value> {
        vec![
            ins(rva, "55", "PUSH EBP"),
            ins(
                rva + 1,
                "e800000000",
                &format!("CALL {:#010x}", base + callee),
            ),
            ins(rva + 6, "c3", "RET"),
        ]
    }

    #[test]
    fn exact_bytes_pair_as_identical() {
        let body = || vec![ins(0x10, "55", "PUSH EBP"), ins(0x11, "c3", "RET")];
        let a = parse(&export(
            "m",
            0x40_0000,
            vec![function("f", 0x10, &[], body())],
        ));
        let b = parse(&export(
            "m",
            0x40_0000,
            vec![function("g", 0x10, &[], body())],
        ));
        let report = compare_functions(&a, &b);
        assert_eq!(report.summary.identical, 1);
        assert_eq!(report.pairs[0].method, MatchMethod::ExactBytes);
        assert!(!report.pairs[0].candidate);
    }

    #[test]
    fn rebased_function_is_normalized_identical() {
        let a = parse(&export(
            "m",
            0x40_0000,
            vec![
                function("f", 0x10, &[0x80], caller(0x10, 0x40_0000, 0x80)),
                function("t", 0x80, &[], vec![ins(0x80, "c3", "RET")]),
            ],
        ));
        let b = parse(&export(
            "m",
            0x50_0000,
            vec![
                function("f", 0x10, &[0x80], {
                    let mut v = caller(0x10, 0x50_0000, 0x80);
                    v[1] = ins(0x11, "e811111111", "CALL 0x00500080");
                    v
                }),
                function("t", 0x80, &[], vec![ins(0x80, "c3", "RET")]),
            ],
        ));
        let report = compare_functions(&a, &b);
        let pair = report.pairs.iter().find(|p| p.rva_a == 0x10).unwrap();
        assert_eq!(
            pair.verdict,
            FunctionVerdict::NormalizedIdentical,
            "{pair:?}"
        );
        assert_eq!(pair.method, MatchMethod::NormalizedBytes);
        assert_eq!(report.summary.identical, 1, "the RET stub matches exactly");
    }

    #[test]
    fn image_address_operands_are_masked_but_plain_immediates_stay() {
        let image = 0x40_0000..0x40_1000;
        assert_eq!(
            normalize_instruction("MOV", "MOV EAX,dword ptr [0x00400123]", image.clone()),
            "MOV EAX,dword ptr [IMAGE_ADDRESS]"
        );
        assert_eq!(
            normalize_instruction("MOV", "MOV EAX,0x10", image.clone()),
            "MOV EAX,0x10"
        );
        assert_eq!(
            normalize_instruction("JMP", "JMP LAB_00401234", image.clone()),
            "JMP FLOW_TARGET"
        );
        assert_eq!(
            normalize_instruction("CALL", "CALL EAX", image.clone()),
            "CALL EAX"
        );
        assert_eq!(
            normalize_instruction("LEA", "LEA RAX,[DAT_0040abcd]", image),
            "LEA RAX,[DAT_ADDRESS]"
        );
    }

    #[test]
    fn changed_function_reports_the_differing_instruction_range() {
        let make = |imm: &str, bytes: &str| {
            vec![
                ins(0x10, "55", "PUSH EBP"),
                ins(0x11, "89e5", "MOV EBP,ESP"),
                ins(0x13, bytes, &format!("MOV EAX,{imm}")),
                ins(0x18, "31c0", "XOR EAX,EAX"),
                ins(0x1a, "c3", "RET"),
            ]
        };
        let a = parse(&export(
            "m",
            0x40_0000,
            vec![function("f", 0x10, &[], make("0x1", "b801000000"))],
        ));
        let b = parse(&export(
            "m",
            0x40_0000,
            vec![function("f", 0x10, &[], make("0x2", "b802000000"))],
        ));
        let report = compare_functions(&a, &b);
        let pair = &report.pairs[0];
        assert_eq!(pair.verdict, FunctionVerdict::Changed);
        assert_eq!(pair.changed_ranges.len(), 1);
        let range = &pair.changed_ranges[0];
        assert_eq!((range.a.first, range.a.count), (2, 1));
        assert_eq!(
            (range.a.rva_start, range.a.rva_end),
            (Some(0x13), Some(0x18))
        );
        assert_eq!((range.b.first, range.b.count), (2, 1));
    }

    #[test]
    fn changed_entry_points_pair_as_candidates_without_anchors() {
        let a = parse(&export(
            "m",
            0x40_0000,
            vec![function(
                "f",
                0x10,
                &[],
                vec![
                    ins(0x10, "55", "PUSH EBP"),
                    ins(0x11, "90", "NOP"),
                    ins(0x12, "c3", "RET"),
                ],
            )],
        ));
        let b = parse(&export(
            "m",
            0x40_0000,
            vec![function(
                "f",
                0x10,
                &[],
                vec![
                    ins(0x10, "55", "PUSH EBP"),
                    ins(0x11, "f4", "HLT"),
                    ins(0x12, "c3", "RET"),
                ],
            )],
        ));
        let pair = &compare_functions(&a, &b).pairs[0];
        assert_eq!(
            (pair.method, pair.candidate),
            (MatchMethod::CallGraph, true)
        );
        assert_eq!(pair.verdict, FunctionVerdict::Changed);
    }

    #[test]
    fn insertion_is_an_empty_range_on_the_other_side() {
        let a_ins = vec![ins(0, "55", "PUSH EBP"), ins(1, "c3", "RET")];
        let b_ins = vec![
            ins(0, "55", "PUSH EBP"),
            ins(1, "90", "NOP"),
            ins(2, "c3", "RET"),
        ];
        let a = parse(&export("m", 0x40_0000, vec![function("f", 0, &[], a_ins)]));
        let b = parse(&export("m", 0x40_0000, vec![function("f", 0, &[], b_ins)]));
        let range = &compare_functions(&a, &b).pairs[0].changed_ranges[0];
        assert_eq!((range.a.first, range.a.count), (1, 0));
        assert_eq!((range.b.first, range.b.count), (1, 1));
    }

    #[test]
    fn call_graph_pairs_a_changed_callee_as_a_candidate() {
        let helper = |tail: &str, tail_bytes: &str| {
            let mut body = vec![
                ins(0x80, "55", "PUSH EBP"),
                ins(0x81, "89e5", "MOV EBP,ESP"),
                ins(0x83, "8b4508", "MOV EAX,dword ptr [EBP + 0x8]"),
                ins(0x86, "83c001", "ADD EAX,0x1"),
                ins(0x89, "5d", "POP EBP"),
            ];
            body.push(ins(0x8a, tail_bytes, tail));
            body
        };
        let a = parse(&export(
            "m",
            0x40_0000,
            vec![
                function("main", 0x10, &[0x80], caller(0x10, 0x40_0000, 0x80)),
                function("old_helper", 0x80, &[], helper("RET", "c3")),
            ],
        ));
        let b = parse(&export(
            "m",
            0x40_0000,
            vec![
                function("main", 0x10, &[0x80], caller(0x10, 0x40_0000, 0x80)),
                function("new_helper", 0x80, &[], helper("RET 0x4", "c20400")),
            ],
        ));
        let report = compare_functions(&a, &b);
        assert_eq!(report.summary.identical, 1);
        let pair = report
            .pairs
            .iter()
            .find(|p| p.method == MatchMethod::CallGraph)
            .expect("call-graph pair");
        assert!(pair.candidate);
        assert_eq!(pair.verdict, FunctionVerdict::Changed);
        assert!(pair.similarity.unwrap() >= MIN_CANDIDATE_SIMILARITY);
        assert_eq!(report.summary.candidates, 1);
    }

    #[test]
    fn dissimilar_neighbor_stays_unmatched() {
        let a = parse(&export(
            "m",
            0x40_0000,
            vec![
                function("main", 0x10, &[0x80], caller(0x10, 0x40_0000, 0x80)),
                function(
                    "only_a",
                    0x80,
                    &[],
                    vec![ins(0x80, "90", "NOP"), ins(0x81, "c3", "RET")],
                ),
            ],
        ));
        let b = parse(&export(
            "m",
            0x40_0000,
            vec![
                function("main", 0x10, &[0x80], caller(0x10, 0x40_0000, 0x80)),
                function(
                    "only_b",
                    0x80,
                    &[],
                    vec![ins(0x80, "f4", "HLT"), ins(0x81, "cc", "INT3")],
                ),
            ],
        ));
        let report = compare_functions(&a, &b);
        assert_eq!((report.unmatched_a.len(), report.unmatched_b.len()), (1, 1));
        assert_eq!(report.unmatched_a[0].name, "only_a");
        assert_eq!(report.summary.candidates, 0);
    }

    #[test]
    fn ambiguous_identical_bytes_are_not_paired_by_hash() {
        let stub = |rva| vec![ins(rva, "c3", "RET")];
        let a = parse(&export(
            "m",
            0x40_0000,
            vec![
                function("s1", 0x10, &[], stub(0x10)),
                function("s2", 0x20, &[], stub(0x20)),
            ],
        ));
        let b = parse(&export(
            "m",
            0x40_0000,
            vec![function("s", 0x10, &[], stub(0x10))],
        ));
        let report = compare_functions(&a, &b);
        // Two stubs against one: no hash stage guesses, the call-graph stage pairs one as a candidate.
        assert_eq!(report.pairs.len(), 1);
        assert_eq!(report.pairs[0].method, MatchMethod::CallGraph);
        assert!(report.pairs[0].candidate);
        assert_eq!(report.unmatched_a.len(), 1);
        assert_eq!(report.unmatched_a[0].name, "s2");
    }

    #[test]
    fn export_without_instructions_names_the_function() {
        let json =
            br#"{"program":"m","image_base":"0x400000","functions":[{"name":"f","rva":"0x10"}]}"#;
        let error = parse_export(json, "old.json").expect_err("instructions are required");
        assert_eq!(error.code, Code::FormatInvalid);
        assert!(
            error.message.contains("old.json function f at 0x10"),
            "{error}"
        );
        assert!(error.message.contains("instructions"), "{error}");
    }

    #[test]
    fn non_export_json_is_rejected_with_the_expected_shape() {
        let error = parse_export(b"[1,2]", "x.json").expect_err("array is not an export");
        assert!(
            error
                .message
                .contains("expected a bme tools analyze JSON export"),
            "{error}"
        );
        let error = parse_export(b"{}", "x.json").expect_err("functions are required");
        assert!(error.message.contains("\"functions\" array"), "{error}");
    }

    #[test]
    fn duplicate_rva_is_rejected() {
        let f = |name| function(name, 0x10, &[], vec![ins(0x10, "c3", "RET")]);
        let error = parse_export(&export("m", 0x40_0000, vec![f("a"), f("b")]), "d.json")
            .expect_err("duplicate rva");
        assert!(error.message.contains("expected unique"), "{error}");
    }

    #[test]
    fn similarity_scores_shared_subsequence() {
        assert!((similarity(&[1, 2, 3], &[1, 9, 3]) - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(similarity(&[], &[]), 1.0);
        assert_eq!(similarity(&[1], &[2]), 0.0);
    }

    fn parse_error(instructions: Vec<serde_json::Value>) -> String {
        let json = export("m", 0x40_0000, vec![function("f", 0x10, &[], instructions)]);
        parse_export(&json, "fixture.json")
            .expect_err("expected the export to be rejected")
            .to_string()
    }

    #[test]
    fn instruction_rva_overflow_names_the_rva() {
        let message = parse_error(vec![ins(0xffff_ffff_ffff_ffff, "5555", "PUSH EBP")]);
        assert!(
            message.contains("0xffffffffffffffff") && message.contains("fit in 64 bits"),
            "(parse_export): expected an rva overflow error naming the rva | received {message}"
        );
    }

    #[test]
    fn odd_or_non_hex_instruction_bytes_name_rva_and_value() {
        for bad in ["5", "zz", "55 c3"] {
            let message = parse_error(vec![ins(0x10, bad, "PUSH EBP")]);
            assert!(
                message.contains("0x10") && message.contains(&format!("{bad:?}")),
                "(parse_export {bad:?}): expected an error naming rva and bytes | received {message}"
            );
        }
    }

    #[test]
    fn hex_case_does_not_change_the_exact_hash() {
        let body = |bytes: &str| vec![ins(0x10, bytes, "MOV EAX,0xAB")];
        let build = |bytes: &str| {
            parse(&export(
                "m",
                0x40_0000,
                vec![function("f", 0x10, &[], body(bytes))],
            ))
        };
        assert_eq!(
            build("B8AB000000").functions[0].exact_hash,
            build("b8ab000000").functions[0].exact_hash
        );
    }
}
