//! A minimal AML namespace walker: names, kinds and method body hashes.
//!
//! This is not an interpreter. It reads the table header, then walks the
//! namespace-defining terms (`Scope`, `Device`, `Method`, `Processor`,
//! `PowerResource`, `ThermalZone`, `Name`, `OperationRegion`, `Field` and a few
//! declarations) and skips every body by its PkgLength. Method bodies are
//! never decoded; each is hashed as stored. A term the walker cannot size
//! (an expression where a constant is expected, an unknown opcode) ends the
//! walk of that scope with a warning that names the table offset.
//!
//! Paths use the raw four-character NameSeg as stored (`\_SB_.PCI0`), so a
//! name is never ambiguous with its padded form.
//!
//! Example: `let space = walk_table(&dsdt)?; let sios = space.find("\\_SB_.PCI0.LPCB.SIO1.SIOS");`

use crate::error::{Code, Error, Result};
use crate::util::{le32, sha256_hex, slice};
use serde::Serialize;

/// Length of the common ACPI table header.
pub const HEADER_LEN: usize = 36;
/// Deepest scope nesting the walker follows.
const MAX_DEPTH: usize = 64;

/// The ACPI table header fields comparison reports use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TableHeader {
    pub signature: String,
    pub length: u32,
    pub revision: u8,
    pub checksum_ok: bool,
    pub oem_id: String,
    pub oem_table_id: String,
    pub oem_revision: u32,
}

fn ascii_field(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() {
                char::from(*b)
            } else {
                ' '
            }
        })
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// Parse the 36-byte header of an ACPI table whose declared length fits `table`.
///
/// Example: `let header = parse_header(&dsdt)?; assert_eq!(header.signature, "DSDT");`
pub fn parse_header(table: &[u8]) -> Result<TableHeader> {
    let head = slice(table, 0, HEADER_LEN, "ACPI table header")?;
    let length = le32(table, 4, "ACPI table length")?;
    if (length as usize) < HEADER_LEN || length as usize > table.len() {
        return Err(Error::new(
            Code::FormatInvalid,
            format!(
                "ACPI table length: expected {HEADER_LEN}..={} | received {length}",
                table.len()
            ),
        ));
    }
    let checksum_ok = table[..length as usize]
        .iter()
        .fold(0u8, |sum, b| sum.wrapping_add(*b))
        == 0;
    Ok(TableHeader {
        signature: ascii_field(&head[0..4]),
        length,
        revision: head[8],
        checksum_ok,
        oem_id: ascii_field(&head[10..16]),
        oem_table_id: ascii_field(&head[16..24]),
        oem_revision: le32(table, 24, "ACPI OEM revision")?,
    })
}

/// What kind of namespace term an object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectKind {
    Scope,
    Device,
    Method,
    Processor,
    PowerResource,
    ThermalZone,
    Name,
    OperationRegion,
    Field,
    IndexField,
    BankField,
    Mutex,
    Event,
    Alias,
    External,
    DataRegion,
    /// `CreateBitField`, `CreateByteField`, ... and `CreateField`.
    BufferField,
}

impl ObjectKind {
    /// Containers whose children are listed separately; their own bytes are not hashed.
    pub fn is_container(self) -> bool {
        matches!(
            self,
            ObjectKind::Scope
                | ObjectKind::Device
                | ObjectKind::Processor
                | ObjectKind::PowerResource
                | ObjectKind::ThermalZone
        )
    }
}

/// One namespace object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AmlObject {
    /// Full path, e.g. `\_SB_.PCI0.LPCB.SIO1.SIOS`; fields add `#n` after their region.
    pub path: String,
    pub kind: ObjectKind,
    /// Offset of the term in the table.
    pub offset: usize,
    /// Length of the whole term in bytes.
    pub length: usize,
    /// Method: argument count from the flags byte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<u8>,
    /// SHA-256 of a method's body (after its flags) or of a non-container term's bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// The objects of one table plus what the walker could not read.
#[derive(Debug, Clone, Default)]
pub struct Namespace {
    pub objects: Vec<AmlObject>,
    pub warnings: Vec<String>,
}

impl Namespace {
    /// The first object at `path`.
    ///
    /// Example: `space.find("\\_S3_")` is the sleep-state package when the table defines one.
    pub fn find(&self, path: &str) -> Option<&AmlObject> {
        self.objects.iter().find(|o| o.path == path)
    }
}

/// A parsed NameString.
#[derive(Debug)]
struct NameString {
    /// Leading `\`.
    root: bool,
    /// Leading `^` count.
    parents: usize,
    segments: Vec<String>,
}

type Segments = Vec<String>;

struct Walker<'a> {
    table: &'a [u8],
    objects: Vec<AmlObject>,
    warnings: Vec<String>,
    /// Fields seen per region path, for `#n` suffixes.
    field_counts: std::collections::BTreeMap<String, usize>,
}

fn is_name_lead(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte == b'_'
}

fn render(segments: &[String]) -> String {
    format!("\\{}", segments.join("."))
}

/// Cursor failure inside a scope: why and where.
struct Stop(String);

impl<'a> Walker<'a> {
    fn byte(&self, at: usize) -> std::result::Result<u8, Stop> {
        self.table.get(at).copied().ok_or_else(|| {
            Stop(format!(
                "offset {at:#x}: expected a byte | received end of table"
            ))
        })
    }

    /// PkgLength at `at`: (length including its own bytes, bytes used by the encoding).
    fn pkg_length(&self, at: usize) -> std::result::Result<(usize, usize), Stop> {
        let lead = self.byte(at)?;
        let follow = usize::from(lead >> 6);
        let mut length = if follow == 0 {
            usize::from(lead & 0x3F)
        } else {
            usize::from(lead & 0x0F)
        };
        for i in 0..follow {
            length |= usize::from(self.byte(at + 1 + i)?) << (4 + 8 * i);
        }
        if length < 1 + follow {
            return Err(Stop(format!(
                "offset {at:#x}: PkgLength expected >= {} | received {length}",
                1 + follow
            )));
        }
        Ok((length, 1 + follow))
    }

    /// Parse a NameString at `at`; returns it and the offset after it.
    fn name_string(&self, mut at: usize) -> std::result::Result<(NameString, usize), Stop> {
        let start = at;
        let mut name = NameString {
            root: false,
            parents: 0,
            segments: Vec::new(),
        };
        if self.byte(at)? == b'\\' {
            name.root = true;
            at += 1;
        } else {
            while self.byte(at)? == b'^' {
                name.parents += 1;
                at += 1;
            }
        }
        let count = match self.byte(at)? {
            0x00 => {
                return Ok((name, at + 1));
            }
            0x2E => {
                at += 1;
                2
            }
            0x2F => {
                let count = usize::from(self.byte(at + 1)?);
                at += 2;
                count
            }
            _ => 1,
        };
        for _ in 0..count {
            let seg = self.table.get(at..at + 4).ok_or_else(|| {
                Stop(format!(
                    "offset {at:#x}: NameSeg expected 4 bytes | received end of table"
                ))
            })?;
            if !is_name_lead(seg[0])
                || !seg[1..]
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
            {
                return Err(Stop(format!(
                    "offset {at:#x}: NameSeg expected [A-Z_][A-Z0-9_]{{3}} | received {seg:02x?} (NameString began at {start:#x})"
                )));
            }
            name.segments
                .push(String::from_utf8_lossy(seg).into_owned());
            at += 4;
        }
        Ok((name, at))
    }

    fn resolve(&self, scope: &Segments, name: &NameString) -> Segments {
        let mut base: Segments = if name.root {
            Vec::new()
        } else {
            scope[..scope.len().saturating_sub(name.parents)].to_vec()
        };
        base.extend(name.segments.iter().cloned());
        base
    }

    /// Offset after a data object or constant term argument.
    fn skip_data(&self, at: usize) -> std::result::Result<usize, Stop> {
        let op = self.byte(at)?;
        match op {
            0x00 | 0x01 | 0xFF => Ok(at + 1),
            0x0A => Ok(at + 2),
            0x0B => Ok(at + 3),
            0x0C => Ok(at + 5),
            0x0E => Ok(at + 9),
            0x0D => {
                let rest = self.table.get(at + 1..).unwrap_or_default();
                let nul = rest.iter().position(|b| *b == 0).ok_or_else(|| {
                    Stop(format!(
                        "offset {at:#x}: String expected a NUL terminator | received none"
                    ))
                })?;
                Ok(at + 1 + nul + 1)
            }
            0x11..=0x13 => {
                let (length, _) = self.pkg_length(at + 1)?;
                Ok(at + 1 + length)
            }
            0x5B if matches!(self.byte(at + 1)?, 0x30 | 0x31) => Ok(at + 2),
            0x60..=0x6E => Ok(at + 1),
            b'\\' | b'^' | 0x2E | 0x2F => Ok(self.name_string(at)?.1),
            b if is_name_lead(b) => Ok(self.name_string(at)?.1),
            _ => Err(Stop(format!(
                "offset {at:#x}: expected a constant, package, buffer or name | received opcode {op:#04x}"
            ))),
        }
    }

    fn record(
        &mut self,
        path: String,
        kind: ObjectKind,
        offset: usize,
        end: usize,
        args: Option<u8>,
        hash_from: Option<usize>,
    ) -> std::result::Result<(), Stop> {
        let from = hash_from.unwrap_or(offset);
        let sha256 = if kind.is_container() {
            None
        } else {
            let body = self.table.get(from..end).ok_or_else(|| {
                Stop(format!(
                    "offset {offset:#x}: {kind:?} body expected to start before its end {end:#x} | received start {from:#x}"
                ))
            })?;
            Some(sha256_hex(body))
        };
        self.objects.push(AmlObject {
            path,
            kind,
            offset,
            length: end - offset,
            args,
            sha256,
        });
        Ok(())
    }

    /// Walk terms in `[at, end)` under `scope`.
    fn term_list(&mut self, mut at: usize, end: usize, scope: &Segments, depth: usize) {
        if depth > MAX_DEPTH {
            self.warnings.push(format!(
                "offset {at:#x}: scope nesting expected <= {MAX_DEPTH} | received more"
            ));
            return;
        }
        while at < end {
            match self.term(at, end, scope, depth) {
                Ok(next) if next > at => at = next,
                Ok(_) => return,
                Err(Stop(why)) => {
                    self.warnings.push(format!(
                        "{} ({why}); rest of the scope is not listed",
                        render(scope)
                    ));
                    return;
                }
            }
        }
    }

    /// One namespace term at `at`; returns the offset after it.
    fn term(
        &mut self,
        at: usize,
        end: usize,
        scope: &Segments,
        depth: usize,
    ) -> std::result::Result<usize, Stop> {
        let op = self.byte(at)?;
        let (ext, body) = if op == 0x5B {
            (Some(self.byte(at + 1)?), at + 2)
        } else {
            (None, at + 1)
        };
        // A container: PkgLength, NameString, fixed bytes, then terms.
        let container = |walker: &mut Walker<'a>, kind: ObjectKind, fixed: usize| {
            let (length, used) = walker.pkg_length(body)?;
            let term_end = (body + length).min(end);
            let (name, after) = walker.name_string(body + used)?;
            let needed = after + fixed - body;
            if length < needed {
                return Err(Stop(format!(
                    "offset {at:#x}: {kind:?} PkgLength expected >= {needed} | received {length}"
                )));
            }
            let path = walker.resolve(scope, &name);
            walker.record(render(&path), kind, at, term_end, None, None)?;
            walker.term_list((after + fixed).min(term_end), term_end, &path, depth + 1);
            Ok(term_end)
        };
        match (op, ext) {
            (0x10, None) => container(self, ObjectKind::Scope, 0),
            (0x5B, Some(0x82)) => container(self, ObjectKind::Device, 0),
            (0x5B, Some(0x83)) => container(self, ObjectKind::Processor, 6),
            (0x5B, Some(0x84)) => container(self, ObjectKind::PowerResource, 3),
            (0x5B, Some(0x85)) => container(self, ObjectKind::ThermalZone, 0),
            (0x14, None) => {
                let (length, used) = self.pkg_length(body)?;
                let term_end = (body + length).min(end);
                let (name, after) = self.name_string(body + used)?;
                let flags = self.byte(after)?;
                let needed = after + 1 - body;
                if length < needed {
                    return Err(Stop(format!(
                        "offset {at:#x}: Method PkgLength expected >= {needed} | received {length}"
                    )));
                }
                let path = render(&self.resolve(scope, &name));
                self.record(
                    path,
                    ObjectKind::Method,
                    at,
                    term_end,
                    Some(flags & 7),
                    Some(after + 1),
                )?;
                Ok(term_end)
            }
            (0x08, None) => {
                let (name, after) = self.name_string(body)?;
                let term_end = self.skip_data(after)?;
                let path = render(&self.resolve(scope, &name));
                self.record(path, ObjectKind::Name, at, term_end, None, None)?;
                Ok(term_end)
            }
            (0x5B, Some(0x80)) => {
                let (name, after) = self.name_string(body)?;
                self.byte(after)?;
                let offset_end = self.skip_data(after + 1)?;
                let term_end = self.skip_data(offset_end)?;
                let path = render(&self.resolve(scope, &name));
                self.record(path, ObjectKind::OperationRegion, at, term_end, None, None)?;
                Ok(term_end)
            }
            (0x5B, Some(0x81 | 0x86 | 0x87)) => {
                let kind = match ext {
                    Some(0x81) => ObjectKind::Field,
                    Some(0x86) => ObjectKind::IndexField,
                    _ => ObjectKind::BankField,
                };
                let (length, used) = self.pkg_length(body)?;
                let term_end = (body + length).min(end);
                let (name, _) = self.name_string(body + used)?;
                let region = render(&self.resolve(scope, &name));
                let count = self.field_counts.entry(region.clone()).or_default();
                *count += 1;
                let path = format!("{region}#{count}");
                self.record(path, kind, at, term_end, None, None)?;
                Ok(term_end)
            }
            (0x5B, Some(0x01)) => {
                let (name, after) = self.name_string(body)?;
                self.byte(after)?;
                let path = render(&self.resolve(scope, &name));
                self.record(path, ObjectKind::Mutex, at, after + 1, None, None)?;
                Ok(after + 1)
            }
            (0x5B, Some(0x02)) => {
                let (name, after) = self.name_string(body)?;
                let path = render(&self.resolve(scope, &name));
                self.record(path, ObjectKind::Event, at, after, None, None)?;
                Ok(after)
            }
            (0x5B, Some(0x88)) => {
                let (name, after) = self.name_string(body)?;
                let mut term_end = after;
                for _ in 0..3 {
                    term_end = self.skip_data(term_end)?;
                }
                let path = render(&self.resolve(scope, &name));
                self.record(path, ObjectKind::DataRegion, at, term_end, None, None)?;
                Ok(term_end)
            }
            (0x8A..=0x8D | 0x8F, None) | (0x5B, Some(0x13)) => {
                // Source buffer, index (and bit count for CreateField), then the new name.
                let operands = if ext.is_some() { 3 } else { 2 };
                let mut next = body;
                for _ in 0..operands {
                    next = self.skip_data(next)?;
                }
                let (name, term_end) = self.name_string(next)?;
                let path = render(&self.resolve(scope, &name));
                self.record(path, ObjectKind::BufferField, at, term_end, None, None)?;
                Ok(term_end)
            }
            (0x06, None) => {
                let (_source, after) = self.name_string(body)?;
                let (alias, term_end) = self.name_string(after)?;
                let path = render(&self.resolve(scope, &alias));
                self.record(path, ObjectKind::Alias, at, term_end, None, None)?;
                Ok(term_end)
            }
            (0x15, None) => {
                let (name, after) = self.name_string(body)?;
                let term_end = after + 2;
                self.byte(term_end - 1)?;
                let path = render(&self.resolve(scope, &name));
                self.record(path, ObjectKind::External, at, term_end, None, None)?;
                Ok(term_end)
            }
            (0xA0..=0xA2, None) => {
                // Conditional definitions are decided at run time; skip them by length.
                let (length, _) = self.pkg_length(body)?;
                self.warnings.push(format!(
                    "{} (offset {at:#x}: conditional term {op:#04x} at scope level); not listed",
                    render(scope)
                ));
                Ok((body + length).min(end))
            }
            _ => Err(Stop(format!(
                "offset {at:#x}: expected a namespace term | received opcode {op:#04x}{}",
                ext.map(|e| format!(" {e:#04x}")).unwrap_or_default()
            ))),
        }
    }
}

/// Walk a complete ACPI table (DSDT or SSDT) and list its namespace objects.
///
/// Errors only when the header is invalid; unreadable terms become warnings.
///
/// Example: `let space = walk_table(&dsdt)?; println!("{} objects", space.objects.len());`
pub fn walk_table(table: &[u8]) -> Result<Namespace> {
    let header = parse_header(table)?;
    let end = header.length as usize;
    let mut walker = Walker {
        table: &table[..end],
        objects: Vec::new(),
        warnings: Vec::new(),
        field_counts: Default::default(),
    };
    walker.term_list(HEADER_LEN, end, &Vec::new(), 0);
    Ok(Namespace {
        objects: walker.objects,
        warnings: walker.warnings,
    })
}

/// Builders for AML test fixtures, shared by core and CLI tests.
pub mod fixture {
    use super::HEADER_LEN;

    /// PkgLength encoding of `body_len` (the encoding's own bytes are added).
    pub fn pkg_length(body_len: usize) -> Vec<u8> {
        let total1 = body_len + 1;
        if total1 < 0x40 {
            return vec![total1 as u8];
        }
        let total2 = body_len + 2;
        if total2 < 0x1000 {
            return vec![0x40 | (total2 & 0x0F) as u8, (total2 >> 4) as u8];
        }
        let total3 = body_len + 3;
        vec![
            0x80 | (total3 & 0x0F) as u8,
            ((total3 >> 4) & 0xFF) as u8,
            (total3 >> 12) as u8,
        ]
    }

    /// A NameString: 4-char segments joined as written (`\\_SB_.PCI0`, `^FOO_`, `ABCD`).
    pub fn name(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = text;
        if let Some(r) = rest.strip_prefix('\\') {
            out.push(b'\\');
            rest = r;
        }
        while let Some(r) = rest.strip_prefix('^') {
            out.push(b'^');
            rest = r;
        }
        let segments: Vec<&str> = rest.split('.').filter(|s| !s.is_empty()).collect();
        match segments.len() {
            0 => out.push(0),
            1 => {}
            2 => out.push(0x2E),
            n => out.extend([0x2F, n as u8]),
        }
        for segment in segments {
            assert_eq!(
                segment.len(),
                4,
                "NameSeg {segment:?}: expected 4 characters"
            );
            out.extend(segment.as_bytes());
        }
        out
    }

    fn container(prefix: &[u8], path: &str, fixed: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
        let mut inner = name(path);
        inner.extend(fixed);
        inner.extend(children.concat());
        let mut out = prefix.to_vec();
        out.extend(pkg_length(inner.len()));
        out.extend(inner);
        out
    }

    pub fn scope(path: &str, children: &[Vec<u8>]) -> Vec<u8> {
        container(&[0x10], path, &[], children)
    }

    pub fn device(path: &str, children: &[Vec<u8>]) -> Vec<u8> {
        container(&[0x5B, 0x82], path, &[], children)
    }

    pub fn processor(path: &str, children: &[Vec<u8>]) -> Vec<u8> {
        container(&[0x5B, 0x83], path, &[1, 0x10, 0x04, 0, 0, 6], children)
    }

    pub fn power_resource(path: &str, children: &[Vec<u8>]) -> Vec<u8> {
        container(&[0x5B, 0x84], path, &[0, 0, 0], children)
    }

    pub fn thermal_zone(path: &str, children: &[Vec<u8>]) -> Vec<u8> {
        container(&[0x5B, 0x85], path, &[], children)
    }

    /// `Method (path, args, NotSerialized) { body }` with an opaque body.
    pub fn method(path: &str, args: u8, body: &[u8]) -> Vec<u8> {
        let mut inner = name(path);
        inner.push(args);
        inner.extend(body);
        let mut out = vec![0x14];
        out.extend(pkg_length(inner.len()));
        out.extend(inner);
        out
    }

    /// `Name (path, Zero/One/Byte/Dword)`: a byte constant.
    pub fn name_byte(path: &str, value: u8) -> Vec<u8> {
        let mut out = vec![0x08];
        out.extend(name(path));
        out.extend([0x0A, value]);
        out
    }

    /// `Name (path, Package () { bytes })`.
    pub fn name_package(path: &str, values: &[u8]) -> Vec<u8> {
        let mut inner = vec![values.len() as u8];
        for v in values {
            inner.extend([0x0A, *v]);
        }
        let mut out = vec![0x08];
        out.extend(name(path));
        out.push(0x12);
        out.extend(pkg_length(inner.len()));
        out.extend(inner);
        out
    }

    /// `OperationRegion (path, SystemIO, offset, length)`.
    pub fn operation_region(path: &str, offset: u16, length: u8) -> Vec<u8> {
        let mut out = vec![0x5B, 0x80];
        out.extend(name(path));
        out.extend([1, 0x0B]);
        out.extend(offset.to_le_bytes());
        out.extend([0x0A, length]);
        out
    }

    /// `Field (region, ByteAcc, NoLock, Preserve) { ... }` with an opaque field list.
    pub fn field(region: &str, units: &[u8]) -> Vec<u8> {
        let mut inner = name(region);
        inner.push(0x01);
        inner.extend(units);
        let mut out = vec![0x5B, 0x81];
        out.extend(pkg_length(inner.len()));
        out.extend(inner);
        out
    }

    /// A complete table: header, then `aml`, with a correct checksum.
    pub fn table(signature: &str, oem_table_id: &str, aml: &[u8]) -> Vec<u8> {
        let mut out = signature.as_bytes().to_vec();
        out.extend(((HEADER_LEN + aml.len()) as u32).to_le_bytes());
        out.push(2);
        out.push(0);
        let mut oem = b"BMEOEM".to_vec();
        oem.resize(6, b' ');
        out.extend(oem);
        let mut id = oem_table_id.as_bytes().to_vec();
        id.resize(8, b' ');
        out.extend(id);
        out.extend(1u32.to_le_bytes());
        out.extend(b"INTL");
        out.extend(0x2025_0101u32.to_le_bytes());
        out.extend(aml);
        let sum = out.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        out[9] = sum.wrapping_neg();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    fn paths(space: &Namespace) -> Vec<(&str, ObjectKind)> {
        space
            .objects
            .iter()
            .map(|o| (o.path.as_str(), o.kind))
            .collect()
    }

    #[test]
    fn method_pkglength_shorter_than_its_name_and_flags_is_a_warning() {
        // `Method` PkgLength 1 cannot hold the 4-byte name and the flags byte.
        let aml = [0x14, 0x01, 0x41, 0x41, 0x41, 0x41, 0x00];
        let space = walk_table(&table("DSDT", "SHORT", &aml)).unwrap();
        assert!(space.objects.is_empty(), "{:?}", space.objects);
        assert!(
            space
                .warnings
                .iter()
                .any(|w| w.contains("Method PkgLength expected >= 6 | received 1")),
            "(walk_table): expected a Method PkgLength warning | received {:?}",
            space.warnings
        );
    }

    #[test]
    fn container_pkglength_shorter_than_its_name_is_a_warning() {
        let aml = [0x10, 0x01, 0x41, 0x41, 0x41, 0x41];
        let space = walk_table(&table("DSDT", "SHORT", &aml)).unwrap();
        assert!(space.objects.is_empty(), "{:?}", space.objects);
        assert!(
            space
                .warnings
                .iter()
                .any(|w| w.contains("Scope PkgLength expected >= 5 | received 1")),
            "{:?}",
            space.warnings
        );
    }

    #[test]
    fn walks_nested_scopes_with_root_and_relative_names() {
        let aml = [
            scope(
                "\\_SB_",
                &[device(
                    "PCI0",
                    &[
                        device("LPCB", &[method("SIOS", 1, &[0xA4, 0x00])]),
                        name_byte("_ADR", 0),
                    ],
                )],
            ),
            name_package("\\_S3_", &[5, 0]),
        ]
        .concat();
        let space = walk_table(&table("DSDT", "TESTDSDT", &aml)).unwrap();
        assert_eq!(
            paths(&space),
            vec![
                ("\\_SB_", ObjectKind::Scope),
                ("\\_SB_.PCI0", ObjectKind::Device),
                ("\\_SB_.PCI0.LPCB", ObjectKind::Device),
                ("\\_SB_.PCI0.LPCB.SIOS", ObjectKind::Method),
                ("\\_SB_.PCI0._ADR", ObjectKind::Name),
                ("\\_S3_", ObjectKind::Name),
            ]
        );
        assert!(space.warnings.is_empty(), "{:?}", space.warnings);
    }

    #[test]
    fn dual_and_multi_name_prefixes_and_parent_prefix_resolve() {
        let aml = [scope(
            "\\_SB_.PCI0.LPCB",
            &[
                method("^FOO_", 0, &[]),
                name_byte("SIO1.ABCD", 1),
                name_byte("\\TOP_", 2),
            ],
        )]
        .concat();
        let space = walk_table(&table("SSDT", "X", &aml)).unwrap();
        let found: Vec<&str> = space.objects.iter().map(|o| o.path.as_str()).collect();
        assert_eq!(
            found,
            vec![
                "\\_SB_.PCI0.LPCB",
                "\\_SB_.PCI0.FOO_",
                "\\_SB_.PCI0.LPCB.SIO1.ABCD",
                "\\TOP_"
            ]
        );
    }

    #[test]
    fn method_hash_covers_the_body_and_reports_argument_count() {
        let make =
            |body: &[u8]| walk_table(&table("DSDT", "T", &method("\\SIOS", 1, body))).unwrap();
        let (a, b, c) = (
            make(&[0xA4, 0x00]),
            make(&[0xA4, 0x00]),
            make(&[0xA4, 0x01]),
        );
        let hash = |s: &Namespace| s.objects[0].sha256.clone().unwrap();
        assert_eq!(hash(&a), hash(&b));
        assert_ne!(hash(&a), hash(&c));
        assert_eq!(a.objects[0].args, Some(1));
        assert_eq!(a.objects[0].offset, HEADER_LEN);
    }

    #[test]
    fn method_hash_ignores_the_name_and_flags() {
        let one = walk_table(&table("DSDT", "T", &method("\\AAAA", 0, &[0xA4, 0]))).unwrap();
        let two = walk_table(&table("DSDT", "T", &method("\\BBBB", 3, &[0xA4, 0]))).unwrap();
        assert_eq!(one.objects[0].sha256, two.objects[0].sha256);
    }

    #[test]
    fn other_containers_regions_and_fields_are_listed() {
        let aml = [
            processor("\\_PR_.CPU0", &[]),
            power_resource("\\PWRR", &[name_byte("_STA", 1)]),
            thermal_zone("\\_TZ_.TZ00", &[]),
            operation_region("\\SMI0", 0xB2, 2),
            field("SMI0", &[0x00, 0x08]),
            field("SMI0", &[0x00, 0x10]),
        ]
        .concat();
        let space = walk_table(&table("DSDT", "T", &aml)).unwrap();
        assert_eq!(
            paths(&space),
            vec![
                ("\\_PR_.CPU0", ObjectKind::Processor),
                ("\\PWRR", ObjectKind::PowerResource),
                ("\\PWRR._STA", ObjectKind::Name),
                ("\\_TZ_.TZ00", ObjectKind::ThermalZone),
                ("\\SMI0", ObjectKind::OperationRegion),
                ("\\SMI0#1", ObjectKind::Field),
                ("\\SMI0#2", ObjectKind::Field),
            ]
        );
        assert!(space.warnings.is_empty(), "{:?}", space.warnings);
        assert!(
            space.find("\\PWRR").unwrap().sha256.is_none(),
            "containers are not hashed"
        );
    }

    #[test]
    fn buffer_fields_are_listed_and_do_not_end_the_scope() {
        // CreateDWordField (BUFF, 0x04, FLD0) then CreateField (BUFF, 0x08, 0x10, FLD1).
        let mut fields = vec![0x8A];
        fields.extend(name("BUFF"));
        fields.extend([0x0A, 4]);
        fields.extend(name("FLD0"));
        fields.extend([0x5B, 0x13]);
        fields.extend(name("BUFF"));
        fields.extend([0x0A, 8, 0x0A, 0x10]);
        fields.extend(name("FLD1"));
        let aml = [scope("\\SB__", &[fields]), name_byte("\\AFTR", 1)].concat();
        let space = walk_table(&table("DSDT", "T", &aml)).unwrap();
        assert_eq!(
            paths(&space),
            vec![
                ("\\SB__", ObjectKind::Scope),
                ("\\SB__.FLD0", ObjectKind::BufferField),
                ("\\SB__.FLD1", ObjectKind::BufferField),
                ("\\AFTR", ObjectKind::Name),
            ]
        );
        assert!(space.warnings.is_empty(), "{:?}", space.warnings);
    }

    #[test]
    fn long_pkg_length_encodings_skip_correctly() {
        let big_body = vec![0xA4u8; 5000];
        let aml = [method("\\BIGM", 0, &big_body), name_byte("\\AFTR", 7)].concat();
        let space = walk_table(&table("DSDT", "T", &aml)).unwrap();
        assert_eq!(space.objects.len(), 2);
        assert!(space.warnings.is_empty(), "{:?}", space.warnings);
        assert_eq!(space.objects[1].path, "\\AFTR");
    }

    #[test]
    fn unknown_opcode_warns_with_the_scope_and_offset_and_keeps_earlier_objects() {
        let aml = [name_byte("\\GOOD", 1), vec![0x70, 0x00]].concat();
        let space = walk_table(&table("DSDT", "T", &aml)).unwrap();
        assert_eq!(space.objects.len(), 1);
        assert_eq!(space.warnings.len(), 1);
        assert!(
            space.warnings[0].contains("expected a namespace term | received opcode 0x70"),
            "{:?}",
            space.warnings
        );
        assert!(
            space.warnings[0].starts_with("\\ (offset 0x"),
            "{:?}",
            space.warnings
        );
    }

    #[test]
    fn bad_header_is_an_error_naming_the_length() {
        let mut bad = table("DSDT", "T", &[]);
        bad[4..8].copy_from_slice(&1000u32.to_le_bytes());
        let error = walk_table(&bad).expect_err("length beyond the buffer");
        assert_eq!(error.code, Code::FormatInvalid);
        assert!(
            error.message.contains("expected 36..=36 | received 1000"),
            "{error}"
        );
    }

    #[test]
    fn header_reports_oem_ids_and_checksum() {
        let good = table("SSDT", "CpuPm", &[]);
        let header = parse_header(&good).unwrap();
        assert_eq!(
            (
                header.signature.as_str(),
                header.oem_table_id.as_str(),
                header.checksum_ok
            ),
            ("SSDT", "CpuPm", true)
        );
        let mut broken = good.clone();
        broken[9] ^= 1;
        assert!(!parse_header(&broken).unwrap().checksum_ok);
    }

    #[test]
    fn invalid_name_segment_stops_the_scope() {
        let mut aml = name_byte("\\GOOD", 1);
        aml.extend([0x08, b'a', b'b', b'c', b'd', 0x0A, 0]);
        let space = walk_table(&table("DSDT", "T", &aml)).unwrap();
        assert_eq!(space.objects.len(), 1);
        assert!(
            space.warnings[0].contains("NameSeg expected [A-Z_][A-Z0-9_]{3}"),
            "{:?}",
            space.warnings
        );
    }

    #[test]
    fn pkg_length_encodings_of_every_width_keep_the_walk_aligned() {
        for body in [10usize, 62, 100, 4093, 4094, 70000] {
            let aml = [
                method("\\BIGM", 0, &vec![0xA4u8; body]),
                name_byte("\\AFTR", 7),
            ]
            .concat();
            let space = walk_table(&table("DSDT", "T", &aml)).unwrap();
            assert_eq!(
                space
                    .objects
                    .iter()
                    .map(|o| o.path.as_str())
                    .collect::<Vec<_>>(),
                vec!["\\BIGM", "\\AFTR"],
                "(method body {body} bytes): expected both objects | warnings {:?}",
                space.warnings
            );
        }
    }
}
