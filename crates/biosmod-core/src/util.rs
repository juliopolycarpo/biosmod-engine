//! Small byte helpers: hex, SHA-256, EFI GUIDs and checked little-endian reads.

use crate::error::{Code, Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// Lowercase hex encoding, e.g. `hex(&[0xab, 0x01]) == "ab01"`.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

/// Decode hex (either case), e.g. `unhex("AB01").unwrap() == vec![0xab, 1]`.
pub fn unhex(text: &str) -> Result<Vec<u8>> {
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(Error::new(
            Code::CatalogInvalid,
            format!(
                "hex string of length {}: expected an even length",
                raw.len()
            ),
        ));
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    raw.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| match (nibble(pair[0]), nibble(pair[1])) {
            (Some(high), Some(low)) => Ok(high << 4 | low),
            _ => Err(Error::new(
                Code::CatalogInvalid,
                format!(
                    "hex digit pair {:?}: expected [0-9a-f]",
                    String::from_utf8_lossy(pair)
                ),
            )),
        })
        .collect()
}

/// SHA-256 as lowercase hex, e.g. `sha256_hex(b"")` starts with `e3b0c442`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Raw SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Round up to a multiple of `size` (a power of two or any positive value), e.g. `align(9, 8) == 16`.
pub fn align(value: usize, size: usize) -> usize {
    value.div_ceil(size) * size
}

/// Bytes `[at, at + len)` of `data`, or a `FormatInvalid` error naming `what`.
pub fn slice<'a>(data: &'a [u8], at: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    at.checked_add(len)
        .and_then(|end| data.get(at..end))
        .ok_or_else(|| {
            Error::new(
                Code::FormatInvalid,
                format!(
                    "{what} at {at:#x}+{len:#x}: exceeds buffer of {:#x} bytes",
                    data.len()
                ),
            )
        })
}

/// Little-endian u16 at `at`.
pub fn le16(data: &[u8], at: usize, what: &str) -> Result<u16> {
    Ok(u16::from_le_bytes(
        slice(data, at, 2, what)?.try_into().expect("two bytes"),
    ))
}

/// Little-endian 24-bit value at `at`.
pub fn le24(data: &[u8], at: usize, what: &str) -> Result<u32> {
    let b = slice(data, at, 3, what)?;
    Ok(u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16)
}

/// Little-endian u32 at `at`.
pub fn le32(data: &[u8], at: usize, what: &str) -> Result<u32> {
    Ok(u32::from_le_bytes(
        slice(data, at, 4, what)?.try_into().expect("four bytes"),
    ))
}

/// Little-endian u64 at `at`.
pub fn le64(data: &[u8], at: usize, what: &str) -> Result<u64> {
    Ok(u64::from_le_bytes(
        slice(data, at, 8, what)?.try_into().expect("eight bytes"),
    ))
}

/// Byte-wise sum modulo 256.
pub fn sum8(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, b| acc.wrapping_add(*b))
}

/// An EFI GUID stored in its on-disk (mixed-endian) byte order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// Read a GUID from 16 on-disk bytes.
    pub fn from_slice(raw: &[u8]) -> Guid {
        let mut out = [0u8; 16];
        out.copy_from_slice(&raw[..16]);
        Guid(out)
    }

    /// Parse a constant GUID; panics on malformed input, so use only for literals.
    pub const fn constant(text: &str) -> Guid {
        match parse_guid(text.as_bytes()) {
            Some(guid) => guid,
            None => panic!("malformed GUID literal"),
        }
    }
}

const fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const fn parse_guid(text: &[u8]) -> Option<Guid> {
    if text.len() != 36
        || text[8] != b'-'
        || text[13] != b'-'
        || text[18] != b'-'
        || text[23] != b'-'
    {
        return None;
    }
    // Text order as big-endian bytes, then swap the first three fields.
    let mut be = [0u8; 16];
    let mut i = 0;
    let mut n = 0;
    while i < 36 {
        if text[i] == b'-' {
            i += 1;
            continue;
        }
        let (Some(high), Some(low)) = (hex_value(text[i]), hex_value(text[i + 1])) else {
            return None;
        };
        be[n] = high << 4 | low;
        n += 1;
        i += 2;
    }
    let order = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut out = [0u8; 16];
    let mut k = 0;
    while k < 16 {
        out[k] = be[order[k]];
        k += 1;
    }
    Some(Guid(out))
}

impl FromStr for Guid {
    type Err = Error;

    fn from_str(text: &str) -> Result<Guid> {
        parse_guid(text.as_bytes()).ok_or_else(|| {
            Error::new(
                Code::Usage,
                format!("GUID {text:?}: expected 8-4-4-4-12 hex digits"),
            )
        })
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            b[3],
            b[2],
            b[1],
            b[0],
            b[5],
            b[4],
            b[7],
            b[6],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Guid {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Guid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Guid, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse()
            .map_err(|error: Error| serde::de::Error::custom(error.message))
    }
}

/// Bytes serialized as a lowercase hex string.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct HexBytes(pub Vec<u8>);

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl Serialize for HexBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<HexBytes, D::Error> {
        let text = String::deserialize(deserializer)?;
        unhex(&text)
            .map(HexBytes)
            .map_err(|error| serde::de::Error::custom(error.message))
    }
}

/// A SHA-256 digest serialized as 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest256(pub [u8; 32]);

impl Digest256 {
    /// Digest of `data`.
    pub fn of(data: &[u8]) -> Digest256 {
        Digest256(sha256(data))
    }
}

impl fmt::Display for Digest256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl fmt::Debug for Digest256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Digest256 {
    type Err = Error;

    fn from_str(text: &str) -> Result<Digest256> {
        if text.len() != 64
            || !text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(Error::new(
                Code::CatalogInvalid,
                format!("SHA-256 {text:?}: expected 64 lowercase hex digits"),
            ));
        }
        let bytes = unhex(text)?;
        Ok(Digest256(bytes.try_into().expect("32 bytes")))
    }
}

impl Serialize for Digest256 {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest256 {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Digest256, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse()
            .map_err(|error: Error| serde::de::Error::custom(error.message))
    }
}

fn string_schema(description: &str, pattern: &str) -> schemars::Schema {
    schemars::json_schema!({"type": "string", "description": description, "pattern": pattern})
}

impl schemars::JsonSchema for Guid {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Guid".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        string_schema(
            "EFI GUID in registry format",
            "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$",
        )
    }
}

impl schemars::JsonSchema for HexBytes {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "HexBytes".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        string_schema("Bytes as hexadecimal", "^([0-9a-fA-F]{2})*$")
    }
}

impl schemars::JsonSchema for Digest256 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Digest256".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        string_schema("SHA-256 digest, lowercase hexadecimal", "^[0-9a-f]{64}$")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_round_trips_through_text_and_disk_order() {
        let text = "EE4E5898-3914-4259-9D6E-DC7BD79403CF";
        let guid: Guid = text.parse().unwrap();
        assert_eq!(hex(&guid.0[..4]), "98584eee");
        assert_eq!(guid.to_string(), text);
        assert_eq!(Guid::constant(text), guid);
    }

    #[test]
    fn hex_rejects_odd_length_and_bad_digits() {
        assert_eq!(unhex("0aFF").unwrap(), vec![0x0a, 0xff]);
        assert!(unhex("abc").unwrap_err().message.contains("even length"));
        assert!(
            unhex("zz")
                .unwrap_err()
                .message
                .contains("expected [0-9a-f]")
        );
    }

    #[test]
    fn checked_reads_report_the_overrun() {
        let error = le32(&[1, 2, 3], 0, "field").unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid);
        assert!(error.message.contains("field at 0x0+0x4"));
        assert!(slice(&[0; 4], usize::MAX, 2, "x").is_err());
    }

    #[test]
    fn digest_requires_lowercase_hex() {
        assert!(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
                .parse::<Digest256>()
                .is_err()
        );
        assert_eq!(Digest256::of(b"").to_string(), sha256_hex(b""));
    }
}
