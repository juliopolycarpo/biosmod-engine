//! Decode the MR9A MRC checkpoint breadcrumbs stored in upper-bank CMOS `E0`-`E9`.
//!
//! Layout (see `bme guide breadcrumbs`): `E0` state (`A0` + 2 for slot 1 + 1
//! once the pass ended), `E1`-`E4` slot 0, `E5`-`E8` slot 1 (little-endian
//! `major<<24 | minor<<16 | location`), `E9` failed-pass count.
//!
//! Example: `decode(&[0xA1, 0, 0, 0, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0])`.

use crate::error::{Code, Error, Result};
use serde::Serialize;

/// First CMOS index of the layout.
pub const FIRST_INDEX: u8 = 0xE0;
/// Number of bytes in the layout.
pub const LENGTH: usize = 10;

/// One stored checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Checkpoint {
    pub major: u8,
    pub minor: u8,
    pub location: u16,
}

impl Checkpoint {
    /// `B7/31 location 0302` style text.
    pub fn describe(&self) -> String {
        format!(
            "{:02X}/{:02X} location {:04X}",
            self.major, self.minor, self.location
        )
    }
}

/// The decoded state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Breadcrumbs {
    pub armed: bool,
    pub state: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass_ended: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<Checkpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failures: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<Checkpoint>,
}

/// Decode bytes `E0`-`E9`.
pub fn decode(raw: &[u8]) -> Result<Breadcrumbs> {
    if raw.len() != LENGTH {
        return Err(Error::new(
            Code::Usage,
            format!(
                "breadcrumbs: expected {LENGTH} bytes (E0-E9) | received {}",
                raw.len()
            ),
        ));
    }
    let state = raw[0];
    if state & 0xFC != 0xA0 {
        return Ok(Breadcrumbs {
            armed: false,
            state,
            pass_ended: None,
            active: None,
            failures: None,
            last_failure: None,
        });
    }
    let slot = usize::from((state >> 1) & 1);
    let record = |n: usize| {
        let value = u32::from_le_bytes(raw[1 + 4 * n..5 + 4 * n].try_into().expect("four bytes"));
        Checkpoint {
            major: (value >> 24) as u8,
            minor: (value >> 16) as u8,
            location: value as u16,
        }
    };
    let count = raw[9];
    Ok(Breadcrumbs {
        armed: true,
        state,
        pass_ended: Some(state & 1 != 0),
        active: Some(record(slot)),
        failures: Some(count),
        last_failure: (count != 0).then(|| record(slot ^ 1)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_recorded_hardware_snapshot() {
        let raw = [0xA1, 0x00, 0x00, 0x00, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        let info = decode(&raw).unwrap();
        assert!(info.armed);
        assert_eq!(info.active.unwrap().describe(), "BF/00 location 0000");
        assert_eq!(info.pass_ended, Some(true));
        assert_eq!(info.last_failure, None);
    }

    #[test]
    fn failed_pass_reads_the_other_slot() {
        let mut raw = [0xA2, 0, 0, 0, 0xB0, 0x02, 0x03, 0x31, 0xB7, 3];
        raw[1..5].copy_from_slice(&0xB000_0000u32.to_le_bytes());
        let info = decode(&raw).unwrap();
        assert_eq!(info.active.unwrap().major, 0xB7);
        assert_eq!(info.last_failure.unwrap().describe(), "B0/00 location 0000");
    }

    #[test]
    fn unarmed_and_wrong_length() {
        assert!(!decode(&[0xFF; 10]).unwrap().armed);
        assert_eq!(decode(&[0; 3]).unwrap_err().code, Code::Usage);
    }
}
