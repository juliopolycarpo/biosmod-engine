//! Apply, reverse and inspect guarded byte hunks.
//!
//! Offsets are in original-component coordinates. Every hunk checks its own
//! original bytes, so independent hunks give the same result in any order;
//! overlapping hunks are rejected.
//!
//! Example: `let fixed = apply(&original, &hunks)?;`

use crate::catalog::{Hunk, HunkOp};
use crate::error::{Code, Error, Result};
use crate::util::hex;

/// How a component's bytes relate to a set of hunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HunkState {
    Original,
    Fixed,
    Mixed,
    Mismatch,
}

/// Hunks sorted by offset; fails when original ranges overlap.
pub fn ordered<'a>(hunks: impl IntoIterator<Item = &'a Hunk>) -> Result<Vec<&'a Hunk>> {
    let mut rows: Vec<&Hunk> = hunks.into_iter().collect();
    rows.sort_by_key(|h| h.offset);
    let mut end: Option<usize> = None;
    let mut last_append: Option<usize> = None;
    for hunk in &rows {
        let overlaps = end.is_some_and(|e| hunk.offset < e)
            || (hunk.before.0.is_empty() && last_append == Some(hunk.offset));
        if overlaps {
            return Err(Error::new(
                Code::PatchConflict,
                format!(
                    "hunk at {:#x}: overlaps the previous hunk ending at {:#x}",
                    hunk.offset,
                    end.unwrap_or(0)
                ),
            ));
        }
        end = Some(
            hunk.offset
                .checked_add(hunk.before.0.len())
                .ok_or_else(|| {
                    Error::new(
                        Code::PatchConflict,
                        format!(
                            "hunk at {:#x}: range length {} overflows",
                            hunk.offset,
                            hunk.before.0.len()
                        ),
                    )
                })?,
        );
        last_append = hunk.before.0.is_empty().then_some(hunk.offset);
    }
    Ok(rows)
}

/// Splice every hunk into `data` after checking its guard bytes.
pub fn apply<'a>(data: &[u8], hunks: impl IntoIterator<Item = &'a Hunk>) -> Result<Vec<u8>> {
    let rows = ordered(hunks)?;
    let mut out =
        Vec::with_capacity(data.len() + rows.iter().map(|h| h.after.0.len()).sum::<usize>());
    let mut cursor = 0usize;
    for hunk in rows {
        let (at, old, new) = (hunk.offset, &hunk.before.0, &hunk.after.0);
        if hunk.op == HunkOp::Append && at != data.len() {
            return Err(Error::new(
                Code::PatchSourceMismatch,
                format!(
                    "append hunk at {at:#x}: expected module size {at:#x} | received {:#x}",
                    data.len()
                ),
            ));
        }
        if at.checked_add(old.len()).and_then(|end| data.get(at..end)) != Some(old.as_slice()) {
            return Err(mismatch(at, old, data));
        }
        out.extend_from_slice(&data[cursor..at]);
        out.extend_from_slice(new);
        cursor = at + old.len();
    }
    out.extend_from_slice(&data[cursor..]);
    Ok(out)
}

/// Undo hunks on data that is the fully patched result of the same hunk list.
pub fn reverse<'a>(data: &[u8], hunks: impl IntoIterator<Item = &'a Hunk>) -> Result<Vec<u8>> {
    let rows = ordered(hunks)?;
    let mut out = Vec::with_capacity(data.len());
    let mut cursor = 0usize;
    let mut shift = 0isize;
    for hunk in rows {
        let (old, new) = (&hunk.after.0, &hunk.before.0);
        let at = hunk
            .offset
            .checked_add_signed(shift)
            .ok_or_else(|| mismatch(hunk.offset, old, data))?;
        if at < cursor
            || at.checked_add(old.len()).and_then(|end| data.get(at..end)) != Some(old.as_slice())
        {
            return Err(mismatch(hunk.offset, old, data));
        }
        out.extend_from_slice(&data[cursor..at]);
        out.extend_from_slice(new);
        cursor = at + old.len();
        shift += hunk.after.0.len() as isize - hunk.before.0.len() as isize;
    }
    out.extend_from_slice(&data[cursor..]);
    Ok(out)
}

fn mismatch(at: usize, expected: &[u8], data: &[u8]) -> Error {
    let received = data
        .get(at..at.saturating_add(expected.len()).min(data.len()))
        .unwrap_or(&[]);
    Error::new(
        Code::PatchSourceMismatch,
        format!(
            "hunk at {at:#x}: expected {} | received {}",
            hex(&expected[..expected.len().min(16)]),
            hex(&received[..received.len().min(16)])
        ),
    )
}

/// Whether every hunk shows its original or fixed bytes.
pub fn state<'a>(data: &[u8], hunks: impl IntoIterator<Item = &'a Hunk>) -> Result<HunkState> {
    let mut original = false;
    let mut fixed = false;
    for hunk in ordered(hunks)? {
        let at = hunk.offset;
        let (before, after) = (&hunk.before.0, &hunk.after.0);
        if !before.is_empty()
            && at
                .checked_add(before.len())
                .and_then(|end| data.get(at..end))
                == Some(before.as_slice())
        {
            original = true;
        } else if !after.is_empty()
            && at
                .checked_add(after.len())
                .and_then(|end| data.get(at..end))
                == Some(after.as_slice())
        {
            fixed = true;
        } else if before.is_empty() && data.len() == at {
            original = true;
        } else {
            return Ok(HunkState::Mismatch);
        }
    }
    Ok(match (original, fixed) {
        (true, false) => HunkState::Original,
        (false, true) => HunkState::Fixed,
        _ => HunkState::Mixed,
    })
}

/// The only offset where `pattern` matches `data` (wildcards match any byte), or `None`.
pub fn find_unique(data: &[u8], pattern: &[u8], wild: &[usize]) -> Option<usize> {
    if pattern.is_empty() || pattern.len() > data.len() {
        return None;
    }
    let mut mask = vec![false; pattern.len()];
    for w in wild {
        if let Some(slot) = mask.get_mut(*w) {
            *slot = true;
        }
    }
    let anchor = (0..pattern.len()).find(|i| !mask[*i]);
    let mut found = None;
    for start in 0..=data.len() - pattern.len() {
        if let Some(a) = anchor
            && data[start + a] != pattern[a]
        {
            continue;
        }
        let window = &data[start..start + pattern.len()];
        if window
            .iter()
            .zip(pattern)
            .zip(&mask)
            .all(|((d, p), m)| *m || d == p)
        {
            if found.is_some() {
                return None;
            }
            found = Some(start);
        }
    }
    found
}

/// The signature window of a hunk: context plus original or fixed bytes, with its lead length.
pub fn signature(hunk: &Hunk, fixed: bool) -> (Vec<u8>, usize, &[usize]) {
    let middle = if fixed { &hunk.after.0 } else { &hunk.before.0 };
    let mut pattern =
        Vec::with_capacity(hunk.context_before.0.len() + middle.len() + hunk.context_after.0.len());
    pattern.extend_from_slice(&hunk.context_before.0);
    pattern.extend_from_slice(middle);
    pattern.extend_from_slice(&hunk.context_after.0);
    (
        pattern,
        hunk.context_before.0.len(),
        if fixed {
            &hunk.wild_after
        } else {
            &hunk.wild_before
        },
    )
}

/// Find hunks in a module of a different build by unique context signature.
///
/// Returns `Original` when every original signature occurs exactly once,
/// `Fixed` when every fixed signature does, otherwise `Mismatch`. Offsets are
/// the hunk positions found; appended hunks sit at the module end.
pub fn locate(data: &[u8], hunks: &[Hunk]) -> (HunkState, Vec<usize>) {
    for (wanted, fixed) in [(HunkState::Original, false), (HunkState::Fixed, true)] {
        let offsets: Option<Vec<usize>> = hunks
            .iter()
            .map(|hunk| {
                if hunk.before.0.is_empty() {
                    return Some(data.len());
                }
                let (pattern, lead, wild) = signature(hunk, fixed);
                find_unique(data, &pattern, wild).map(|at| at + lead)
            })
            .collect();
        if let Some(offsets) = offsets {
            return (wanted, offsets);
        }
    }
    (HunkState::Mismatch, Vec::new())
}

/// Hunks moved onto another build's module by [`rebase`].
#[derive(Debug, Clone)]
pub struct Rebased {
    pub hunks: Vec<Hunk>,
    /// Offsets of hunks whose original bytes differ from the reference (masked
    /// addresses or displacements). Their `after` bytes come from the reference
    /// build and need review before use.
    pub review: Vec<usize>,
}

/// Move `hunks` onto `data`, a module from another build, by unique signature.
///
/// Offsets, original bytes and context are taken from `data`; replacement
/// bytes are kept. Fails when any signature is missing or not unique.
///
/// Example: `rebase(&pr9_module, &mr9a_component.hunks)?.review.is_empty()`
/// means every original byte matched exactly.
pub fn rebase(data: &[u8], hunks: &[Hunk]) -> Result<Rebased> {
    let (state, offsets) = locate(data, hunks);
    if state != HunkState::Original {
        return Err(Error::new(
            Code::PatchSourceMismatch,
            format!(
                "signatures: expected every original signature exactly once | found state {state:?}"
            ),
        ));
    }
    let mut moved = Vec::with_capacity(hunks.len());
    let mut review = Vec::new();
    for (hunk, offset) in hunks.iter().zip(offsets) {
        let mut next = hunk.clone();
        next.offset = offset;
        if hunk.op == HunkOp::Replace {
            let len = hunk.before.0.len();
            let lead = hunk.context_before.0.len();
            let tail = hunk.context_after.0.len();
            next.before.0 = data[offset..offset + len].to_vec();
            next.context_before.0 = data[offset - lead..offset].to_vec();
            next.context_after.0 = data[offset + len..offset + len + tail].to_vec();
            if next.before != hunk.before {
                review.push(offset);
            }
        }
        moved.push(next);
    }
    Ok(Rebased {
        hunks: moved,
        review,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::HexBytes;

    #[test]
    fn rebase_takes_original_bytes_from_the_target_and_flags_masked_differences() {
        let reference: Vec<u8> = (0..64u8).collect();
        let mut hunk = replace(20, &reference[20..25], &[0x90; 5]);
        hunk.context_before = HexBytes(reference[4..20].to_vec());
        hunk.context_after = HexBytes(reference[25..41].to_vec());
        // Bytes 1..5 of `before` (a call displacement) may differ between builds.
        hunk.wild_before = (17..21).collect();
        let mut other = vec![0xEEu8; 7];
        other.extend_from_slice(&reference);
        other[7 + 22] ^= 0x04;
        let rebased = rebase(&other, std::slice::from_ref(&hunk)).unwrap();
        assert_eq!(rebased.hunks[0].offset, 27);
        assert_eq!(rebased.hunks[0].before.0, other[27..32].to_vec());
        assert_eq!(rebased.review, vec![27]);
        assert!(apply(&other, &rebased.hunks).is_ok());
        assert_eq!(
            rebase(&[0u8; 64], &[hunk]).unwrap_err().code,
            Code::PatchSourceMismatch
        );
    }

    pub(crate) fn replace(offset: usize, before: &[u8], after: &[u8]) -> Hunk {
        Hunk {
            op: HunkOp::Replace,
            offset,
            before: HexBytes(before.to_vec()),
            after: HexBytes(after.to_vec()),
            context_before: HexBytes::default(),
            context_after: HexBytes::default(),
            findings: vec![],
            wild_before: vec![],
            wild_after: vec![],
        }
    }

    fn append(offset: usize, after: &[u8]) -> Hunk {
        Hunk {
            op: HunkOp::Append,
            ..replace(offset, &[], after)
        }
    }

    #[test]
    fn apply_and_reverse_round_trip_with_append() {
        let data = b"0123456789".to_vec();
        let hunks = [replace(2, b"23", b"ab"), append(10, b"XYZ")];
        let fixed = apply(&data, &hunks).unwrap();
        assert_eq!(fixed, b"01ab456789XYZ");
        assert_eq!(reverse(&fixed, &hunks).unwrap(), data);
        assert_eq!(state(&fixed, &hunks).unwrap(), HunkState::Fixed);
        assert_eq!(state(&data, &hunks).unwrap(), HunkState::Original);
    }

    #[test]
    fn guard_mismatch_and_overlap_are_refused() {
        let data = b"0123456789".to_vec();
        let error = apply(&data, &[replace(2, b"xx", b"ab")]).unwrap_err();
        assert_eq!(error.code, Code::PatchSourceMismatch);
        assert!(
            error.message.contains("expected 7878 | received 3233"),
            "{error}"
        );
        let error =
            apply(&data, &[replace(2, b"23", b"ab"), replace(3, b"34", b"cd")]).unwrap_err();
        assert_eq!(error.code, Code::PatchConflict);
        assert!(
            apply(&data, &[append(4, b"x")]).is_err(),
            "append must sit at the module end"
        );
    }

    #[test]
    fn overflowing_hunk_range_is_rejected() {
        let hunk = replace(usize::MAX, b"x", b"y");
        let error = ordered([&hunk]).unwrap_err();
        assert!(error.message.contains("range"), "{error}");
    }

    #[test]
    fn partial_application_reports_mixed() {
        let data = b"0123456789".to_vec();
        let hunks = [replace(1, b"1", b"a"), replace(5, b"5", b"b")];
        let half = apply(&data, &hunks[..1]).unwrap();
        assert_eq!(state(&half, &hunks).unwrap(), HunkState::Mixed);
        assert_eq!(state(b"zzzzzzzzzz", &hunks).unwrap(), HunkState::Mismatch);
    }

    #[test]
    fn unique_search_honours_wildcards_and_repeats() {
        assert_eq!(find_unique(b"abcXdefabc", b"cXd", &[]), Some(2));
        assert_eq!(find_unique(b"abcabc", b"abc", &[]), None);
        assert_eq!(find_unique(b"a1ca2c", b"a?c", &[1]), None);
        assert_eq!(find_unique(b"a1cb2c", b"a?c", &[1]), Some(0));
    }
}
