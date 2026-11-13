//! Project-owned interface to the LZMA ("LZMA alone"), CRC32 and decode-only codecs.
//!
//! Decode-only codecs (EFI 1.1 and Tiano compression, Brotli, LZMA with the
//! x86 filter) take a `limit` on the decoded size and name it when exceeded.
//!
//! Encoding uses the same liblzma algorithm and options as the reference
//! implementation, so identical inputs produce identical compressed streams.
//! Changing the codec build can change output bytes; plans record
//! [`identity`] and refuse to apply under a different one.

use crate::error::{Code, Error, Result};
use liblzma::stream::{Action, LzmaOptions, MatchFinder, Mode, Status, Stream};
use std::io::Read;

pub mod tiano;

/// Largest decoded size accepted for one LZMA section.
pub const MAX_DECODED: usize = 64 << 20;
/// Dictionary memory limit for decoding.
const DECODER_MEMLIMIT: u64 = 256 << 20;
/// `nice_len` values tried by [`compress_like`]; the smallest output wins.
const NICE_LENGTHS: [u32; 4] = [32, 64, 128, 273];

/// The codec build identity, e.g. `"liblzma 5.8.4"`.
pub fn identity() -> String {
    // SAFETY: lzma_version_number has no preconditions and returns a plain integer.
    let number = unsafe { liblzma_sys::lzma_version_number() };
    let (major, minor, patch) = (
        number / 10_000_000,
        number / 10_000 % 1000,
        number / 10 % 1000,
    );
    format!("liblzma {major}.{minor}.{patch}")
}

/// Decode an LZMA-alone stream (13-byte header) with bounded output.
///
/// Trailing bytes after the end of the stream are ignored, as the reference does.
/// Example: `let plain = decompress(&section_payload)?;`
pub fn decompress(stream: &[u8]) -> Result<Vec<u8>> {
    decompress_within(stream, MAX_DECODED)
}

/// Like [`decompress`], with the decoded size capped at `cap` (at most [`MAX_DECODED`]).
///
/// Example: `let plain = decompress_within(&section_payload, 1 << 20)?;`
pub fn decompress_within(stream: &[u8], cap: usize) -> Result<Vec<u8>> {
    let cap = cap.min(MAX_DECODED);
    if stream.len() < 13 {
        return Err(Error::new(
            Code::FormatInvalid,
            format!(
                "LZMA stream of {} bytes: expected a 13-byte header",
                stream.len()
            ),
        ));
    }
    let declared = u64::from_le_bytes(stream[5..13].try_into().expect("eight bytes"));
    let limit = if declared == u64::MAX {
        cap
    } else {
        usize::try_from(declared).unwrap_or(usize::MAX)
    };
    if limit > cap {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!("LZMA stream declares {declared:#x} decoded bytes: expected at most {cap:#x}"),
        ));
    }
    let mut decoder = Stream::new_lzma_decoder(DECODER_MEMLIMIT).map_err(lzma_error)?;
    let mut output = Vec::with_capacity(limit.min(cap));
    let mut consumed = 0usize;
    loop {
        if output.len() == output.capacity() {
            if output.len() >= cap {
                return Err(Error::new(
                    Code::FormatUnsupported,
                    format!("LZMA stream: decoded size exceeds {cap:#x}"),
                ));
            }
            output.reserve(output.len().max(4096).min(cap - output.len()));
        }
        let before_in = decoder.total_in();
        let status = decoder
            .process_vec(&stream[consumed..], &mut output, Action::Run)
            .map_err(lzma_error)?;
        consumed += (decoder.total_in() - before_in) as usize;
        if status == Status::StreamEnd {
            return Ok(output);
        }
        // Run stops only at end of stream, a full output buffer or exhausted input.
        if output.len() < output.capacity() {
            return Err(Error::new(
                Code::FormatInvalid,
                "LZMA stream: data ended before the end of the stream",
            ));
        }
    }
}

/// Compress `decoded` with the lc/lp/pb and dictionary size of `original`.
///
/// Mirrors the reference packer: liblzma preset 6 with normal mode and BT4,
/// trying several `nice_len` values and keeping the smallest stream. The size
/// field is set to the decoded length, and the result is verified by decoding.
/// Example: `let packed = compress_like(&new_body, &old_payload)?;`
pub fn compress_like(decoded: &[u8], original: &[u8]) -> Result<Vec<u8>> {
    if original.len() < 13 {
        return Err(Error::new(
            Code::FormatInvalid,
            "LZMA stream: expected a 13-byte header to copy properties from",
        ));
    }
    let prop = u32::from(original[0]);
    if prop >= 9 * 5 * 5 {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!("LZMA properties byte {prop:#x}: expected below 0xe1"),
        ));
    }
    let (lc, lp, pb) = (prop % 9, prop / 9 % 5, prop / 45);
    let dictionary = u32::from_le_bytes(original[1..5].try_into().expect("four bytes"));
    let mut best: Option<Vec<u8>> = None;
    for nice in NICE_LENGTHS {
        let packed = encode(decoded, dictionary, lc, lp, pb, nice)?;
        if best.as_ref().is_none_or(|b| packed.len() < b.len()) {
            best = Some(packed);
        }
    }
    let best = best.expect("at least one candidate");
    if decompress(&best)? != decoded {
        return Err(Error::new(
            Code::OutputVerificationFailed,
            "LZMA round trip: recompressed data does not decode to the input",
        ));
    }
    Ok(best)
}

fn encode(data: &[u8], dictionary: u32, lc: u32, lp: u32, pb: u32, nice: u32) -> Result<Vec<u8>> {
    let mut options = LzmaOptions::new_preset(6).map_err(lzma_error)?;
    options
        .dict_size(dictionary)
        .literal_context_bits(lc)
        .literal_position_bits(lp)
        .position_bits(pb)
        .mode(Mode::Normal)
        .match_finder(MatchFinder::BinaryTree4)
        .nice_len(nice);
    let mut encoder = Stream::new_lzma_encoder(&options).map_err(lzma_error)?;
    let mut output = Vec::with_capacity(data.len() / 2 + 4096);
    let mut consumed = 0usize;
    loop {
        if output.len() == output.capacity() {
            output.reserve(output.len().max(4096));
        }
        let before = encoder.total_in();
        let status = encoder
            .process_vec(&data[consumed..], &mut output, Action::Finish)
            .map_err(lzma_error)?;
        consumed += (encoder.total_in() - before) as usize;
        if status == Status::StreamEnd {
            break;
        }
    }
    if output.len() < 13 {
        return Err(Error::new(
            Code::Internal,
            "LZMA encoder produced no header",
        ));
    }
    output[5..13].copy_from_slice(&(data.len() as u64).to_le_bytes());
    Ok(output)
}

/// Decode an EFI compression section payload (EFI 1.1 or Tiano), capped at `limit` bytes.
///
/// Returns the plain bytes and the variant that decoded them.
/// Example: `let (plain, variant) = efi_decompress(&payload, 1 << 20)?;`
pub fn efi_decompress(payload: &[u8], limit: usize) -> Result<(Vec<u8>, tiano::Variant)> {
    tiano::decompress(payload, limit.min(MAX_DECODED))
}

/// Decode an EFI compression section payload as one specific variant, capped at `limit` bytes.
///
/// Example: `let plain = efi_decompress_as(&payload, tiano::Variant::Tiano, 1 << 20)?;`
pub fn efi_decompress_as(payload: &[u8], variant: tiano::Variant, limit: usize) -> Result<Vec<u8>> {
    tiano::decompress_as(payload, variant, limit.min(MAX_DECODED))
}

/// Size of the EDK II Brotli section header: decoded size and scratch size, both `u64`.
pub const BROTLI_HEADER_LEN: usize = 16;

/// Decode a GUID-defined Brotli payload (EDK II `BrotliCustomDecompress`).
///
/// The 16-byte header declares the decoded size, which must be at most `limit`
/// and which the stream must produce exactly.
/// Example: `let plain = brotli_decompress(&payload, 1 << 20)?;`
pub fn brotli_decompress(payload: &[u8], limit: usize) -> Result<Vec<u8>> {
    let limit = limit.min(MAX_DECODED);
    if payload.len() < BROTLI_HEADER_LEN {
        return Err(Error::new(
            Code::FormatInvalid,
            format!(
                "Brotli section payload of {} bytes: expected a {BROTLI_HEADER_LEN}-byte header",
                payload.len()
            ),
        ));
    }
    let declared = u64::from_le_bytes(payload[0..8].try_into().expect("eight bytes"));
    let declared = usize::try_from(declared).unwrap_or(usize::MAX);
    if declared > limit {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!(
                "Brotli section declares {declared:#x} decoded bytes: expected at most {limit:#x}"
            ),
        ));
    }
    // One byte past the declaration detects a stream that expands further.
    let mut reader = brotli_decompressor::Decompressor::new(&payload[BROTLI_HEADER_LEN..], 4096)
        .take(declared as u64 + 1);
    let mut output = Vec::with_capacity(declared.min(1 << 20));
    reader
        .read_to_end(&mut output)
        .map_err(|e| Error::new(Code::FormatInvalid, format!("Brotli stream: {e}")))?;
    if output.len() != declared {
        let received = if output.len() > declared {
            format!("more than {declared:#x}")
        } else {
            format!("{:#x}", output.len())
        };
        return Err(Error::new(
            Code::FormatInvalid,
            format!("Brotli stream decoded size: expected {declared:#x} | received {received}"),
        ));
    }
    Ok(output)
}

/// Decode a GUID-defined LZMA F86 payload: LZMA-alone data, then the x86 BCJ filter.
///
/// Example: `let plain = lzma_x86_decompress(&payload, 1 << 20)?;`
pub fn lzma_x86_decompress(payload: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut data = decompress_within(payload, limit)?;
    x86_convert(&mut data, false);
    Ok(data)
}

/// The x86 BCJ filter with instruction pointer 0, as in the LZMA SDK `x86_Convert`.
///
/// It turns the relative operands of CALL (E8) and JMP (E9) into absolute ones
/// when `encoding` and back otherwise, in place. The last four bytes stay as is.
/// The state machine follows the SDK so output matches `LzmaF86Decompress`.
/// Example: `x86_convert(&mut code, false);`
pub(crate) fn x86_convert(data: &mut [u8], encoding: bool) {
    const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
    const BIT_NUMBER: [usize; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
    // An operand's top byte is plausible only when it is a sign extension.
    let sign_byte = |b: u8| b == 0 || b == 0xFF;
    if data.len() < 5 {
        return;
    }
    let limit = data.len() - 4;
    let mut position = 0usize;
    let mut previous = usize::MAX;
    let mut mask = 0usize;
    loop {
        while position < limit && data[position] & 0xFE != 0xE8 {
            position += 1;
        }
        if position >= limit {
            break;
        }
        let gap = position.wrapping_sub(previous);
        if gap > 3 {
            mask = 0;
        } else {
            mask = (mask << (gap - 1)) & 7;
            if mask != 0 {
                let byte = data[position + 4 - BIT_NUMBER[mask]];
                if !ALLOWED[mask] || sign_byte(byte) {
                    previous = position;
                    mask = ((mask << 1) & 7) | 1;
                    position += 1;
                    continue;
                }
            }
        }
        previous = position;
        if sign_byte(data[position + 4]) {
            let mut source = u32::from_le_bytes([
                data[position + 1],
                data[position + 2],
                data[position + 3],
                data[position + 4],
            ]);
            let here = (position as u32).wrapping_add(5);
            let destination = loop {
                let destination = if encoding {
                    here.wrapping_add(source)
                } else {
                    source.wrapping_sub(here)
                };
                if mask == 0 {
                    break destination;
                }
                let index = BIT_NUMBER[mask] * 8;
                if !sign_byte((destination >> (24 - index)) as u8) {
                    break destination;
                }
                source = destination ^ ((1u32 << (32 - index)) - 1);
            };
            let top = if (destination >> 24) & 1 == 1 {
                0xFF
            } else {
                0
            };
            data[position + 1..position + 4].copy_from_slice(&destination.to_le_bytes()[..3]);
            data[position + 4] = top;
            position += 5;
        } else {
            mask = ((mask << 1) & 7) | 1;
            position += 1;
        }
    }
}

fn lzma_error(error: liblzma::stream::Error) -> Error {
    Error::new(Code::FormatInvalid, format!("LZMA: {error}"))
}

/// IEEE CRC32, as used by CRC32 GUID-defined sections.
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        (0..20_000u32)
            .map(|i| (i * 7 % 251) as u8 ^ (i >> 9) as u8)
            .collect()
    }

    #[test]
    fn compress_like_round_trips_and_keeps_properties() {
        let data = sample();
        let template = encode(&data, 1 << 16, 3, 0, 2, 64).unwrap();
        let packed = compress_like(&data, &template).unwrap();
        assert_eq!(packed[0], template[0]);
        assert_eq!(&packed[5..13], &(data.len() as u64).to_le_bytes());
        assert_eq!(decompress(&packed).unwrap(), data);
    }

    #[test]
    fn truncated_stream_is_an_error_not_a_panic() {
        let data = sample();
        let packed = encode(&data, 1 << 16, 3, 0, 2, 64).unwrap();
        let error = decompress(&packed[..packed.len() / 2]).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid, "{error}");
        assert!(decompress(&packed[..5]).is_err());
    }

    #[test]
    fn oversized_declaration_is_refused_before_allocation() {
        let mut header = vec![0x5d, 0, 0, 1, 0];
        header.extend_from_slice(&(1u64 << 40).to_le_bytes());
        header.extend_from_slice(&[0; 16]);
        assert_eq!(
            decompress(&header).unwrap_err().code,
            Code::FormatUnsupported
        );
    }

    const SMALL_BROTLI: &[u8] = include_bytes!("../tests/fixtures/small.br");

    /// A Brotli section payload: EDK II header (decoded size, scratch size) and stream.
    fn brotli_payload(declared: u64, stream: &[u8]) -> Vec<u8> {
        let mut payload = declared.to_le_bytes().to_vec();
        payload.extend_from_slice(&0x1000u64.to_le_bytes());
        payload.extend_from_slice(stream);
        payload
    }

    #[test]
    fn brotli_decodes_the_edk2_payload_layout() {
        let plain = tiano::tests::fixture_text(300, 1);
        let decoded = brotli_decompress(&brotli_payload(300, SMALL_BROTLI), 1 << 20).unwrap();
        assert_eq!(decoded, plain);
    }

    #[test]
    fn brotli_decodes_a_stored_meta_block() {
        let data = crate::synthetic::module(5, 1000);
        let payload = brotli_payload(1000, &crate::synthetic::brotli_stored(&data));
        assert_eq!(brotli_decompress(&payload, 1 << 20).unwrap(), data);
    }

    #[test]
    fn brotli_declared_size_must_match_the_stream() {
        for (declared, expected) in [(299u64, "more than 0x12b"), (301, "received 0x12c")] {
            let error =
                brotli_decompress(&brotli_payload(declared, SMALL_BROTLI), 1 << 20).unwrap_err();
            assert_eq!(error.code, Code::FormatInvalid, "{error}");
            assert!(
                error
                    .message
                    .contains(&format!("decoded size: expected {declared:#x} | received"))
                    && error.message.contains(expected),
                "{error}"
            );
        }
    }

    #[test]
    fn brotli_expansion_bomb_fails_on_the_named_limit() {
        let error =
            brotli_decompress(&brotli_payload(1 << 40, SMALL_BROTLI), 64 << 20).unwrap_err();
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(
            error
                .message
                .contains("declares 0x10000000000 decoded bytes: expected at most 0x4000000"),
            "{error}"
        );
        let error = brotli_decompress(&brotli_payload(300, SMALL_BROTLI), 100).unwrap_err();
        assert!(error.message.contains("expected at most 0x64"), "{error}");
    }

    #[test]
    fn brotli_rejects_short_header_and_corrupt_stream() {
        let error = brotli_decompress(&[0; 15], 1 << 20).unwrap_err();
        assert!(
            error
                .message
                .contains("payload of 15 bytes: expected a 16-byte header"),
            "{error}"
        );
        let mut stream = SMALL_BROTLI.to_vec();
        stream.truncate(stream.len() / 2);
        let error = brotli_decompress(&brotli_payload(300, &stream), 1 << 20).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid, "{error}");
        assert!(error.message.contains("Brotli stream"), "{error}");
    }

    fn x86_like(size: usize) -> Vec<u8> {
        crate::synthetic::x86_code(size)
    }

    fn lzma_f86_payload(plain: &[u8]) -> Vec<u8> {
        let mut filtered = plain.to_vec();
        x86_convert(&mut filtered, true);
        let mut template = vec![0x5D, 0, 0, 1, 0];
        template.extend_from_slice(&[0xFF; 8]);
        compress_like(&filtered, &template).unwrap()
    }

    const X86_BCJ_XZ: &[u8] = include_bytes!("../tests/fixtures/x86-like.bcj");

    #[test]
    fn x86_convert_matches_the_xz_encoder_and_round_trips() {
        let plain = x86_like(600);
        assert_eq!(X86_BCJ_XZ.len(), plain.len());
        assert_ne!(
            X86_BCJ_XZ, plain,
            "expected the BCJ filter to rewrite CALLs"
        );
        let mut decoded = X86_BCJ_XZ.to_vec();
        x86_convert(&mut decoded, false);
        assert!(
            decoded == plain,
            "decoded x86 filter output differs from the source"
        );
        let mut encoded = plain.clone();
        x86_convert(&mut encoded, true);
        assert!(
            encoded == X86_BCJ_XZ,
            "encoder output differs from xz's x86 filter"
        );
    }

    #[test]
    fn x86_convert_leaves_short_buffers_alone() {
        let mut short = [0xE8, 1, 2, 3];
        x86_convert(&mut short, false);
        assert_eq!(short, [0xE8, 1, 2, 3]);
    }

    #[test]
    fn lzma_f86_round_trips_through_lzma_and_the_x86_filter() {
        let plain = x86_like(4000);
        let payload = lzma_f86_payload(&plain);
        assert_eq!(lzma_x86_decompress(&payload, 1 << 20).unwrap(), plain);
        assert_ne!(
            decompress(&payload).unwrap(),
            plain,
            "plain LZMA decoding must leave the filter applied"
        );
    }

    #[test]
    fn lzma_f86_honours_the_decoded_size_limit() {
        let payload = lzma_f86_payload(&x86_like(4000));
        let error = lzma_x86_decompress(&payload, 1000).unwrap_err();
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(error.message.contains("expected at most 0x3e8"), "{error}");
    }

    #[test]
    fn decompress_within_caps_below_the_global_limit() {
        let packed = encode(&sample(), 1 << 16, 3, 0, 2, 64).unwrap();
        let error = decompress_within(&packed, 1000).unwrap_err();
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(error.message.contains("at most 0x3e8"), "{error}");
        assert_eq!(decompress_within(&packed, 1 << 20).unwrap(), sample());
    }

    #[test]
    fn efi_decompress_reports_the_variant_and_caps_the_limit() {
        let (plain, variant) = efi_decompress(tiano::tests::SMALL_EFI, 1 << 20).unwrap();
        assert_eq!(plain, tiano::tests::fixture_text(300, 1));
        assert_eq!(variant, tiano::Variant::Efi);
        let error = efi_decompress(tiano::tests::SMALL_TIANO, 100).unwrap_err();
        assert_eq!(error.code, Code::FormatUnsupported);
    }

    #[test]
    fn identity_names_the_bundled_library() {
        assert!(identity().starts_with("liblzma 5."), "{}", identity());
    }
}
