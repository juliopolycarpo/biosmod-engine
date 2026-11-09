//! Project-owned interface to the LZMA ("LZMA alone") and CRC32 codecs.
//!
//! Encoding uses the same liblzma algorithm and options as the reference
//! implementation, so identical inputs produce identical compressed streams.
//! Changing the codec build can change output bytes; plans record
//! [`identity`] and refuse to apply under a different one.

use crate::error::{Code, Error, Result};
use liblzma::stream::{Action, LzmaOptions, MatchFinder, Mode, Status, Stream};

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
        MAX_DECODED
    } else {
        usize::try_from(declared).unwrap_or(usize::MAX)
    };
    if limit > MAX_DECODED {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!(
                "LZMA stream declares {declared:#x} decoded bytes: expected at most {MAX_DECODED:#x}"
            ),
        ));
    }
    let mut decoder = Stream::new_lzma_decoder(DECODER_MEMLIMIT).map_err(lzma_error)?;
    let mut output = Vec::with_capacity(limit.min(MAX_DECODED));
    let mut consumed = 0usize;
    loop {
        if output.len() == output.capacity() {
            if output.len() >= MAX_DECODED {
                return Err(Error::new(
                    Code::FormatUnsupported,
                    format!("LZMA stream: decoded size exceeds {MAX_DECODED:#x}"),
                ));
            }
            output.reserve(output.len().max(4096).min(MAX_DECODED - output.len()));
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

    #[test]
    fn identity_names_the_bundled_library() {
        assert!(identity().starts_with("liblzma 5."), "{}", identity());
    }
}
