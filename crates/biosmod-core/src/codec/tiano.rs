//! Decoder for the EFI 1.1 and Tiano compression of EFI compression sections.
//!
//! The format is the LZ77 plus Huffman scheme of EDK II `UefiDecompressLib`.
//! Both variants share one bitstream; the Tiano one reads the position-set
//! symbol count with 5 bits where EFI 1.1 reads 4. The stream starts with two
//! little-endian `u32` values (compressed size, original size).
//!
//! Example: `let (plain, variant) = decompress(&section_payload, 1 << 20)?;`

use crate::error::{Code, Error, Result};

/// Which bit width the position-set symbol count used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// EFI 1.1: 4-bit position-set count.
    Efi,
    /// Tiano: 5-bit position-set count.
    Tiano,
}

impl Variant {
    fn position_count_bits(self) -> u32 {
        match self {
            Variant::Efi => 4,
            Variant::Tiano => 5,
        }
    }

    /// Display name used in diagnostics and reports.
    pub fn label(self) -> &'static str {
        match self {
            Variant::Efi => "EFI 1.1 compression",
            Variant::Tiano => "Tiano compression",
        }
    }
}

const BIT_BUFFER_BITS: u32 = 32;
const THRESHOLD: usize = 3;
/// Character-and-length set: 256 literals plus match lengths 3..=256.
const NC: usize = 0xFF + 256 + 2 - THRESHOLD;
const CBIT: u32 = 9;
const MAX_POSITION_SET: usize = 31;
const TBIT: u32 = 5;
/// Extra set: code-length codes.
const NT: usize = 16 + 3;
/// Largest of the T and P sets.
const NPT: usize = 0x20;
const C_TABLE_BITS: u32 = 12;
const PT_TABLE_BITS: u32 = 8;
const TREE_NODES: usize = 2 * NC - 1;
/// Zero bytes the decoder may read past the stream: its 32-bit look-ahead plus slack.
const MAX_ZERO_FILL: usize = 8;

/// Decode a stream with the first variant that succeeds, trying Tiano and then EFI 1.1.
///
/// The bitstream has no checksum, so a stream of one variant can decode to
/// garbage as the other; use [`decompress_candidates`] when the caller can
/// validate the output. `limit` caps the declared original size. The sizes in
/// the stream header are checked against the input and `limit` before any
/// output is reserved.
///
/// Example: `let (plain, variant) = decompress(&payload, 64 << 20)?;`
pub fn decompress(stream: &[u8], limit: usize) -> Result<(Vec<u8>, Variant)> {
    Ok(decompress_candidates(stream, limit)?.remove(0))
}

/// Every variant that decodes the stream without error, Tiano first.
///
/// Fails when none does, naming each variant's error. The result is never empty.
///
/// Example: `for (plain, variant) in decompress_candidates(&payload, 1 << 20)? { /* validate */ }`
pub fn decompress_candidates(stream: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Variant)>> {
    let (data, original) = split_header(stream, limit)?;
    let mut decoded = Vec::new();
    let mut errors = Vec::new();
    for variant in [Variant::Tiano, Variant::Efi] {
        match Decoder::new(data, variant).run(original) {
            Ok(plain) => decoded.push((plain, variant)),
            Err(error) => errors.push(format!("{}: {}", variant.label(), error.message)),
        }
    }
    if decoded.is_empty() {
        return Err(Error::new(
            Code::FormatInvalid,
            format!(
                "EFI compression: neither variant decodes | {}",
                errors.join(" | ")
            ),
        ));
    }
    Ok(decoded)
}

/// Decode a stream as one specific variant.
///
/// Example: `let plain = decompress_as(&payload, Variant::Efi, 1 << 20)?;`
pub fn decompress_as(stream: &[u8], variant: Variant, limit: usize) -> Result<Vec<u8>> {
    let (data, original) = split_header(stream, limit)?;
    Decoder::new(data, variant).run(original)
}

/// Validate the 8-byte header; return the compressed bytes and the original size.
fn split_header(stream: &[u8], limit: usize) -> Result<(&[u8], usize)> {
    if stream.len() < 8 {
        return Err(invalid(format!(
            "stream of {} bytes: expected an 8-byte header",
            stream.len()
        )));
    }
    let compressed = u32::from_le_bytes(stream[0..4].try_into().expect("four bytes")) as usize;
    let original = u32::from_le_bytes(stream[4..8].try_into().expect("four bytes")) as usize;
    if original > limit {
        return Err(Error::new(
            Code::FormatUnsupported,
            format!(
                "EFI compression: stream declares {original:#x} decoded bytes | expected at most {limit:#x}"
            ),
        ));
    }
    let data = &stream[8..];
    if compressed > data.len() {
        return Err(invalid(format!(
            "header compressed size: expected at most {:#x} | received {compressed:#x}",
            data.len()
        )));
    }
    Ok((&data[..compressed], original))
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(
        Code::FormatInvalid,
        format!("EFI compression: {}", message.into()),
    )
}

struct Decoder<'a> {
    source: &'a [u8],
    position: usize,
    zero_filled: usize,
    bit_buffer: u32,
    sub_bit_buffer: u32,
    bit_count: u32,
    block_size: u16,
    position_bits: u32,
    c_len: [u8; NC],
    pt_len: [u8; NPT],
    c_table: [u16; 1 << C_TABLE_BITS],
    pt_table: [u16; 1 << PT_TABLE_BITS],
    left: [u16; TREE_NODES],
    right: [u16; TREE_NODES],
}

impl<'a> Decoder<'a> {
    fn new(source: &'a [u8], variant: Variant) -> Self {
        let mut decoder = Decoder {
            source,
            position: 0,
            zero_filled: 0,
            bit_buffer: 0,
            sub_bit_buffer: 0,
            bit_count: 0,
            block_size: 0,
            position_bits: variant.position_count_bits(),
            c_len: [0; NC],
            pt_len: [0; NPT],
            c_table: [0; 1 << C_TABLE_BITS],
            pt_table: [0; 1 << PT_TABLE_BITS],
            left: [0; TREE_NODES],
            right: [0; TREE_NODES],
        };
        decoder.fill(BIT_BUFFER_BITS);
        decoder
    }

    /// Shift `count` bits out of the buffer and refill it from the source.
    fn fill(&mut self, mut count: u32) {
        self.bit_buffer = self.bit_buffer.checked_shl(count).unwrap_or(0);
        while count > self.bit_count {
            count -= self.bit_count;
            self.bit_buffer |= self.sub_bit_buffer.checked_shl(count).unwrap_or(0);
            if let Some(byte) = self.source.get(self.position) {
                self.sub_bit_buffer = u32::from(*byte);
                self.position += 1;
            } else {
                self.sub_bit_buffer = 0;
                self.zero_filled += 1;
            }
            self.bit_count = 8;
        }
        self.bit_count -= count;
        self.bit_buffer |= self.sub_bit_buffer >> self.bit_count;
    }

    fn peek(&self, count: u32) -> usize {
        (self.bit_buffer >> (BIT_BUFFER_BITS - count)) as usize
    }

    fn bits(&mut self, count: u32) -> usize {
        if count == 0 {
            return 0;
        }
        let value = self.peek(count);
        self.fill(count);
        value
    }

    fn check_stream_end(&self) -> Result<()> {
        if self.zero_filled > MAX_ZERO_FILL {
            return Err(invalid(format!(
                "stream ends inside the data: read {} bytes past the {} stored",
                self.zero_filled,
                self.source.len()
            )));
        }
        Ok(())
    }

    /// Read the code lengths of the T (`count_set == NT`) or P set and build its table.
    fn read_pt_lengths(&mut self, symbols: usize, bits: u32, special: Option<usize>) -> Result<()> {
        let number = self.bits(bits);
        if number == 0 {
            let only = self.bits(bits);
            self.pt_len[..symbols].fill(0);
            self.pt_table.fill(only as u16);
            return Ok(());
        }
        if number > symbols {
            return Err(invalid(format!(
                "position or extra set: expected at most {symbols} symbols | received {number}"
            )));
        }
        let mut index = 0;
        while index < number {
            let mut length = self.peek(3);
            if length == 7 {
                let mut mask = 1u32 << (BIT_BUFFER_BITS - 1 - 3);
                while mask & self.bit_buffer != 0 {
                    mask >>= 1;
                    length += 1;
                }
            }
            self.fill(if length < 7 { 3 } else { length as u32 - 3 });
            if length > 16 {
                return Err(invalid(format!(
                    "code length: expected at most 16 | received {length}"
                )));
            }
            self.pt_len[index] = length as u8;
            index += 1;
            if Some(index) == special {
                let zeros = self.bits(2);
                if index + zeros > symbols {
                    return Err(invalid("extra set zero run overruns its symbol count"));
                }
                self.pt_len[index..index + zeros].fill(0);
                index += zeros;
            }
        }
        self.pt_len[index..symbols].fill(0);
        let lengths = self.pt_len;
        make_table(
            symbols,
            &lengths[..symbols],
            PT_TABLE_BITS,
            &mut self.pt_table,
            &mut self.left,
            &mut self.right,
        )
    }

    fn read_c_lengths(&mut self) -> Result<()> {
        let number = self.bits(CBIT);
        if number == 0 {
            let only = self.bits(CBIT);
            if only >= NC {
                return Err(invalid(format!(
                    "single character code: expected below {NC} | received {only}"
                )));
            }
            self.c_len.fill(0);
            self.c_table.fill(only as u16);
            return Ok(());
        }
        if number > NC {
            return Err(invalid(format!(
                "character set: expected at most {NC} symbols | received {number}"
            )));
        }
        let mut index = 0;
        while index < number {
            let mut symbol = usize::from(self.pt_table[self.peek(8)]);
            if symbol >= NT {
                symbol = self.walk_tree(symbol, 8, NT)?;
            }
            self.fill(u32::from(self.pt_len[symbol]));
            if symbol <= 2 {
                let run = match symbol {
                    0 => 1,
                    1 => self.bits(4) + 3,
                    _ => self.bits(CBIT) + 20,
                };
                if index + run > NC {
                    return Err(invalid(format!(
                        "character set zero run: expected to end within {NC} symbols | received {}",
                        index + run
                    )));
                }
                self.c_len[index..index + run].fill(0);
                index += run;
            } else {
                self.c_len[index] = (symbol - 2) as u8;
                index += 1;
            }
        }
        self.c_len[index..].fill(0);
        let lengths = self.c_len;
        make_table(
            NC,
            &lengths,
            C_TABLE_BITS,
            &mut self.c_table,
            &mut self.left,
            &mut self.right,
        )
    }

    /// Follow tree nodes from `node` until reaching a leaf below `leaves`.
    fn walk_tree(&self, mut node: usize, consumed: u32, leaves: usize) -> Result<usize> {
        let mut mask = 1u32 << (BIT_BUFFER_BITS - 1 - consumed);
        let mut steps = 0;
        while node >= leaves {
            if node >= TREE_NODES || mask == 0 || steps > 16 {
                return Err(invalid(format!(
                    "code tree node: expected a leaf below {leaves} within 16 bits | received node {node}"
                )));
            }
            node = usize::from(if self.bit_buffer & mask != 0 {
                self.right[node]
            } else {
                self.left[node]
            });
            mask >>= 1;
            steps += 1;
        }
        Ok(node)
    }

    fn decode_c(&mut self) -> Result<usize> {
        if self.block_size == 0 {
            self.block_size = self.bits(16) as u16;
            self.read_pt_lengths(NT, TBIT, Some(3))?;
            self.read_c_lengths()?;
            self.read_pt_lengths(MAX_POSITION_SET, self.position_bits, None)?;
            self.check_stream_end()?;
        }
        self.block_size = self.block_size.wrapping_sub(1);
        let mut symbol = usize::from(self.c_table[self.peek(C_TABLE_BITS)]);
        if symbol >= NC {
            symbol = self.walk_tree(symbol, C_TABLE_BITS, NC)?;
        }
        self.fill(u32::from(self.c_len[symbol]));
        Ok(symbol)
    }

    fn decode_p(&mut self) -> Result<usize> {
        let mut symbol = usize::from(self.pt_table[self.peek(PT_TABLE_BITS)]);
        if symbol >= MAX_POSITION_SET {
            symbol = self.walk_tree(symbol, PT_TABLE_BITS, MAX_POSITION_SET)?;
        }
        self.fill(u32::from(self.pt_len[symbol]));
        if symbol > 1 {
            let extra = self.bits(symbol as u32 - 1);
            return Ok((1usize << (symbol - 1)) + extra);
        }
        Ok(symbol)
    }

    fn run(&mut self, original: usize) -> Result<Vec<u8>> {
        // Grow with the data: a forged header must not reserve its full claim.
        let mut out: Vec<u8> = Vec::with_capacity(original.min(1 << 20));
        while out.len() < original {
            let symbol = self.decode_c()?;
            if symbol < 256 {
                out.push(symbol as u8);
                continue;
            }
            let length = symbol - (256 - THRESHOLD);
            let distance = self.decode_p()? + 1;
            if distance > out.len() {
                return Err(invalid(format!(
                    "match at output {:#x}: expected distance within the decoded data | received {distance:#x}",
                    out.len()
                )));
            }
            if out.len() + length > original {
                return Err(invalid(format!(
                    "match at output {:#x}: expected to end within the declared {original:#x} bytes | received length {length}",
                    out.len()
                )));
            }
            for _ in 0..length {
                out.push(out[out.len() - distance]);
            }
        }
        self.check_stream_end()?;
        Ok(out)
    }
}

/// Build the lookup table and overflow tree for canonical code `lengths`.
///
/// Codes up to `table_bits` long index `table` directly; longer ones store a
/// tree node (numbered from `lengths.len()`) in `left` and `right`.
fn make_table(
    symbols: usize,
    lengths: &[u8],
    table_bits: u32,
    table: &mut [u16],
    left: &mut [u16; TREE_NODES],
    right: &mut [u16; TREE_NODES],
) -> Result<()> {
    let mut count = [0u32; 17];
    for length in lengths {
        count[usize::from(*length)] += 1;
    }
    count[0] = 0;
    let mut start = [0u32; 18];
    for bits in 1..=16 {
        start[bits + 1] = start[bits] + (count[bits] << (16 - bits));
    }
    if start[17] != 0 && start[17] != 1 << 16 {
        return Err(invalid(format!(
            "code lengths: expected a complete prefix code (65536) | received {} over {symbols} symbols",
            start[17]
        )));
    }
    let shift = 16 - table_bits;
    let mut weight = [0u32; 17];
    for bits in 1..=16usize {
        if bits as u32 <= table_bits {
            start[bits] >>= shift;
            weight[bits] = 1 << (table_bits - bits as u32);
        } else {
            weight[bits] = 1 << (16 - bits);
        }
    }
    let table_size = 1usize << table_bits;
    let first_unused = (start[table_bits as usize + 1] >> shift) as usize;
    if first_unused != 0 {
        table[first_unused.min(table_size)..table_size].fill(0);
    }
    let mut next_node = symbols;
    let mask = 1u32 << (15 - table_bits);
    for (symbol, length) in lengths.iter().enumerate() {
        let length = usize::from(*length);
        if length == 0 {
            continue;
        }
        let next_code = start[length] + weight[length];
        if length as u32 <= table_bits {
            if next_code as usize > table_size {
                return Err(invalid("code lengths overflow the lookup table"));
            }
            table[start[length] as usize..next_code as usize].fill(symbol as u16);
        } else {
            let mut code = start[length];
            let mut slot = Slot::Table((code >> shift) as usize);
            for _ in 0..length as u32 - table_bits {
                let current = slot.get(table, left, right);
                let node = if current == 0 {
                    if next_node >= TREE_NODES {
                        return Err(invalid("code tree: more nodes than the format allows"));
                    }
                    left[next_node] = 0;
                    right[next_node] = 0;
                    slot.set(table, left, right, next_node as u16);
                    next_node += 1;
                    next_node - 1
                } else {
                    usize::from(current)
                };
                if node >= TREE_NODES {
                    return Err(invalid("code tree: node index outside the tree"));
                }
                slot = if code & mask != 0 {
                    Slot::Right(node)
                } else {
                    Slot::Left(node)
                };
                code <<= 1;
            }
            slot.set(table, left, right, symbol as u16);
        }
        start[length] = next_code;
    }
    Ok(())
}

/// A writable location in the lookup table or the overflow tree.
enum Slot {
    Table(usize),
    Left(usize),
    Right(usize),
}

impl Slot {
    fn get(&self, table: &[u16], left: &[u16; TREE_NODES], right: &[u16; TREE_NODES]) -> u16 {
        match *self {
            Slot::Table(i) => table[i],
            Slot::Left(i) => left[i],
            Slot::Right(i) => right[i],
        }
    }

    fn set(
        &self,
        table: &mut [u16],
        left: &mut [u16; TREE_NODES],
        right: &mut [u16; TREE_NODES],
        value: u16,
    ) {
        match *self {
            Slot::Table(i) => table[i] = value,
            Slot::Left(i) => left[i] = value,
            Slot::Right(i) => right[i] = value,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const SMALL_EFI: &[u8] = include_bytes!("../../tests/fixtures/small.efi");
    pub(crate) const SMALL_TIANO: &[u8] = include_bytes!("../../tests/fixtures/small.tiano");
    const MULTIBLOCK_EFI: &[u8] = include_bytes!("../../tests/fixtures/multiblock.efi");
    const MULTIBLOCK_TIANO: &[u8] = include_bytes!("../../tests/fixtures/multiblock.tiano");

    /// The text the fixtures were compressed from, rebuilt from its generator.
    ///
    /// The fixtures come from EDK II's `EfiCompress` and `TianoCompress` (through
    /// the `uefi_firmware` Python extension) over this deterministic word list.
    pub(crate) fn fixture_text(size: usize, seed: u64) -> Vec<u8> {
        const WORDS: [&str; 24] = [
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
            "lambda", "mu", "nu", "xi", "omicron", "pi", "rho", "sigma", "tau", "upsilon", "phi",
            "chi", "psi", "omega",
        ];
        let (mut state, mut words, mut total) = (seed, Vec::<String>::new(), 0usize);
        while total < size {
            state = (state * 1_103_515_245 + 12_345) & 0x7fff_ffff;
            let mut word = WORDS[((state >> 8) % 24) as usize].to_string();
            if state % 5 == 0 {
                word += &((state >> 4) % 997).to_string();
            }
            total += word.len() + 1;
            words.push(word);
        }
        let mut text = words.join(" ").into_bytes();
        text.truncate(size);
        text
    }

    #[test]
    fn fixture_text_is_deterministic_and_sized() {
        assert_eq!(fixture_text(300, 1).len(), 300);
        assert_eq!(fixture_text(300, 1), fixture_text(300, 1));
        assert_ne!(fixture_text(300, 1), fixture_text(300, 2));
    }

    #[test]
    fn decodes_edk2_efi_and_tiano_streams_and_names_the_variant() {
        let small = fixture_text(300, 1);
        let large = fixture_text(60_000, 7);
        for (stream, plain, variant) in [
            (SMALL_EFI, &small, Variant::Efi),
            (SMALL_TIANO, &small, Variant::Tiano),
            (MULTIBLOCK_EFI, &large, Variant::Efi),
            (MULTIBLOCK_TIANO, &large, Variant::Tiano),
        ] {
            let (decoded, detected) = decompress(stream, 1 << 20).expect("fixture decodes");
            assert_eq!(
                detected,
                variant,
                "variant of a {}-byte stream",
                stream.len()
            );
            assert!(
                decoded == *plain,
                "{variant:?}: decoded bytes differ from the source text"
            );
        }
    }

    #[test]
    fn a_stream_never_decodes_as_the_other_variant_to_the_same_text() {
        let small = fixture_text(300, 1);
        for (stream, wrong) in [(SMALL_EFI, Variant::Tiano), (SMALL_TIANO, Variant::Efi)] {
            let same = decompress_as(stream, wrong, 1 << 20).is_ok_and(|plain| plain == small);
            assert!(
                !same,
                "expected {wrong:?} not to decode the other variant's stream"
            );
        }
    }

    #[test]
    fn decompress_as_decodes_the_matching_variant() {
        let small = fixture_text(300, 1);
        assert_eq!(
            decompress_as(SMALL_EFI, Variant::Efi, 1 << 20).unwrap(),
            small
        );
        assert_eq!(
            decompress_as(SMALL_TIANO, Variant::Tiano, 1 << 20).unwrap(),
            small
        );
    }

    #[test]
    fn candidates_include_the_true_variant_exactly_once() {
        let small = fixture_text(300, 1);
        for (stream, variant) in [(SMALL_EFI, Variant::Efi), (SMALL_TIANO, Variant::Tiano)] {
            let candidates = decompress_candidates(stream, 1 << 20).unwrap();
            assert!(
                candidates.iter().any(|(p, v)| *v == variant && *p == small),
                "expected {variant:?} among the candidates"
            );
            assert_eq!(
                candidates.iter().filter(|(p, _)| *p == small).count(),
                1,
                "exactly one candidate reproduces the text"
            );
        }
    }

    #[test]
    fn candidates_error_names_both_variants() {
        // Cut the data and make the header agree, so both variants run out of bits.
        let mut cut = SMALL_TIANO[..60].to_vec();
        cut[0..4].copy_from_slice(&52u32.to_le_bytes());
        let error = decompress_candidates(&cut, 1 << 20).unwrap_err();
        assert!(
            error
                .message
                .contains("neither variant decodes | Tiano compression:")
                && error.message.contains("EFI 1.1 compression:"),
            "{error}"
        );
    }

    #[test]
    fn variant_labels_name_the_format() {
        assert_eq!(Variant::Efi.label(), "EFI 1.1 compression");
        assert_eq!(Variant::Tiano.label(), "Tiano compression");
    }

    #[test]
    fn truncated_streams_fail_with_a_named_error_not_a_panic() {
        for cut in [0, 4, 7, 9, 40, SMALL_TIANO.len() - 1] {
            let error = decompress(&SMALL_TIANO[..cut], 1 << 20).unwrap_err();
            assert_eq!(error.code, Code::FormatInvalid, "cut at {cut}: {error}");
            assert!(error.message.contains("EFI compression"), "{error}");
        }
    }

    #[test]
    fn corrupted_bytes_never_panic_and_mostly_fail() {
        let mut failures = 0;
        let flips = SMALL_TIANO.len() - 8;
        for index in 8..SMALL_TIANO.len() {
            let mut stream = SMALL_TIANO.to_vec();
            stream[index] ^= 0xFF;
            // A flip in an unused block-size bit or a literal can still decode.
            failures += decompress(&stream, 1 << 20).is_err() as usize;
        }
        assert!(
            failures * 2 > flips,
            "single-byte flips rejected: expected more than {} | received {failures}",
            flips / 2
        );
    }

    #[test]
    fn declared_size_beyond_the_limit_is_refused_before_decoding() {
        let mut stream = SMALL_TIANO.to_vec();
        stream[4..8].copy_from_slice(&0x4000_0000u32.to_le_bytes());
        let error = decompress(&stream, 0x400_0000).unwrap_err();
        assert_eq!(error.code, Code::FormatUnsupported);
        assert!(
            error
                .message
                .contains("declares 0x40000000 decoded bytes | expected at most 0x4000000"),
            "{error}"
        );
    }

    #[test]
    fn header_compressed_size_beyond_the_input_is_refused() {
        let mut stream = SMALL_TIANO.to_vec();
        stream[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        let error = decompress(&stream, 1 << 20).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid);
        assert!(
            error
                .message
                .contains("header compressed size: expected at most"),
            "{error}"
        );
    }

    #[test]
    fn expansion_bomb_with_a_tiny_stream_stops_at_the_declared_size() {
        // The stream really holds 300 bytes; a header claiming 10 MiB must run
        // out of data (error), not allocate or loop for the claimed size.
        let mut stream = SMALL_TIANO.to_vec();
        stream[4..8].copy_from_slice(&(10u32 << 20).to_le_bytes());
        let error = decompress(&stream, 64 << 20).unwrap_err();
        assert_eq!(error.code, Code::FormatInvalid, "{error}");
    }

    #[test]
    fn make_table_rejects_an_incomplete_code() {
        let mut table = [0u16; 1 << PT_TABLE_BITS];
        let (mut left, mut right) = ([0u16; TREE_NODES], [0u16; TREE_NODES]);
        let error = make_table(
            4,
            &[1, 0, 0, 0],
            PT_TABLE_BITS,
            &mut table,
            &mut left,
            &mut right,
        )
        .unwrap_err();
        assert!(
            error
                .message
                .contains("expected a complete prefix code (65536) | received 32768"),
            "{error}"
        );
    }
}
