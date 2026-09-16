//! Minimal, dependency-free byte/text encoders used for the *non-secret* wire representations
//! in this crate: standard Base64 (with padding, RFC 4648 §4) for salts and wrapped keys
//! inside JSON, and Crockford Base32 for recovery codes.
//!
//! Neither of these is a cryptographic primitive — they are public, well-known text encodings
//! applied to values that are already public (a salt) or already AEAD ciphertext (a wrapped
//! key) or about to become an AEAD input elsewhere (a recovery code, which is only ever used
//! as raw key-derivation input, never compared or transmitted as plaintext secret bytes by
//! this module). `docs/CRYPTO.md` §1 does not list a base64/base32 crate among the approved
//! `RustCrypto` primitives, so rather than adding a dependency for ~60 lines of table-driven
//! encoding, it is implemented here directly.

const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard Base64 (RFC 4648 §4), padded, with the `+/` alphabet — matches
/// `docs/ARCHITECTURE.md` §3 ("Base64 in JSON is standard alphabet with padding").
pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied();
        let b2 = chunk.get(2).copied();
        let n =
            (u32::from(b0) << 16) | (u32::from(b1.unwrap_or(0)) << 8) | u32::from(b2.unwrap_or(0));
        out.push(STD_ALPHABET[usize::try_from((n >> 18) & 0x3f).unwrap_or(0)] as char);
        out.push(STD_ALPHABET[usize::try_from((n >> 12) & 0x3f).unwrap_or(0)] as char);
        out.push(if b1.is_some() {
            STD_ALPHABET[usize::try_from((n >> 6) & 0x3f).unwrap_or(0)] as char
        } else {
            '='
        });
        out.push(if b2.is_some() {
            STD_ALPHABET[usize::try_from(n & 0x3f).unwrap_or(0)] as char
        } else {
            '='
        });
    }
    out
}

/// Decodes standard, padded Base64. Returns `None` (never panics) on any malformed input:
/// wrong overall length, an out-of-alphabet character, or padding in the wrong place.
pub(crate) fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut vals = [0u32; 4];
        let mut pad = 0usize;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                pad += 1;
                vals[i] = 0;
            } else {
                if pad > 0 {
                    // '=' padding must be a trailing run, not interleaved with data chars.
                    return None;
                }
                vals[i] = base64_char_value(c)?;
            }
        }
        if pad > 2 {
            return None;
        }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push(u8::try_from((n >> 16) & 0xff).ok()?);
        if pad < 2 {
            out.push(u8::try_from((n >> 8) & 0xff).ok()?);
        }
        if pad < 1 {
            out.push(u8::try_from(n & 0xff).ok()?);
        }
    }
    Some(out)
}

fn base64_char_value(c: u8) -> Option<u32> {
    STD_ALPHABET
        .iter()
        .position(|&x| x == c)
        .map(|p| u32::try_from(p).unwrap_or(0))
}

/// Crockford Base32 alphabet (32 symbols, excludes `I`, `L`, `O`, `U` to avoid transcription
/// mistakes) — see `docs/CRYPTO.md` §3 for recovery-code formatting.
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encodes `input` as unpadded Crockford Base32 (uppercase, no grouping — grouping is a
/// display concern handled by the `recovery` module).
pub(crate) fn crockford_encode(input: &[u8]) -> String {
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    for &byte in input {
        bits = (bits << 8) | u32::from(byte);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = (bits >> bit_count) & 0x1f;
            out.push(CROCKFORD_ALPHABET[usize::try_from(idx).unwrap_or(0)] as char);
        }
    }
    if bit_count > 0 {
        let remainder = bits & ((1u32 << bit_count) - 1);
        let idx = (remainder << (5 - bit_count)) & 0x1f;
        out.push(CROCKFORD_ALPHABET[usize::try_from(idx).unwrap_or(0)] as char);
    }
    out
}

/// Decodes unpadded Crockford Base32 (must already be uppercase, no separators). Returns
/// `None` on any invalid character or on non-zero trailing padding bits (a tamper/typo
/// signal), never panics.
pub(crate) fn crockford_decode(input: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    for c in input.chars() {
        let val = crockford_char_value(c)?;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            let byte = (bits >> bit_count) & 0xff;
            out.push(u8::try_from(byte).ok()?);
        }
    }
    if bit_count > 0 {
        let remainder = bits & ((1u32 << bit_count) - 1);
        if remainder != 0 {
            return None;
        }
    }
    Some(out)
}

fn crockford_char_value(c: char) -> Option<u32> {
    let c = c.to_ascii_uppercase();
    CROCKFORD_ALPHABET
        .iter()
        .position(|&x| x as char == c)
        .map(|p| u32::try_from(p).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::{base64_decode, base64_encode, crockford_decode, crockford_encode};

    #[test]
    #[allow(clippy::cast_possible_truncation)] // test data, `len` is bounded by the loop below
    fn base64_round_trips_all_padding_cases() {
        for len in 0..16usize {
            let input: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let encoded = base64_encode(&input);
            let decoded = base64_decode(&encoded).expect("valid base64 must decode");
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn base64_decode_rejects_garbage() {
        assert_eq!(base64_decode(""), Some(Vec::new())); // empty is valid base64 of 0 bytes
        assert!(base64_decode("a").is_none()); // wrong length
        assert!(base64_decode("!!!!").is_none()); // invalid chars
        assert!(base64_decode("A=AA").is_none()); // padding not trailing
    }

    #[test]
    fn crockford_round_trips_32_bytes() {
        let input = [0x42u8; 32];
        let encoded = crockford_encode(&input);
        assert_eq!(
            encoded.len(),
            52,
            "32 bytes must encode to 52 Crockford symbols"
        );
        let decoded = crockford_decode(&encoded).expect("valid crockford must decode");
        assert_eq!(decoded, input);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // test data, values are small and bounded
    fn crockford_round_trips_boundary_lengths() {
        for len in 0..40usize {
            let input: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let encoded = crockford_encode(&input);
            let decoded = crockford_decode(&encoded).expect("valid crockford must decode");
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn crockford_decode_is_case_insensitive_and_rejects_bad_chars() {
        let input = [1u8, 2, 3, 4, 5];
        let encoded = crockford_encode(&input);
        let lower = encoded.to_lowercase();
        assert_eq!(crockford_decode(&lower), Some(input.to_vec()));
        assert!(crockford_decode("!!!!!").is_none());
    }
}
