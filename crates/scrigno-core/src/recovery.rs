//! Recovery code: 32 random bytes shown to the user once, formatted as Crockford Base32 in
//! dash-separated groups of 4 characters (`docs/CRYPTO.md` §3).
//!
//! The code itself is never stored in plaintext; only a [`crate::keys::Kek`] derived from it
//! via [`crate::kdf::derive_kek`] ever touches disk, inside a `recovery`-kind
//! [`crate::keyslot::Keyslot`]. Callers are responsible for never logging or persisting the
//! code text itself.

use crate::codec::{crockford_decode, crockford_encode};
use crate::error::Error;
use crate::rng::fill_random;

const CODE_LEN: usize = 32;
const GROUP_LEN: usize = 4;

/// Generates a new recovery code: 32 random bytes from `OsRng`, formatted as Crockford Base32
/// in dash-separated groups of 4 characters (52 characters total, e.g. `ABCD-EFGH-…`).
///
/// # Errors
/// Returns [`Error::Internal`] if `OsRng` fails.
pub fn generate_code() -> Result<String, Error> {
    let mut bytes = [0u8; CODE_LEN];
    fill_random(&mut bytes)?;
    Ok(format_grouped(&crockford_encode(&bytes)))
}

/// Parses a recovery code back into its 32 raw bytes.
///
/// Accepts the dash-separated grouped form produced by [`generate_code`]; dashes and
/// surrounding whitespace are stripped and matching is case-insensitive, so a user retyping
/// the code without its dashes (or in lowercase) still works.
///
/// # Errors
/// Returns [`Error::InvalidRecoveryCode`] if, after stripping separators, the input contains
/// a character outside the Crockford alphabet or does not decode to exactly 32 bytes.
pub fn parse_code(code: &str) -> Result<[u8; CODE_LEN], Error> {
    let cleaned: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let decoded = crockford_decode(&cleaned).ok_or(Error::InvalidRecoveryCode)?;
    let bytes: [u8; CODE_LEN] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidRecoveryCode)?;
    Ok(bytes)
}

fn format_grouped(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + raw.len() / GROUP_LEN);
    for (i, ch) in raw.chars().enumerate() {
        if i > 0 && i % GROUP_LEN == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_has_expected_shape() {
        let code = generate_code().unwrap();
        assert_eq!(
            code.len(),
            52 + 12,
            "52 symbols + 12 dashes for 13 groups of 4"
        );
        assert!(code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        for group in code.split('-') {
            assert_eq!(group.len(), GROUP_LEN);
        }
    }

    #[test]
    fn round_trips() {
        let code = generate_code().unwrap();
        let bytes = parse_code(&code).unwrap();
        // Re-encoding the parsed bytes must reproduce the same code (mod grouping/case).
        let reencoded = generate_code_from_bytes_for_test(&bytes);
        assert_eq!(reencoded, code);
    }

    fn generate_code_from_bytes_for_test(bytes: &[u8; CODE_LEN]) -> String {
        format_grouped(&crockford_encode(bytes))
    }

    #[test]
    fn parse_is_case_insensitive_and_ignores_dashes_and_whitespace() {
        let code = generate_code().unwrap();
        let messy = format!("  {} ", code.to_lowercase());
        assert_eq!(parse_code(&messy).unwrap(), parse_code(&code).unwrap());
    }

    #[test]
    fn parse_rejects_invalid_characters() {
        assert_eq!(
            parse_code("not-a-valid-code-!!!!").unwrap_err(),
            Error::InvalidRecoveryCode
        );
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert_eq!(
            parse_code("ABCD-EFGH").unwrap_err(),
            Error::InvalidRecoveryCode
        );
    }

    #[test]
    fn distinct_codes_each_call() {
        assert_ne!(generate_code().unwrap(), generate_code().unwrap());
    }
}
