//! Passphrase/token acquisition for the CLI. Per this milestone's brief: never accept either as
//! a positional argument (would show up in `ps`); read from a `--*-file`, an env var, or (for
//! the passphrase only) an interactive, echo-suppressing prompt.

use std::path::Path;

use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::CliError;

/// Reads the first line of `path` (trailing newline/CR stripped) as a secret.
fn read_secret_file(path: &Path) -> Result<SecretString, CliError> {
    // Both intermediate buffers hold a copy of the secret; zeroize them on every exit path.
    let contents =
        Zeroizing::new(std::fs::read_to_string(path).map_err(|_| CliError::SecretFileUnreadable)?);
    let first_line = Zeroizing::new(contents.lines().next().unwrap_or("").to_string());
    if first_line.is_empty() {
        return Err(CliError::SecretFileUnreadable);
    }
    Ok(SecretString::from(first_line.to_string()))
}

/// Resolves the vault passphrase: `--passphrase-file`, else `SCRIGNO_PASSPHRASE`, else an
/// interactive prompt (asked twice and compared when `confirm` is set, for `create`).
pub fn resolve_passphrase(
    passphrase_file: Option<&Path>,
    confirm: bool,
) -> Result<SecretString, CliError> {
    if let Some(path) = passphrase_file {
        return read_secret_file(path);
    }
    if let Ok(value) = std::env::var("SCRIGNO_PASSPHRASE")
        && !value.is_empty()
    {
        return Ok(SecretString::from(value));
    }

    // Zeroizing so both prompt results are wiped on drop, including on the mismatch
    // early-return below.
    let first = Zeroizing::new(
        rpassword::prompt_password("Passphrase: ").map_err(|_| CliError::PromptFailed)?,
    );
    if confirm {
        let second = Zeroizing::new(
            rpassword::prompt_password("Confirm passphrase: ")
                .map_err(|_| CliError::PromptFailed)?,
        );
        if *first != *second {
            return Err(CliError::PassphraseMismatch);
        }
    }
    Ok(SecretString::from(first.to_string()))
}

/// Resolves the server API bearer token: `--token-file`, else `SCRIGNO_API_TOKEN`. Never
/// prompted interactively (it isn't a secret the user is expected to type from memory).
pub fn resolve_token(token_file: Option<&Path>) -> Result<SecretString, CliError> {
    if let Some(path) = token_file {
        return read_secret_file(path);
    }
    if let Ok(value) = std::env::var("SCRIGNO_API_TOKEN")
        && !value.is_empty()
    {
        return Ok(SecretString::from(value));
    }
    Err(CliError::MissingToken)
}
