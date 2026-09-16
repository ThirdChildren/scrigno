//! `scrigno`: headless CLI over `scrigno-client`. This is the system's end-to-end test harness
//! (`docs/ARCHITECTURE.md`, `scripts/e2e.sh`) — every capability exists here before it gets a
//! screen. Thin by design: every subcommand parses its arguments, calls exactly one
//! `scrigno-client` `Vault`/`UnlockedVault` method, and prints the result. No business logic
//! lives in this crate.
//!
//! Each invocation is a fresh process: `unlock` (and every command that needs the master key)
//! re-derives it from the passphrase every time — nothing is cached across invocations. This is
//! deliberately simple/slow (acceptable for a test tool, per this milestone's brief), not how
//! the Tauri app will behave (M4 keeps a long-lived `UnlockedVault` in memory).

mod secrets;

use std::io::Write as _;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use scrigno_client::{ClientError, DocSummary, UnlockedVault, Vault};
use secrecy::SecretString;
use uuid::Uuid;

/// Dev default from `docs/ARCHITECTURE.md §7`; overridden by `--server` or, for a data dir
/// already bound to a vault, whatever server URL `create`/`join` stored there.
const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8787";

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Client(#[from] ClientError),
    #[error("local I/O error")]
    Io(#[from] std::io::Error),
    #[error("could not serialize JSON output")]
    Json(#[from] serde_json::Error),
    #[error("no API token: pass --token-file or set SCRIGNO_API_TOKEN")]
    MissingToken,
    #[error("--data-dir is required")]
    MissingDataDir,
    #[error("could not read the secret file")]
    SecretFileUnreadable,
    #[error("could not read the passphrase from the terminal")]
    PromptFailed,
    #[error("the two passphrases entered do not match")]
    PassphraseMismatch,
    #[error("'{0}' is not a valid document id")]
    InvalidId(String),
    #[error("keep-offline state must be 'on' or 'off', got '{0}'")]
    InvalidOnOff(String),
}

#[derive(Debug, Parser)]
#[command(name = "scrigno", about = "Headless client for a Scrigno vault")]
struct Cli {
    /// Directory holding this device's local vault store (`vault.sqlite3`, cached blobs).
    ///
    /// `Option` (rather than a plain required `PathBuf`) purely because `clap` doesn't allow a
    /// `global = true` argument to also be `required` — every subcommand needs it in practice;
    /// see [`Cli::data_dir`].
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Server base URL. Required (or defaults to the dev server) for `create`/`join`; for every
    /// other command it only overrides the URL already stored locally when given.
    #[arg(long, global = true)]
    server: Option<String>,
    /// Read the passphrase from this file's first line instead of the environment/a prompt.
    #[arg(long, global = true)]
    passphrase_file: Option<PathBuf>,
    /// Read the API token from this file's first line instead of the environment.
    #[arg(long, global = true)]
    token_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    /// `--data-dir` is required for every subcommand in practice (see the field's own doc
    /// comment for why it isn't `required` at the `clap` level).
    fn data_dir(&self) -> Result<&std::path::Path, CliError> {
        self.data_dir.as_deref().ok_or(CliError::MissingDataDir)
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Bootstrap a brand-new vault on the server and bind this data dir to it (first device).
    Create,
    /// Join a vault another device already created (second+ device).
    Join,
    /// Unlock the vault bound to this data dir (proves the passphrase works; nothing is cached).
    Unlock,
    /// Unlock then immediately lock again (demonstrates the locked/unlocked state machine).
    Lock,
    /// Print whether this data dir has been bound to a vault yet.
    Status,
    /// Encrypt and add a file as a new document.
    Add {
        file: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// List documents (decrypted metadata only; never touches the network).
    List {
        #[arg(long)]
        json: bool,
    },
    /// Decrypt document `id` to a local file, downloading its blob first if not cached.
    Open {
        id: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Update a document's title/tags/note (each omitted flag keeps the current value).
    UpdateMeta {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Tombstone a document.
    Delete { id: String },
    /// Run one full sync round (pull, push, prefetch).
    Sync,
    /// Set whether a document's blob is always kept in the local cache.
    KeepOffline { id: String, state: String },
    /// Debug/support tool: dump the raw `/v1/changes` feed, bypassing decryption entirely.
    Changes {
        #[arg(long)]
        raw: bool,
        #[arg(long, default_value_t = 0)]
        since: i64,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    if let Err(error) = run(cli).await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    match &cli.command {
        Command::Create => cmd_create(&cli).await,
        Command::Join => cmd_join(&cli).await,
        Command::Unlock => cmd_unlock(&cli).await,
        Command::Lock => cmd_lock(&cli).await,
        Command::Status => cmd_status(&cli),
        Command::Add {
            file,
            title,
            tags,
            note,
        } => cmd_add(&cli, file, title, tags, note).await,
        Command::List { json } => cmd_list(&cli, *json).await,
        Command::Open { id, out } => cmd_open(&cli, id, out).await,
        Command::UpdateMeta {
            id,
            title,
            tags,
            note,
        } => cmd_update_meta(&cli, id, title.clone(), tags, note.clone()).await,
        Command::Delete { id } => cmd_delete(&cli, id).await,
        Command::Sync => cmd_sync(&cli).await,
        Command::KeepOffline { id, state } => cmd_keep_offline(&cli, id, state).await,
        Command::Changes { raw, since } => cmd_changes(&cli, *raw, *since).await,
    }
}

fn server_or_default(cli: &Cli) -> String {
    cli.server
        .clone()
        .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string())
}

fn token(cli: &Cli) -> Result<SecretString, CliError> {
    secrets::resolve_token(cli.token_file.as_deref())
}

fn parse_id(raw: &str) -> Result<Uuid, CliError> {
    Uuid::parse_str(raw).map_err(|_| CliError::InvalidId(raw.to_string()))
}

/// Shared by every command that needs the master key: opens the local store and unlocks it.
/// `async` for uniformity with every other command handler here, even though `Vault::unlock`
/// itself never touches the network (see its own doc comment).
#[allow(clippy::unused_async)]
async fn unlock(cli: &Cli) -> Result<UnlockedVault, CliError> {
    let passphrase = secrets::resolve_passphrase(cli.passphrase_file.as_deref(), false)?;
    let token = token(cli)?;
    let locked = Vault::open(cli.data_dir()?)?;
    let unlocked = locked.unlock(&passphrase, token, cli.server.as_deref())?;
    Ok(unlocked)
}

async fn cmd_create(cli: &Cli) -> Result<(), CliError> {
    let passphrase = secrets::resolve_passphrase(cli.passphrase_file.as_deref(), true)?;
    let token = token(cli)?;
    let server = server_or_default(cli);
    let locked = Vault::open(cli.data_dir()?)?;
    let unlocked = locked.create(&server, token, &passphrase).await?;
    println!("vault created: {}", unlocked.vault_id());
    Ok(())
}

async fn cmd_join(cli: &Cli) -> Result<(), CliError> {
    let passphrase = secrets::resolve_passphrase(cli.passphrase_file.as_deref(), false)?;
    let token = token(cli)?;
    let server = server_or_default(cli);
    let locked = Vault::open(cli.data_dir()?)?;
    let unlocked = locked.join(&server, token, &passphrase).await?;
    println!("vault joined: {}", unlocked.vault_id());
    Ok(())
}

async fn cmd_unlock(cli: &Cli) -> Result<(), CliError> {
    let vault = unlock(cli).await?;
    println!("unlocked: {}", vault.vault_id());
    Ok(())
}

async fn cmd_lock(cli: &Cli) -> Result<(), CliError> {
    let vault = unlock(cli).await?;
    let _locked = vault.lock();
    println!("locked");
    Ok(())
}

fn cmd_status(cli: &Cli) -> Result<(), CliError> {
    let vault = Vault::open(cli.data_dir()?)?;
    if vault.is_initialised()? {
        println!("initialised");
    } else {
        println!("uninitialised");
    }
    Ok(())
}

async fn cmd_add(
    cli: &Cli,
    file: &PathBuf,
    title: &str,
    tags: &[String],
    note: &str,
) -> Result<(), CliError> {
    let mut vault = unlock(cli).await?;
    let reader = std::fs::File::open(file)?;
    let original_name = file.file_name().map_or_else(
        || "document".to_string(),
        |n| n.to_string_lossy().to_string(),
    );
    let mime = guess_mime(&original_name);
    let summary = vault
        .add(
            reader,
            title.to_string(),
            tags.to_vec(),
            note.to_string(),
            mime,
            original_name,
        )
        .await?;
    println!("added: {} ({})", summary.id, summary.title);
    Ok(())
}

async fn cmd_list(cli: &Cli, json: bool) -> Result<(), CliError> {
    let vault = unlock(cli).await?;
    let docs = vault.list();
    if json {
        println!("{}", serde_json::to_string_pretty(&docs)?);
    } else {
        print_table(&docs);
    }
    Ok(())
}

fn print_table(docs: &[DocSummary]) {
    for doc in docs {
        println!(
            "{}\tv{}\t{}\t{}\t{}",
            doc.id,
            doc.version,
            if doc.dirty { "dirty" } else { "clean" },
            if doc.keep_offline { "keep" } else { "-" },
            doc.title,
        );
    }
}

async fn cmd_open(cli: &Cli, id: &str, out: &PathBuf) -> Result<(), CliError> {
    let id = parse_id(id)?;
    let mut vault = unlock(cli).await?;
    let mut writer = std::fs::File::create(out)?;
    vault.open(id, &mut writer).await?;
    writer.flush()?;
    println!("wrote {}", out.display());
    Ok(())
}

async fn cmd_update_meta(
    cli: &Cli,
    id: &str,
    title: Option<String>,
    tags: &[String],
    note: Option<String>,
) -> Result<(), CliError> {
    let id = parse_id(id)?;
    let mut vault = unlock(cli).await?;
    let current = vault
        .list()
        .into_iter()
        .find(|d| d.id == id.to_string())
        .ok_or(ClientError::NotFound)?;

    let new_title = title.unwrap_or(current.title);
    let new_tags = if tags.is_empty() {
        current.tags
    } else {
        tags.to_vec()
    };
    let new_note = note.unwrap_or(current.note);

    let summary = vault.update_meta(id, new_title, new_tags, new_note)?;
    println!("updated: {} ({})", summary.id, summary.title);
    Ok(())
}

async fn cmd_delete(cli: &Cli, id: &str) -> Result<(), CliError> {
    let id = parse_id(id)?;
    let mut vault = unlock(cli).await?;
    vault.delete(id)?;
    println!("deleted: {id}");
    Ok(())
}

async fn cmd_sync(cli: &Cli) -> Result<(), CliError> {
    let mut vault = unlock(cli).await?;
    let report = vault.sync().await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn cmd_keep_offline(cli: &Cli, id: &str, state: &str) -> Result<(), CliError> {
    let id = parse_id(id)?;
    let on = match state {
        "on" => true,
        "off" => false,
        other => return Err(CliError::InvalidOnOff(other.to_string())),
    };
    let mut vault = unlock(cli).await?;
    vault.set_keep_offline(id, on)?;
    println!("keep_offline({id}) = {on}");
    Ok(())
}

async fn cmd_changes(cli: &Cli, raw: bool, since: i64) -> Result<(), CliError> {
    if !raw {
        eprintln!("note: `changes` is a debug tool; pass --raw explicitly");
    }
    let token = token(cli)?;
    let server = server_or_default(cli);
    let value = scrigno_client::debug_raw_changes(&server, token, since, 500).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

/// Minimal, dependency-free extension → MIME guess. Good enough for the CLI/e2e fixtures; a real
/// content-type sniff is out of scope for a test harness.
fn guess_mime(file_name: &str) -> String {
    let ext = file_name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "txt" => "text/plain",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
    .to_string()
}
