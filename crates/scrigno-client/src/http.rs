//! HTTP client for the `/v1/*` API (`docs/ARCHITECTURE.md §3`).
//!
//! Two `reqwest::Client` instances: `json` (connect 10s, request 60s — every JSON-body call) and
//! `blob` (connect 10s, **no** overall request timeout — streaming blob transfers can legitimately
//! take a long time on a slow link, per this milestone's brief). Retries with backoff are applied
//! only to idempotent requests (`GET`, `PUT /v1/blobs/{id}` — the latter is idempotent per §3:
//! re-uploading identical content returns `200` with the same shape as `201`); `PUT`/`DELETE
//! /v1/docs/{id}` are never auto-retried by this module (the sync engine itself decides what to
//! do with a `412`).

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::Stream;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use uuid::Uuid;

use crate::error::{ClientError, Result};
use crate::wire::{
    BlobPutResponseWire, ChangesPageWire, CreateVaultWire, DocumentRecordWire, ErrorBodyWire,
    NewKeyslotWire, PutDocWire, VaultWire,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const RETRY_ATTEMPTS: u32 = 3;
const RETRY_BASE_DELAY: Duration = Duration::from_millis(200);
/// Chunk size used when streaming a blob upload from disk / a blob download to disk.
const STREAM_CHUNK: usize = 256 * 1024;

/// Progress callback invoked with the cumulative number of bytes transferred so far. Used by
/// blob upload/download (§: "blob streams ... with progress callback"); the eventual Tauri layer
/// (M4) turns this into `sync-progress` events.
pub type ProgressFn<'a> = dyn FnMut(u64) + Send + 'a;

/// Outcome of a conditional (`If-Match`) write to `/v1/docs/{id}`.
pub(crate) enum PutOutcome {
    /// `200`/`201`: the write was applied. Carries the resulting record.
    Applied(DocumentRecordWire),
    /// `412 version_mismatch`. The server's current record is parsed (to validate the response
    /// shape) but deliberately discarded: §5 handles a conflict by going back to step 1 (a fresh
    /// `pull()`), which fetches the same record through the ordinary change feed rather than a
    /// one-off out-of-band copy of it.
    Conflict,
}

pub(crate) struct HttpClient {
    json: reqwest::Client,
    blob: reqwest::Client,
    base_url: String,
    token: SecretString,
}

impl HttpClient {
    pub fn new(base_url: &str, token: SecretString) -> Result<Self> {
        let json = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| ClientError::Network)?;
        let blob = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|_| ClientError::Network)?;
        Ok(Self {
            json,
            blob,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder.bearer_auth(self.token.expose_secret())
    }

    // ------------------------------------------------------------- vault ---------------------

    pub async fn get_vault(&self) -> Result<VaultWire> {
        let resp =
            with_retry(|| async { self.auth(self.json.get(self.url("/v1/vault"))).send().await })
                .await?;
        parse_json_ok(resp).await
    }

    pub async fn create_vault(&self, id: Uuid, keyslot: NewKeyslotWire) -> Result<VaultWire> {
        let body = CreateVaultWire { id, keyslot };
        let resp = self
            .auth(self.json.post(self.url("/v1/vault")))
            .json(&body)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_json_ok(resp).await
    }

    // ------------------------------------------------------------ changes --------------------

    pub async fn get_changes(&self, since: i64, limit: i64) -> Result<ChangesPageWire> {
        let resp = with_retry(|| async {
            self.auth(
                self.json
                    .get(self.url("/v1/changes"))
                    .query(&[("since", since), ("limit", limit)]),
            )
            .send()
            .await
        })
        .await?;
        parse_json_ok(resp).await
    }

    /// `GET /v1/changes` deserialized as raw [`serde_json::Value`] instead of the typed
    /// [`ChangesPageWire`] — `enc_meta` stays opaque base64. Backs the CLI's `changes --raw`
    /// debug command; nothing here is ever decrypted.
    pub async fn get_changes_raw(&self, since: i64, limit: i64) -> Result<serde_json::Value> {
        let resp = with_retry(|| async {
            self.auth(
                self.json
                    .get(self.url("/v1/changes"))
                    .query(&[("since", since), ("limit", limit)]),
            )
            .send()
            .await
        })
        .await?;
        parse_json_ok(resp).await
    }

    // -------------------------------------------------------------- docs ---------------------

    pub async fn put_doc(&self, id: Uuid, if_match: i64, body: &PutDocWire) -> Result<PutOutcome> {
        let resp = self
            .auth(self.json.put(self.url(&format!("/v1/docs/{id}"))))
            .header("If-Match", if_match.to_string())
            .json(body)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_doc_write(resp).await
    }

    pub async fn delete_doc(&self, id: Uuid, if_match: i64) -> Result<PutOutcome> {
        let resp = self
            .auth(self.json.delete(self.url(&format!("/v1/docs/{id}"))))
            .header("If-Match", if_match.to_string())
            .send()
            .await
            .map_err(map_reqwest_err)?;
        parse_doc_write(resp).await
    }

    // -------------------------------------------------------------- blobs --------------------

    /// Streams `path`'s contents as the request body, hashing as it goes; verifies the server's
    /// returned `sha256` matches what was actually sent. Idempotent — safe to retry.
    pub async fn put_blob(
        &self,
        id: Uuid,
        path: &Path,
        mut progress: Option<&mut ProgressFn<'_>>,
    ) -> Result<BlobPutResponseWire> {
        for attempt in 0..RETRY_ATTEMPTS {
            let file = tokio::fs::File::open(path).await?;
            let len = file.metadata().await?.len();
            let stream = HashingFileStream::new(file);
            let hasher_out = stream.hasher_handle();
            let body = reqwest::Body::wrap_stream(stream);

            let result = self
                .auth(self.blob.put(self.url(&format!("/v1/blobs/{id}"))))
                .header("Content-Length", len)
                .body(body)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    let sent_sha = hasher_out.finalize_hex();
                    let parsed: BlobPutResponseWire = parse_json_ok(resp).await?;
                    if parsed.sha256 != sent_sha {
                        return Err(ClientError::Crypto);
                    }
                    if let Some(cb) = progress.as_mut() {
                        cb(len);
                    }
                    return Ok(parsed);
                }
                Ok(resp) if resp.status().is_server_error() && attempt + 1 < RETRY_ATTEMPTS => {
                    backoff(attempt).await;
                }
                Ok(resp) => return map_error_response(resp).await,
                Err(_) if attempt + 1 < RETRY_ATTEMPTS => backoff(attempt).await,
                Err(e) => return Err(map_reqwest_err(e)),
            }
        }
        Err(ClientError::Network)
    }

    /// Downloads a blob to `dest_tmp_path` (caller renames into the cache once verified),
    /// verifying the streamed ciphertext's SHA-256 against the `ETag` header. Retried on
    /// transient network failures (idempotent `GET`).
    pub async fn get_blob_to_file(
        &self,
        id: Uuid,
        dest_tmp_path: &Path,
        mut progress: Option<&mut ProgressFn<'_>>,
    ) -> Result<(i64, String)> {
        for attempt in 0..RETRY_ATTEMPTS {
            let result = self
                .auth(self.blob.get(self.url(&format!("/v1/blobs/{id}"))))
                .send()
                .await;

            let resp = match result {
                Ok(resp) if resp.status().is_success() => resp,
                Ok(resp) if resp.status().is_server_error() && attempt + 1 < RETRY_ATTEMPTS => {
                    backoff(attempt).await;
                    continue;
                }
                Ok(resp) => return map_error_response(resp).await,
                Err(_) if attempt + 1 < RETRY_ATTEMPTS => {
                    backoff(attempt).await;
                    continue;
                }
                Err(e) => return Err(map_reqwest_err(e)),
            };

            let expected_sha = resp
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim_matches('"').to_string())
                .ok_or(ClientError::ServerContract)?;

            match self
                .drain_to_file(resp, dest_tmp_path, progress.as_deref_mut())
                .await
            {
                Ok((size, sha)) => {
                    if sha != expected_sha {
                        let _ = tokio::fs::remove_file(dest_tmp_path).await;
                        return Err(ClientError::Crypto);
                    }
                    return Ok((size, sha));
                }
                Err(e) if attempt + 1 < RETRY_ATTEMPTS => {
                    let _ = tokio::fs::remove_file(dest_tmp_path).await;
                    let _ = e;
                    backoff(attempt).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(ClientError::Network)
    }

    async fn drain_to_file(
        &self,
        resp: reqwest::Response,
        dest: &Path,
        mut progress: Option<&mut ProgressFn<'_>>,
    ) -> Result<(i64, String)> {
        let mut file = tokio::fs::File::create(dest).await?;
        let mut hasher = Sha256::new();
        let mut total: u64 = 0;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(map_reqwest_err)?;
            hasher.update(&chunk);
            total += chunk.len() as u64;
            file.write_all(&chunk).await?;
            if let Some(cb) = progress.as_mut() {
                cb(total);
            }
        }
        file.flush().await?;
        let hex = hex_encode(&hasher.finalize());
        Ok((i64::try_from(total).unwrap_or(i64::MAX), hex))
    }
}

async fn parse_doc_write(resp: reqwest::Response) -> Result<PutOutcome> {
    if resp.status() == reqwest::StatusCode::PRECONDITION_FAILED {
        let _record: DocumentRecordWire =
            resp.json().await.map_err(|_| ClientError::ServerContract)?;
        return Ok(PutOutcome::Conflict);
    }
    if resp.status().is_success() {
        let record: DocumentRecordWire =
            resp.json().await.map_err(|_| ClientError::ServerContract)?;
        return Ok(PutOutcome::Applied(record));
    }
    map_error_response(resp).await
}

async fn parse_json_ok<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    if resp.status().is_success() {
        return resp.json().await.map_err(|_| ClientError::ServerContract);
    }
    map_error_response(resp).await
}

async fn map_error_response<T>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ClientError::Unauthorized);
    }
    let body = resp.json::<ErrorBodyWire>().await.ok();
    let code = body.as_ref().map(|b| b.error.code.as_str());
    Err(match (status, code) {
        (reqwest::StatusCode::NOT_FOUND, Some("vault_not_initialised")) => {
            ClientError::VaultNotInitialised
        }
        (reqwest::StatusCode::NOT_FOUND, _) => ClientError::NotFound,
        (reqwest::StatusCode::CONFLICT, Some("vault_exists")) => ClientError::VaultExists,
        (reqwest::StatusCode::BAD_REQUEST, _) => ClientError::InvalidInput,
        _ => ClientError::ServerContract,
    })
}

fn map_reqwest_err(_: reqwest::Error) -> ClientError {
    ClientError::Network
}

async fn with_retry<F, Fut>(mut make_request: F) -> Result<reqwest::Response>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<reqwest::Response, reqwest::Error>>,
{
    for attempt in 0..RETRY_ATTEMPTS {
        match make_request().await {
            Ok(resp) if resp.status().is_server_error() && attempt + 1 < RETRY_ATTEMPTS => {
                backoff(attempt).await;
            }
            Ok(resp) => return Ok(resp),
            Err(_) if attempt + 1 < RETRY_ATTEMPTS => backoff(attempt).await,
            Err(e) => return Err(map_reqwest_err(e)),
        }
    }
    Err(ClientError::Network)
}

async fn backoff(attempt: u32) {
    tokio::time::sleep(RETRY_BASE_DELAY * 2u32.pow(attempt)).await;
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A `Stream<Item = std::io::Result<Vec<u8>>>` that reads `file` in [`STREAM_CHUNK`]-sized
/// pieces, feeding each piece through a shared [`Sha256`] hasher as it goes. Used for blob
/// upload so hashing and network transfer happen in a single pass without ever holding the
/// whole file in memory (§: "never buffered whole in memory").
struct HashingFileStream {
    file: tokio::fs::File,
    hasher: std::sync::Arc<std::sync::Mutex<Sha256>>,
}

/// Handle to read out the final digest once the stream has been fully consumed.
struct HasherHandle(std::sync::Arc<std::sync::Mutex<Sha256>>);

impl HasherHandle {
    fn finalize_hex(&self) -> String {
        // `Sha256::finalize` takes the hasher by value; clone the accumulated state so this can
        // be called after the stream (which still logically "owns" the hasher) has finished.
        let guard = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hex_encode(&guard.clone().finalize())
    }
}

impl HashingFileStream {
    fn new(file: tokio::fs::File) -> Self {
        Self {
            file,
            hasher: std::sync::Arc::new(std::sync::Mutex::new(Sha256::new())),
        }
    }

    fn hasher_handle(&self) -> HasherHandle {
        HasherHandle(self.hasher.clone())
    }
}

impl Stream for HashingFileStream {
    type Item = std::io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut chunk = vec![0u8; STREAM_CHUNK];
        let mut read_buf = ReadBuf::new(&mut chunk);
        match Pin::new(&mut this.file).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(None);
                }
                chunk.truncate(n);
                if let Ok(mut hasher) = this.hasher.lock() {
                    hasher.update(&chunk);
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}
