//! Blob GC: deletes `blob` rows (and their `object_store` objects) that are not referenced by any
//! non-deleted `document` and are older than 24h, per `docs/ARCHITECTURE.md §2`. Tombstones
//! (`document.deleted = true`) are never touched and blobs they used to point at are eligible for
//! GC like any other unreferenced blob -- that's the point: interrupted uploads and superseded
//! blobs get cleaned up, deleted *documents* are kept forever.

use std::time::Duration;

use object_store::path::Path as StorePath;
use object_store::{ObjectStore, ObjectStoreExt};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;

/// Runs the GC sweep every `interval` until the process exits. Errors are logged and the loop
/// continues; a single failed sweep must never crash the server.
pub fn spawn(state: AppState, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; skip it so we don't GC at every cold start before
        // anything has had a chance to become 24h old anyway, and to spread load away from
        // startup.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match sweep(&state.db, state.store.as_ref()).await {
                Ok(deleted) if deleted > 0 => {
                    tracing::info!(deleted, "blob GC sweep complete");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(%error, "blob GC sweep failed");
                }
            }
        }
    })
}

struct Candidate {
    id: Uuid,
    vault_id: Uuid,
}

/// Runs a single GC sweep, returning the number of blobs deleted. Exposed for tests.
///
/// # Errors
///
/// Returns [`sqlx::Error`] if the database query/transaction fails. Individual `object_store`
/// deletion failures are logged and do not fail the sweep (see module docs).
pub async fn sweep(db: &PgPool, store: &dyn ObjectStore) -> Result<u64, sqlx::Error> {
    let mut tx = db.begin().await?;

    let candidates: Vec<Candidate> = sqlx::query_as!(
        Candidate,
        r#"
        SELECT b.id, b.vault_id
        FROM blob b
        WHERE NOT EXISTS (
            SELECT 1 FROM document d WHERE d.blob_id = b.id AND d.deleted = false
        )
        AND b.created_at < now() - interval '24 hours'
        FOR UPDATE SKIP LOCKED
        "#
    )
    .fetch_all(&mut *tx)
    .await?;

    if candidates.is_empty() {
        tx.commit().await?;
        return Ok(0);
    }

    let ids: Vec<Uuid> = candidates.iter().map(|c| c.id).collect();
    sqlx::query!("DELETE FROM blob WHERE id = ANY($1)", &ids)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    for candidate in &candidates {
        let path = StorePath::from(format!("{}/{}", candidate.vault_id, candidate.id));
        if let Err(error) = store.delete(&path).await {
            // The DB row is already gone (it was genuinely unreferenced and past the grace
            // period), so this only leaks storage space, never correctness. Log and move on.
            tracing::error!(%error, blob_id = %candidate.id, "GC: failed to delete blob object");
        }
    }

    Ok(u64::try_from(candidates.len()).unwrap_or(u64::MAX))
}
