//! `GET /v1/changes` — §3.

use axum::Json;
use axum::extract::{Query, State};

use crate::AppState;
use crate::error::ApiError;
use crate::models::{ChangesPage, DocumentRecord};

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 500;

#[derive(Debug, serde::Deserialize)]
pub struct ChangesQuery {
    since: Option<i64>,
    limit: Option<i64>,
}

/// `GET /v1/changes?since=<seq>&limit=<n<=500>` -> `200 { items, next_since, has_more }`, ordered
/// by `server_seq`, includes tombstones.
pub async fn list_changes(
    State(state): State<AppState>,
    Query(query): Query<ChangesQuery>,
) -> Result<Json<ChangesPage>, ApiError> {
    let since = query.since.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if limit <= 0 || limit > MAX_LIMIT {
        return Err(ApiError::BadRequest(format!(
            "limit must be between 1 and {MAX_LIMIT}"
        )));
    }

    // Fetch one extra row to determine `has_more` without a second COUNT query.
    let fetch_limit = limit + 1;
    let mut items: Vec<DocumentRecord> = sqlx::query_as!(
        DocumentRecord,
        r#"SELECT id, version, blob_id, blob_size, enc_meta, deleted, server_seq, updated_at
           FROM document
           WHERE server_seq > $1
           ORDER BY server_seq ASC
           LIMIT $2"#,
        since,
        fetch_limit
    )
    .fetch_all(&state.db)
    .await?;

    let has_more = i64::try_from(items.len()).unwrap_or(i64::MAX) > limit;
    if has_more {
        items.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    }

    let next_since = items.last().map_or(since, |item| item.server_seq);

    Ok(Json(ChangesPage {
        items,
        next_since,
        has_more,
    }))
}
