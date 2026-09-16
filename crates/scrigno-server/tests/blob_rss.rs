//! Peak-RSS regression test for a 150 MiB blob upload, per `docs/ROADMAP.md` M2's acceptance
//! criterion ("Uploading a 150 MiB blob keeps server RSS under 100 MiB (streamed)").
//!
//! Same technique as `scrigno-core`'s `peak_rss_stays_under_budget_for_50_mib`: read
//! `/proc/self/status` `VmHWM` before and after, and assert the *increase* stays under budget.
//! Linux-only, `#[ignore]`d because it's slow (real disk I/O for 150 MiB) and RSS is noisier than
//! a normal unit test assertion. Run explicitly with:
//!
//! ```sh
//! cargo test -p scrigno-server --release --test blob_rss -- --ignored --nocapture
//! ```

mod support;

use axum::body::Body;
use axum::http::StatusCode;
use futures_util::stream;
use sqlx::PgPool;
use uuid::Uuid;

const TOTAL_BYTES: usize = 150 * 1024 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
/// The acceptance criterion's 100 MiB budget, applied to the *increase* over the process's RSS
/// before the upload starts (so pre-existing tokio/sqlx/axum baseline memory isn't counted
/// against the budget, exactly as scrigno-core's equivalent test does for its own 8 MiB budget).
const BUDGET_KIB: u64 = 100 * 1024;

#[sqlx::test(migrations = "./migrations")]
#[ignore = "slow; run explicitly with `cargo test --release --test blob_rss -- --ignored --nocapture`"]
async fn uploading_150_mib_keeps_rss_increase_under_100_mib(pool: PgPool) {
    let router = support::app_with_limit(pool, 200 * 1024 * 1024);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    let before = read_vm_hwm_kib();

    // Crucially, this must *lazily* generate one chunk at a time (`stream::unfold`), not
    // pre-collect a `Vec` of every chunk up front: since this is an in-process
    // `tower::ServiceExt::oneshot` test, the "client" building the request body and the
    // "server" consuming it run in the same process/memory space, so a pre-materialized
    // 150 MiB `Vec` of chunks would inflate the very RSS number this test is trying to bound,
    // regardless of how the server itself behaves.
    let body_stream = stream::unfold(0usize, |sent| async move {
        if sent >= TOTAL_BYTES {
            return None;
        }
        let take = CHUNK_BYTES.min(TOTAL_BYTES - sent);
        let chunk: Result<axum::body::Bytes, std::io::Error> =
            Ok(axum::body::Bytes::from(vec![0x5Au8; take]));
        Some((chunk, sent + take))
    });

    let response = support::send(
        &router,
        support::authed("PUT", &format!("/v1/blobs/{id}"))
            .header("content-length", TOTAL_BYTES.to_string())
            .body(Body::from_stream(body_stream))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let after = read_vm_hwm_kib();
    let increase_kib = after.saturating_sub(before);
    println!(
        "peak RSS before={before} KiB after={after} KiB increase={increase_kib} KiB (budget {BUDGET_KIB} KiB)"
    );
    assert!(
        increase_kib < BUDGET_KIB,
        "peak RSS increased by {increase_kib} KiB, budget is {BUDGET_KIB} KiB"
    );
}

fn read_vm_hwm_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let digits: String = rest.chars().filter(char::is_ascii_digit).collect();
            return digits.parse().unwrap_or(0);
        }
    }
    0
}
