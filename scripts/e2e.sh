#!/usr/bin/env bash
#
# scripts/e2e.sh — two-device end-to-end scenario for Scrigno (docs/ARCHITECTURE.md, CLAUDE.md).
#
# Usage:
#   ./scripts/e2e.sh          (or `just e2e`)
#
# What it does:
#   - Brings up the full stack itself: `docker compose --profile full up -d --build --wait`
#     (Postgres + scrigno-server — the same thing `just up` does) and waits for /healthz. It does
#     NOT assume `just db`/`just server` are already running; it is self-sufficient.
#   - Builds `scrigno-cli` (debug profile, for fast iteration; the CLI itself is what's under
#     test here, not release optimisation).
#   - Drives two CLI "devices" (two `--data-dir`s) through the whole M3 command surface: create,
#     join, add, sync, update-meta, delete, open — asserting with `cmp` (byte-exact content) and
#     `jq` (decrypted metadata) at every step. Exits non-zero on the first mismatch, printing
#     which step failed.
#
# Re-runnability: the server holds a single vault per deployment (docs/ARCHITECTURE.md §2), so a
# second run against a still-alive server cannot `create` a new one — this script probes
# `GET /v1/vault` first and `join`s an existing vault instead. Every title/tag this script
# chooses is suffixed with a per-run id so `jq` lookups by title never collide with documents
# left over from a previous run. The passphrase: if `.env` sets `SCRIGNO_PASSPHRASE`, that fixed
# value is used every time (as documented in `.env.example`, "only for scripts, never for real
# vaults"); otherwise a throwaway one is generated once and cached at `.data/e2e-passphrase` so
# repeated runs against the same still-alive vault keep using the same passphrase — and
# `just reset-db` (which deletes `.data/`) naturally invalidates that cache along with the vault
# it belonged to, so the next run generates a fresh one to match the fresh server.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

log() { printf '\n\033[1;34m==>\033[0m %s\n' "$1"; }
fail() {
  printf '\n\033[1;31mFAIL\033[0m %s\n' "$1" >&2
  exit 1
}

for tool in docker curl jq cmp openssl timeout cargo; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool '$tool' not found on PATH"
done

# ---------------------------------------------------------------- configuration ----------------

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

: "${SCRIGNO_API_TOKEN:?SCRIGNO_API_TOKEN must be set — copy .env.example to .env and fill it in}"
: "${SCRIGNO_PORT:=8787}"
server_url="http://127.0.0.1:${SCRIGNO_PORT}"
run_id="e2e-$(date +%s)-$$"

# ---------------------------------------------------------------- server up --------------------

log "starting Postgres + scrigno-server (docker compose --profile full)"
docker compose --profile full up -d --build --wait

log "waiting for ${server_url}/healthz"
healthy=""
for _ in $(seq 1 60); do
  if curl -sf "${server_url}/healthz" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 1
done
[ -n "$healthy" ] || fail "server never became healthy at ${server_url}/healthz"

# ---------------------------------------------------------------- build ------------------------

log "building scrigno-cli"
cargo build -p scrigno-cli
scrigno="${repo_root}/target/debug/scrigno"

# ---------------------------------------------------------------- passphrase -------------------

passphrase_file="$(mktemp)"
dir_a="$(mktemp -d)"
dir_b="$(mktemp -d)"
fixtures="$(mktemp -d)"
cleanup() { rm -f "$passphrase_file"; rm -rf "$dir_a" "$dir_b" "$fixtures"; }
trap cleanup EXIT

if [ -n "${SCRIGNO_PASSPHRASE:-}" ]; then
  printf '%s' "$SCRIGNO_PASSPHRASE" >"$passphrase_file"
else
  mkdir -p .data
  cache=".data/e2e-passphrase"
  if [ ! -s "$cache" ]; then
    openssl rand -base64 24 >"$cache"
    chmod 600 "$cache"
  fi
  cp "$cache" "$passphrase_file"
fi
chmod 600 "$passphrase_file"

cli() {
  local data_dir="$1"
  shift
  "$scrigno" --data-dir "$data_dir" --server "$server_url" --passphrase-file "$passphrase_file" "$@"
}

# ---------------------------------------------------------------- fixtures ---------------------

log "generating fixtures (1 KiB text, 3 MiB random, 0-byte)"
head -c 1024 /dev/urandom | base64 | head -c 1024 >"$fixtures/small.txt"
head -c $((3 * 1024 * 1024)) /dev/urandom >"$fixtures/big.bin"
: >"$fixtures/empty.bin"

# ---------------------------------------------------------------- bootstrap --------------------

vault_status="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${SCRIGNO_API_TOKEN}" "${server_url}/v1/vault")"

log "device A: bootstrapping vault (GET /v1/vault -> ${vault_status})"
case "$vault_status" in
404) cli "$dir_a" create ;;
200) cli "$dir_a" join ;;
*) fail "unexpected GET /v1/vault status ${vault_status}" ;;
esac

log "device B: joining vault"
cli "$dir_b" join

# ---------------------------------------------------------------- scenario 1 -------------------
# Add on A -> sync -> visible and byte-identical on B.

log "scenario 1: add + sync propagates a document, content decrypts correctly"
add_out="$(cli "$dir_a" add "$fixtures/small.txt" --title "Documento piccolo $run_id" --tag e2e --note "primo test")"
doc1_id="$(printf '%s' "$add_out" | head -n1 | awk '{print $2}')"
[ -n "$doc1_id" ] || fail "scenario 1: could not parse a document id from: $add_out"

cli "$dir_a" sync >/dev/null
cli "$dir_b" sync >/dev/null

cli "$dir_b" list --json | jq -e --arg id "$doc1_id" \
  '[.[] | select(.id == $id)] | length == 1' >/dev/null ||
  fail "scenario 1: document $doc1_id not visible on device B after sync"

cli "$dir_b" open "$doc1_id" --out "$fixtures/small.roundtrip.txt"
cmp "$fixtures/small.txt" "$fixtures/small.roundtrip.txt" ||
  fail "scenario 1: content decrypted on B does not match what A added"
log "scenario 1 OK"

# ---------------------------------------------------------------- scenario 2 -------------------
# Edit the same doc on both devices while "offline" from each other -> exactly one conflict copy,
# no data lost.

log "scenario 2: concurrent metadata edit on A and B -> exactly one conflict copy"
cli "$dir_a" update-meta "$doc1_id" --title "Titolo da A $run_id"
cli "$dir_b" update-meta "$doc1_id" --title "Titolo da B $run_id"

cli "$dir_b" sync >/dev/null # B's edit lands on the server first.
cli "$dir_a" sync >/dev/null # A discovers the conflict and creates a conflict copy.
cli "$dir_b" sync >/dev/null # B picks up A's conflict copy too.

for dir in "$dir_a" "$dir_b"; do
  list_json="$(cli "$dir" list --json)"

  conflict_count="$(printf '%s' "$list_json" | jq --arg rid "$run_id" \
    '[.[] | select((.title | contains("copia in conflitto")) and (.title | contains($rid)))] | length')"
  [ "$conflict_count" = "1" ] ||
    fail "scenario 2: expected exactly one conflict copy on $dir, found $conflict_count"

  printf '%s' "$list_json" | jq -e --arg rid "$run_id" \
    '[.[].title] | any(contains("Titolo da B " + $rid))' >/dev/null ||
    fail "scenario 2: B's edit (server winner) missing on $dir"
  printf '%s' "$list_json" | jq -e --arg rid "$run_id" \
    '[.[].title] | any(startswith("Titolo da A " + $rid))' >/dev/null ||
    fail "scenario 2: A's edit (conflict copy) missing on $dir — data would have been lost"

  # Strongest check: the conflict copy's blob itself round-trips byte-exact under its new
  # doc_id, not just its title (exercises the AAD rebinding in encrypt_new_document end to end).
  copy_id="$(printf '%s' "$list_json" | jq -r --arg rid "$run_id" \
    '[.[] | select((.title | contains("copia in conflitto")) and (.title | contains($rid)))][0].id')"
  [ -n "$copy_id" ] && [ "$copy_id" != "null" ] ||
    fail "scenario 2: could not resolve conflict copy id on $dir"
  copy_out="$fixtures/conflict-copy-$(basename "$dir").bin"
  cli "$dir" open "$copy_id" --out "$copy_out"
  cmp "$fixtures/small.txt" "$copy_out" ||
    fail "scenario 2: conflict copy blob content on $dir does not match A's original file — data would have been lost"
done
log "scenario 2 OK (no data lost, both edits recoverable)"

# ---------------------------------------------------------------- scenario 3 -------------------
# Delete propagates, no error.

log "scenario 3: delete on A propagates to B"
cli "$dir_a" delete "$doc1_id"
cli "$dir_a" sync >/dev/null
cli "$dir_b" sync >/dev/null

for dir in "$dir_a" "$dir_b"; do
  cli "$dir" list --json | jq -e --arg id "$doc1_id" \
    '[.[] | select(.id == $id)] | length == 0' >/dev/null ||
    fail "scenario 3: tombstone for $doc1_id did not propagate to $dir"
done
log "scenario 3 OK"

# ---------------------------------------------------------------- scenario 4 -------------------
# 0-byte and 3 MiB fixtures round-trip byte-exact.

log "scenario 4: 0-byte and 3 MiB files round-trip byte-exact"
cli "$dir_a" add "$fixtures/empty.bin" --title "Vuoto $run_id" >/dev/null
cli "$dir_a" add "$fixtures/big.bin" --title "Grande $run_id" >/dev/null
cli "$dir_a" sync >/dev/null
cli "$dir_b" sync >/dev/null

empty_id="$(cli "$dir_b" list --json | jq -r --arg t "Vuoto $run_id" '.[] | select(.title == $t) | .id')"
big_id="$(cli "$dir_b" list --json | jq -r --arg t "Grande $run_id" '.[] | select(.title == $t) | .id')"
[ -n "$empty_id" ] && [ -n "$big_id" ] || fail "scenario 4: could not find the new documents on B"

cli "$dir_b" open "$empty_id" --out "$fixtures/empty.roundtrip.bin"
cli "$dir_b" open "$big_id" --out "$fixtures/big.roundtrip.bin"
cmp "$fixtures/empty.bin" "$fixtures/empty.roundtrip.bin" || fail "scenario 4: 0-byte file mismatch"
cmp "$fixtures/big.bin" "$fixtures/big.roundtrip.bin" || fail "scenario 4: 3 MiB file mismatch"
log "scenario 4 OK"

# ---------------------------------------------------------------- scenario 5 -------------------
# Interrupt a sync mid blob-upload; re-running sync converges. (`add` never touches the network
# in this design — the blob upload happens during `sync`'s push step, per docs/ARCHITECTURE.md
# §5 — so that is the operation this scenario interrupts, not `add` itself.)

log "scenario 5: kill sync mid-upload, re-run sync, converges"
cli "$dir_a" add "$fixtures/big.bin" --title "Interrotto $run_id" >/dev/null
interrupted_id="$(cli "$dir_a" list --json | jq -r --arg t "Interrotto $run_id" '.[] | select(.title == $t) | .id')"
[ -n "$interrupted_id" ] || fail "scenario 5: could not find the new document on A"

set +e
timeout 1 "$scrigno" --data-dir "$dir_a" --server "$server_url" \
  --passphrase-file "$passphrase_file" sync >/dev/null 2>&1
set -e
# Whether or not the 1 s budget actually interrupted the upload (a 3 MiB upload to localhost may
# complete within it on a fast machine), the property under test is that a second, ordinary sync
# converges regardless — the local dirty row and its cached blob file are untouched by a killed
# process, so re-running sync just retries (or finds nothing left to do).
cli "$dir_a" sync >/dev/null

dirty_count="$(cli "$dir_a" list --json | jq --arg id "$interrupted_id" \
  '[.[] | select(.id == $id and .dirty == true)] | length')"
[ "$dirty_count" = "0" ] || fail "scenario 5: document $interrupted_id still dirty after resumed sync"

cli "$dir_b" sync >/dev/null
cli "$dir_b" list --json | jq -e --arg id "$interrupted_id" \
  '[.[] | select(.id == $id)] | length == 1' >/dev/null ||
  fail "scenario 5: interrupted-upload document never converged on device B"

cli "$dir_b" open "$interrupted_id" --out "$fixtures/interrupted.roundtrip.bin"
cmp "$fixtures/big.bin" "$fixtures/interrupted.roundtrip.bin" ||
  fail "scenario 5: converged content does not match the original file"
log "scenario 5 OK"

log "all scenarios passed"
