set dotenv-load := true
set shell := ["bash", "-euo", "pipefail", "-c"]

app_dir := "apps/mobile"

# List recipes
default:
    @just --list --unsorted

# ---------------------------------------------------------------- infra -----------------------

# Start only Postgres in Docker (server then runs natively with `just server`)
db:
    docker compose up -d --wait postgres
    @echo "postgres ready on ${SCRIGNO_PUBLISH_HOST:-127.0.0.1}:${POSTGRES_PORT:-5432}"

# Postgres + server, both in Docker (prod-like; this is what the homeserver runs)
up:
    docker compose --profile full up -d --build --wait
    @echo "server healthy on http://127.0.0.1:${SCRIGNO_PORT:-8787}"

# Stop containers (keeps data)
down:
    docker compose --profile full down

# Follow server logs
logs:
    docker compose --profile full logs -f server

# DESTRUCTIVE: stop and delete database + blob volumes
reset-db:
    docker compose --profile full down -v
    rm -rf .data

# ---------------------------------------------------------------- rust ------------------------

# Run the server natively against compose Postgres (fast dev loop; needs `just db`)
server:
    mkdir -p "${SCRIGNO_BLOB_DIR:-./.data/blobs}"
    cargo run -p scrigno-server

# Regenerate SQLx offline query data (commit .sqlx/ afterwards)
sqlx-prepare:
    cargo sqlx prepare --workspace -- --all-targets

# Rust checks only
check-rust:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cd {{app_dir}}/src-tauri && cargo fmt -- --check && cargo clippy --all-targets -- -D warnings && cargo test

# Frontend checks only
check-ui:
    cd {{app_dir}} && pnpm lint && pnpm typecheck && pnpm test -- --run

# Everything that must be green before "done"
check: check-rust check-ui

# Export Rust types to TypeScript bindings (apps/mobile/src/bindings)
bindings:
    cargo test -p scrigno-client --features ts-export export_bindings

# ---------------------------------------------------------------- app -------------------------

# Install frontend deps
install:
    cd {{app_dir}} && pnpm install

# Tauri desktop dev (primary manual test surface)
app:
    cd {{app_dir}} && pnpm tauri dev

# Tauri Android dev on the connected emulator/device
android-dev:
    cd {{app_dir}} && pnpm tauri android dev

# Release APK for arm64 phones (needs keystore.properties for signing)
apk:
    cd {{app_dir}} && pnpm tauri android build --apk --target aarch64
    @echo "APK under {{app_dir}}/src-tauri/gen/android/app/build/outputs/apk/"

# ---------------------------------------------------------------- cli / e2e -------------------

# Build the CLI
cli:
    cargo build -p scrigno-cli

# End-to-end scenario driven by the CLI against compose (available from milestone M3)
# scripts/e2e.sh brings up the full stack itself (Postgres + server, via `docker compose
# --profile full`, i.e. what `just up` does) and waits for /healthz, so no `db`/`up`
# prerequisite is declared here — running it directly (`./scripts/e2e.sh`) works the same way.
e2e:
    ./scripts/e2e.sh
