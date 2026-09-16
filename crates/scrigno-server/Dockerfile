# syntax=docker/dockerfile:1.7
# Builds only the server. The Tauri app is a separate Cargo project and is excluded via .dockerignore.

FROM rust:1-bookworm AS builder
WORKDIR /app
ENV SQLX_OFFLINE=true
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# .sqlx/ must exist (keep .sqlx/.gitkeep) or this COPY fails on a fresh checkout
COPY .sqlx ./.sqlx
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release -p scrigno-server \
    && cp target/release/scrigno-server /scrigno-server

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home scrigno \
    && mkdir -p /data/blobs && chown -R scrigno:scrigno /data
COPY --from=builder /scrigno-server /usr/local/bin/scrigno-server
USER scrigno
ENV SCRIGNO_BIND=0.0.0.0:8787 SCRIGNO_BLOB_DIR=/data/blobs
EXPOSE 8787
VOLUME ["/data/blobs"]
ENTRYPOINT ["/usr/local/bin/scrigno-server"]
