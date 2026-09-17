# Scrigno

Zero-knowledge personal document vault: Tauri 2 app (Android + desktop) and a tiny Rust server
that stores only ciphertext, meant to run in Docker on a homeserver. Homelab-native (one binary,
Postgres, a folder), searchable through on-device OCR with the text kept inside the encrypted
metadata, and built around the Italian "fascicolo": document kinds with validity rules and
expiry reminders. No web client on purpose.

Everything is driven by `just` — run it with no arguments to see the recipes. Start with
`cp .env.example .env`, set `SCRIGNO_API_TOKEN`, then `just db && just server` in one terminal
and `just app` in another. Project rules for Claude Code are in `CLAUDE.md`; design docs in
`docs/`.

## Common commands

Day to day (Postgres in Docker, server native — fast reload on `cargo run`):
```
just db              # start only Postgres in Docker
just server           # run the server natively against it (needs just db first)
just app               # Tauri desktop dev window
```

Prod-like (Postgres + server both in Docker, what the homeserver actually runs):
```
just up                # build + start both containers, waits for /healthz
just down              # stop containers, keeps data
just logs               # follow the server container's logs
```

Reset the dev database (DESTRUCTIVE — wipes Postgres and the local blob volume/cache):
```
just reset-db
```

Checks, before calling anything done:
```
just check              # fmt + clippy + all Rust tests + UI lint/typecheck/tests
just check-rust          # Rust only
just check-ui             # frontend only
just e2e                   # two-device CLI scenario against the real stack (brings the stack up itself)
```

Other useful ones:
```
just cli                # build the scrigno-cli binary (crates/scrigno-cli)
just bindings             # regenerate apps/mobile/src/bindings/*.ts from Rust
just sqlx-prepare           # regenerate .sqlx/ after changing a server query (commit the result)
just android-dev              # Tauri Android dev on a connected emulator/device
just apk                        # release APK build (needs keystore.properties)
```

Run `just` with no arguments any time for the full, current recipe list straight from the
`justfile` — this section is a cheat sheet, the `justfile` is the source of truth.
