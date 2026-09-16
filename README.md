# Scrigno

Scrigno is a zero-knowledge personal document vault: a Tauri 2 app (Android is the primary
target, desktop is the day-to-day dev target) plus a small Rust server that stores only
ciphertext. The server never sees a document, its title, its tags, its note or any other
plaintext — all encryption and decryption happens on the device in `crates/scrigno-core`.
See `docs/ARCHITECTURE.md` and `docs/CRYPTO.md` for the full design.

Run `just` to list every available command (setup, dev loop, checks, e2e, Android build). Start
with `cp .env.example .env`, fill in `SCRIGNO_API_TOKEN`, then `just db && just server` for the
backend and `just app` for the desktop app.
