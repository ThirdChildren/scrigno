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

## Android

`apps/mobile/src-tauri/gen/android/` is committed (Tauri's own guidance for the generated
project). One-time SDK/NDK setup, then every Android command below needs these exported first:

```
export ANDROID_HOME="$HOME/android-sdk"
export ANDROID_SDK_ROOT="$HOME/android-sdk"
export NDK_HOME="$ANDROID_HOME/ndk/<installed-version>"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
```

Debug build (unsigned by design, `adb install`-able, cleartext HTTP allowed — see below):
```
just android-dev                                            # live reload on an emulator/device
cd apps/mobile && pnpm tauri android build --apk --target aarch64 --debug   # one-shot debug APK
```

Cleartext HTTP (`http://10.0.2.2:8787` for the emulator, or a LAN dev server with
`SCRIGNO_PUBLISH_HOST=0.0.0.0`) is allowed **only** in debug builds
(`gen/android/app/build.gradle.kts`'s `debug` build type sets
`manifestPlaceholders["usesCleartextTraffic"] = "true"`; `release` never does) — never enabled
outside development, matching M6's eventual `https://scrigno.stefanoleto.xyz`.

Release build (`just apk`) needs `apps/mobile/src-tauri/gen/android/keystore.properties`
(gitignored — never commit it, it names the owner's production signing key). Generate the
keystore once, keep the file and its passwords backed up somewhere safe **outside** the repo:

```
keytool -genkeypair -v -keystore scrigno-release.jks -alias scrigno \
  -keyalg RSA -keysize 2048 -validity 10000
```

Then create `apps/mobile/src-tauri/gen/android/keystore.properties`:

```
storeFile=/absolute/path/to/scrigno-release.jks
storePassword=...
keyAlias=scrigno
keyPassword=...
```

Without that file, the `release` build type has no `signingConfig` and the Android Gradle Plugin
produces an **unsigned** APK/AAB (its documented behaviour when a non-`debug` build type has no
explicit signing config — the build itself still succeeds) — expected on a fresh checkout, not
installable as-is until it's signed.

Android server URL hint: the emulator reaches the host machine at `http://10.0.2.2:8787`; a phone
on the LAN needs `SCRIGNO_PUBLISH_HOST=0.0.0.0` in `.env` plus the machine's LAN IP (see the
"Network exposure" comment in `.env.example`).
