# Scrigno — cryptographic design (normative)

This document is the spec `crates/scrigno-core` implements. Any deviation is a bug unless this
file is updated first. Terminology: **MK** master key, **KEK** key-encryption key derived from a
secret, **DEK** per-document data key, **AAD** additional authenticated data.

## 1. Primitives

| Purpose | Primitive | Crate |
|---|---|---|
| AEAD | XChaCha20-Poly1305 (24-byte nonce, 16-byte tag) | `chacha20poly1305` |
| Chunked AEAD | STREAM construction, `aead::stream::EncryptorBE32` / `DecryptorBE32` over XChaCha20-Poly1305 | `chacha20poly1305` with `stream` feature |
| Password KDF | Argon2id | `argon2` |
| Hash | BLAKE3 (plaintext content hash, client-side dedup/integrity) | `blake3` |
| Randomness | `OsRng` only | `rand` / `rand_core` |
| Memory hygiene | `Zeroize` / `Zeroizing<T>`, `SecretBox` | `zeroize`, `secrecy` |

No other primitive may be introduced without updating this table.

## 2. Key hierarchy

```
passphrase ──Argon2id(salt, params)──▶ KEK_p ──wrap──▶ keyslot("passphrase")
recovery code ─Argon2id(salt, params)─▶ KEK_r ──wrap──▶ keyslot("recovery")      (optional, M4)
                                                          │
                                                          ▼ unwrap
                                               MK (32 random bytes, generated once per vault)
                                                          │
                     ┌────────────────────────────────────┼─────────────────────────────┐
                     ▼                                    ▼                             ▼
            DEK_doc1 (32 B random)             DEK_doc2 (32 B random)     enc_meta_docN = AEAD(MK, meta JSON)
                     │ wrapped with MK                    │
                     ▼                                    ▼
            blob_doc1 = STREAM(DEK_doc1, file)   blob_doc2 = ...
```

- **MK** never leaves the device unwrapped. It exists in memory only while the vault is unlocked.
- **Every document has its own DEK.** Compromise of one DEK exposes one file.
- Changing the passphrase re-wraps MK into a new keyslot; documents are untouched.
- Rotating MK itself is out of scope for now (would require re-wrapping every DEK and re-encrypting every `enc_meta`).

## 3. Argon2id parameters

| Slot kind | m (KiB) | t | p | Output |
|---|---|---|---|---|
| `passphrase` (default) | 65536 (64 MiB) | 3 | 1 | 32 bytes |
| `recovery` | 65536 | 3 | 1 | 32 bytes |

- Salt: 16 random bytes per keyslot.
- Parameters are **stored in the keyslot** and read back on unlock, so they can be raised later
  without breaking existing vaults. Implement a floor: refuse to *create* a slot below
  m=19456, t=2, p=1 (OWASP minimum), but *accept* any stored params on unlock.
- Passphrase policy (enforced in the app, not in core): ≥ 12 characters; show an entropy hint;
  no composition rules.
- Recovery code: 32 random bytes shown once as Base32 (Crockford alphabet) in groups of 4,
  e.g. `ABCD-EFGH-…` (52 chars). Stored nowhere in plaintext.

## 4. Binary formats

All multi-byte integers big-endian. All formats start with a 1-byte `version`; readers reject
unknown versions with `Error::UnsupportedVersion`.

### 4.1 `WrappedKey` — MK wrapped under a KEK, or DEK wrapped under MK

```
offset  len   field
0       1     version = 0x01
1       24    nonce (random)
25      48    ciphertext = XChaCha20-Poly1305(key=KEK|MK, nonce, plaintext=32-byte key, aad)
```
Total 73 bytes.

AAD:
- MK under KEK: `b"scrigno/mk/v1" || vault_id (16 B) || keyslot_id (16 B)`
- DEK under MK: `b"scrigno/dek/v1" || doc_id (16 B)`

### 4.2 `Keyslot` — JSON, stored on server and locally

```json
{
  "id": "uuid",
  "kind": "passphrase" | "recovery",
  "kdf": { "alg": "argon2id", "m_kib": 65536, "t": 3, "p": 1, "salt": "<base64 16 B>" },
  "wrapped_mk": "<base64 of WrappedKey (73 B)>",
  "created_at": "RFC 3339"
}
```
The server stores this verbatim and never interprets `wrapped_mk`.

### 4.3 `EncMeta` — encrypted document metadata

Plaintext is `DocMeta` as canonical JSON (serde_json, keys in struct order):

```json
{
  "v": 1,
  "title": "Carta d'identità",
  "tags": ["identità", "personale"],
  "note": "scade 2031",
  "mime": "application/pdf",
  "size": 183422,
  "content_hash": "<hex blake3 of plaintext>",
  "original_name": "scan.pdf",
  "created_at": "RFC 3339",
  "thumb": "<base64 JPEG ≤ 24 KiB or null>"
}
```

Envelope:
```
0       1     version = 0x01
1       24    nonce
25      n+16  ciphertext = XChaCha20-Poly1305(MK, nonce, meta JSON, aad)
```
AAD: `b"scrigno/meta/v1" || doc_id (16 B) || doc_version (u32 BE)`.

Binding to `doc_version` means the server cannot silently attach an older meta to a newer record.
The thumbnail is generated **on device** and is part of the encrypted metadata; the server never
sees an image.

### 4.4 `Blob` — encrypted file content

```
0       4     magic "SCRG"
4       1     version = 0x01
5       73    wrapped_dek (WrappedKey, DEK under MK, aad = "scrigno/dek/v1" || doc_id)
78      19    stream nonce prefix (random)
97      …     STREAM segments
```

Segments: plaintext is split into chunks of exactly **1 MiB (1 048 576 B)**, last chunk may be
shorter (may be 0 B for an empty file: still emit one final empty segment). Each segment is
`XChaCha20-Poly1305` over the chunk with the STREAM nonce (`prefix || counter u32 BE || last_flag`)
as implemented by `EncryptorBE32`; ciphertext length = chunk + 16.

AAD for **every** segment: `header (bytes 0..97) || doc_id (16 B)`.

Properties this buys: truncation and reordering are detected (STREAM), a blob cannot be attached
to a different document (doc_id in AAD), and decryption can stream to disk/viewer chunk by chunk
without holding the whole file in memory.

The **ciphertext** SHA-256 is computed by the server on upload and returned as `ETag`; the client
verifies it on download before decrypting (cheap defence against storage corruption).

## 5. Vault lifecycle on the device

### 5.1 Create / join
1. Create: generate `vault_id`, MK, first `passphrase` keyslot → `POST /v1/vault`.
2. Join (second device): `GET /v1/vault` → pick a keyslot → derive KEK → unwrap MK.
3. In both cases MK is then handed to the **device unlock store** (5.2).

### 5.2 Device unlock store (biometric / quick unlock)
Purpose: not typing a 12+ char passphrase every time, while keeping MK encrypted at rest.

- MK is stored in a **Stronghold snapshot** (`tauri-plugin-stronghold`) at
  `<app_data_dir>/vault.stronghold`, protected by a 32-byte random **device secret**.
- **Where the device secret lives** (in order of preference, decide in M5 by checking what the
  current `tauri-plugin-biometric` version supports):
  1. Android Keystore-backed key with `setUserAuthenticationRequired(true)` — device secret is
     wrapped by that key and can only be unwrapped after a successful biometric prompt.
     Use it if the plugin exposes keystore-bound encrypt/decrypt; otherwise write a minimal
     Kotlin plugin for exactly this.
  2. Fallback (desktop, and Android until 1 is available): device secret in an app-private file
     with restrictive permissions; the biometric prompt is then **UX gating only** and must be
     documented as such in the app's settings screen.
- Re-authentication with the passphrase is required: after 7 days, after 5 failed biometric
  attempts, after reinstall, and whenever the user chooses "Blocca completamente".
- **Auto-lock:** MK is zeroized from memory after 5 minutes of inactivity (configurable 1–30) and
  whenever the app goes to background for more than 30 s. Locked ≠ logged out: ciphertext cache
  stays, only MK is dropped.

### 5.3 What is written to disk on the device
Allowed: ciphertext blobs (cache), `enc_meta`, the SQLite index (ids, versions, dirty flags,
cursor), Stronghold snapshot, settings. **Never**: plaintext files, decrypted metadata, MK, DEKs,
passphrase, thumbnails in plaintext. Sharing/exporting a document to another app writes a
plaintext copy to the app's cache dir and deletes it as soon as the share sheet returns.

## 6. Server API token

The bearer token is an access-control measure, **not** part of the confidentiality design. If it
leaks, an attacker can delete or add ciphertext but cannot read anything. Compare it in constant
time (`subtle::ConstantTimeEq`). Never log it.

## 7. Threat model

| Adversary | Confidentiality | Integrity / availability |
|---|---|---|
| Server fully compromised (DB + blobs + token) | **Protected.** Sees only sizes, timestamps, counts | Can delete, withhold or roll back records. Detected partially (client keeps its cursor and versions; a rollback shows up as `server_seq` going backwards → app shows a warning). Full protection out of scope. |
| Network attacker (no TLS or broken TLS) | Protected by E2E | Same as above |
| Lost/stolen phone, vault locked | Protected by Argon2id + passphrase; with 5.2 option 1 also by hardware | — |
| Lost/stolen phone, vault unlocked, screen unlocked | **Not protected.** Mitigation: auto-lock | — |
| Malware on the device with root | Not protected | — |
| Someone who knows the passphrase | Not protected (by definition) | — |
| Traffic analysis (blob sizes reveal file sizes) | Partially leaks. Optional padding to 64 KiB multiples is a M6+ improvement | — |

## 8. Test vectors

`crates/scrigno-core/tests/vectors/` must contain fixed inputs (keys, nonces, doc ids, plaintext)
and expected outputs for `WrappedKey`, `EncMeta` and a 3-segment `Blob`. Tests inject the nonce
and key material via an internal `#[cfg(test)]` constructor; production code has no way to
supply a nonce.

## 9. Review checklist (used by `crypto-reviewer`)

- Nonces: always 24 random bytes from `OsRng`, never derived, never reused; STREAM prefix 19 B.
- AAD present and exactly as specified in every call; doc_id / version taken from the record,
  not from user input.
- `version` byte checked before parsing; lengths checked before slicing (no panics on bad input).
- All key material in `Zeroizing`/`SecretBox`; no `Clone` on key types; no `Debug` that prints bytes.
- Argon2 floor enforced on create; stored params honoured on unlock.
- No plaintext or key in any `tracing`/`println!`/error message/test output.
- IPC: commands never return MK/DEK/KEK; decrypted content only as binary response, never cached.
- Constant-time comparison for the API token.
