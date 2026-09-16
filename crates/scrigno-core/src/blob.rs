//! `Blob`: encrypted file content, streamed in and out via `std::io::{Write, Read}` adapters.
//! See `docs/CRYPTO.md` §4.4.
//!
//! This is the only part of `scrigno-core` that touches `std::io`, and only as the adapter
//! boundary the crate's module doc promises: [`Encryptor`] and [`Decryptor`] wrap a
//! caller-supplied `W`/`R` and never do I/O of their own (no file, no socket). Both buffer at
//! most one ~1 MiB chunk of plaintext/ciphertext at a time, regardless of the total blob size,
//! so encrypting or decrypting a large file never holds the whole thing in memory.

use std::io::{self, Read, Write};

use aead_stream::{
    DecryptorBE32 as RawStreamDecryptor, EncryptorBE32 as RawStreamEncryptor, StreamBE32,
};
use chacha20poly1305::{Key as ChaKey, XChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::ids::DocId;
use crate::keys::{Dek, MasterKey};
use crate::rng::fill_random;
use crate::wrap::{self, WRAPPED_KEY_LEN, WrappedKey};

const MAGIC: [u8; 4] = *b"SCRG";
const VERSION: u8 = 0x01;
const STREAM_NONCE_PREFIX_LEN: usize = 19;
/// Header length: `magic(4) + version(1) + wrapped_dek(73) + stream_nonce_prefix(19)`.
const HEADER_LEN: usize = 4 + 1 + WRAPPED_KEY_LEN + STREAM_NONCE_PREFIX_LEN;
/// Plaintext chunk size: exactly 1 MiB, per `docs/CRYPTO.md` §4.4.
pub const CHUNK_SIZE: usize = 1_048_576;
const TAG_LEN: usize = 16;
const DOC_ID_LEN: usize = 16;

type Primitive = StreamBE32<XChaCha20Poly1305>;
type StreamNonce = aead_stream::Nonce<XChaCha20Poly1305, Primitive>;

fn chacha_key(bytes: &[u8; 32]) -> ChaKey {
    ChaKey::from(*bytes)
}

fn to_io_err<E: std::fmt::Display>(err: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}

fn state_err() -> io::Error {
    io::Error::other("blob stream was already finished")
}

/// Streaming encryptor: a [`std::io::Write`] adapter.
///
/// Callers `write()` plaintext into it in any chunk size; internally it buffers **at most one
/// 1 MiB chunk** regardless of total input size, so encrypting a large file never holds more
/// than ~1 MiB of plaintext (plus its ~1 MiB ciphertext counterpart while a chunk is in
/// flight) in memory.
///
/// [`Encryptor::finish`] must be called once all plaintext has been written — this is required
/// even for a 0-byte file, to emit the final (possibly empty) STREAM segment. Forgetting it
/// produces a truncated blob that [`Decryptor`] will reject.
pub struct Encryptor<W: Write> {
    writer: W,
    stream: Option<RawStreamEncryptor<XChaCha20Poly1305>>,
    aad: Vec<u8>,
    buf: Vec<u8>,
}

impl<W: Write> Encryptor<W> {
    /// Starts a new blob: generates a fresh [`Dek`], wraps it under `mk` (DEK-under-MK AAD,
    /// bound to `doc_id`), picks a random 19-byte STREAM nonce prefix, and writes the 97-byte
    /// header to `writer` immediately.
    ///
    /// # Errors
    /// Returns an [`io::Error`] if `OsRng` or the AEAD wrap fails (wrapping
    /// [`Error::Internal`]), or if writing the header to `writer` fails.
    pub fn new(mut writer: W, mk: &MasterKey, doc_id: DocId) -> io::Result<Self> {
        let dek = Dek::generate().map_err(to_io_err)?;
        let wrapped_dek = wrap::wrap_dek(mk, doc_id, &dek).map_err(to_io_err)?;

        let mut prefix = [0u8; STREAM_NONCE_PREFIX_LEN];
        fill_random(&mut prefix).map_err(to_io_err)?;

        let header = build_header(&wrapped_dek, &prefix);
        writer.write_all(&header)?;
        Ok(Self::from_parts(writer, &header, &dek, prefix, doc_id))
    }

    /// Test-only, deterministic variant of [`new`](Self::new): takes the DEK, the wrapped-DEK
    /// nonce, and the stream nonce prefix explicitly instead of from `OsRng`, so fixed test
    /// vectors are reproducible. Not reachable from production code (`docs/CRYPTO.md` §8).
    #[cfg(test)]
    pub(crate) fn new_for_test(
        mut writer: W,
        mk: &MasterKey,
        doc_id: DocId,
        dek: &Dek,
        wrapped_dek_nonce: [u8; 24],
        stream_nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    ) -> io::Result<Self> {
        let wrapped_dek = wrap::wrap_dek_for_test(mk, doc_id, dek, wrapped_dek_nonce);
        let header = build_header(&wrapped_dek, &stream_nonce_prefix);
        writer.write_all(&header)?;
        Ok(Self::from_parts(
            writer,
            &header,
            dek,
            stream_nonce_prefix,
            doc_id,
        ))
    }

    /// Shared tail of `new`/`new_for_test`: builds the AAD and the STREAM cipher state once
    /// the header has already been written.
    fn from_parts(
        writer: W,
        header: &[u8; HEADER_LEN],
        dek: &Dek,
        prefix: [u8; STREAM_NONCE_PREFIX_LEN],
        doc_id: DocId,
    ) -> Self {
        let aad = build_aad(header, doc_id);
        let stream_nonce = StreamNonce::from(prefix);
        let stream = RawStreamEncryptor::<XChaCha20Poly1305>::new(
            &chacha_key(dek.as_bytes()),
            &stream_nonce,
        );

        Self {
            writer,
            stream: Some(stream),
            aad,
            buf: Vec::with_capacity(CHUNK_SIZE),
        }
    }

    /// Finalizes the blob: encrypts and writes the last STREAM segment (the remaining buffered
    /// plaintext, which may be empty) and returns the inner writer.
    ///
    /// An empty final segment is still emitted for a 0-byte file, and — as a direct
    /// consequence of never buffering more than one chunk — also whenever the total plaintext
    /// length is an exact multiple of [`CHUNK_SIZE`]: `finish` always appends one dedicated
    /// last-marked segment after whatever full non-last segments `write` already flushed, per
    /// `docs/CRYPTO.md` §4.4's "still emit one final empty segment" rule generalized to any
    /// exact multiple. [`Decryptor`] handles this unconditionally by always probing for
    /// additional data after a full-size segment, so this is consistent on both ends.
    ///
    /// # Errors
    /// Propagates I/O errors from the inner writer, and wraps an [`Error::Internal`] if the
    /// STREAM counter has been exhausted (unreachable in practice at this chunk size, but
    /// checked rather than assumed).
    pub fn finish(mut self) -> io::Result<W> {
        let stream = self.stream.take().ok_or_else(state_err)?;
        stream
            .encrypt_last_in_place(&self.aad, &mut self.buf)
            .map_err(to_io_err)?;
        self.writer.write_all(&self.buf)?;
        self.writer.flush()?;
        Ok(self.writer)
    }

    fn write_full_chunk(&mut self) -> io::Result<()> {
        let aad = &self.aad;
        let buf = &mut self.buf;
        let stream = self.stream.as_mut().ok_or_else(state_err)?;
        stream.encrypt_next_in_place(aad, buf).map_err(to_io_err)?;
        self.writer.write_all(buf)?;
        buf.clear();
        Ok(())
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        if self.stream.is_none() {
            return Err(state_err());
        }
        let total = data.len();
        while !data.is_empty() {
            let space = CHUNK_SIZE - self.buf.len();
            let take = space.min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == CHUNK_SIZE {
                self.write_full_chunk()?;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Streaming decryptor: a [`std::io::Read`] adapter.
///
/// Callers `read()` plaintext out of it; internally it holds at most one decrypted ~1 MiB
/// chunk plus one in-flight ~1 MiB ciphertext segment being assembled, regardless of the total
/// blob size.
pub struct Decryptor<R: Read> {
    reader: R,
    stream: Option<RawStreamDecryptor<XChaCha20Poly1305>>,
    aad: Vec<u8>,
    /// Holds one decrypted plaintext chunk. `Zeroizing` scrubs the previous chunk's bytes
    /// automatically whenever this field is reassigned (see `fill_next_segment`) or when the
    /// `Decryptor` itself is dropped, per CLAUDE.md's "zeroize every buffer that held ...
    /// plaintext".
    out_buf: Zeroizing<Vec<u8>>,
    out_pos: usize,
    /// One byte read past the end of the previous full-size ciphertext segment, used to probe
    /// whether the stream continues without holding a whole extra chunk in memory.
    pending: Option<u8>,
    finished: bool,
}

impl<R: Read> Decryptor<R> {
    /// Reads and validates the 97-byte header, unwraps the DEK it carries (bound to `doc_id`
    /// via AAD), and prepares to decrypt STREAM segments on demand as [`Read::read`] is called.
    ///
    /// # Errors
    /// Returns an [`io::Error`] wrapping [`Error::Malformed`] if the magic bytes don't match,
    /// [`Error::UnsupportedVersion`] if the version byte is unrecognised,
    /// [`Error::Authentication`] if the wrapped DEK doesn't unwrap under `mk`/`doc_id`, or an
    /// I/O error if `reader` can't supply a full header.
    pub fn new(mut reader: R, mk: &MasterKey, doc_id: DocId) -> io::Result<Self> {
        let mut header = [0u8; HEADER_LEN];
        reader.read_exact(&mut header)?;

        if header[0..4] != MAGIC {
            return Err(to_io_err(Error::Malformed));
        }
        if header[4] != VERSION {
            return Err(to_io_err(Error::UnsupportedVersion));
        }

        let mut wrapped_bytes = [0u8; WRAPPED_KEY_LEN];
        wrapped_bytes.copy_from_slice(&header[5..5 + WRAPPED_KEY_LEN]);
        let wrapped = WrappedKey::from_slice(&wrapped_bytes).map_err(to_io_err)?;
        let dek = wrap::unwrap_dek(mk, doc_id, &wrapped).map_err(to_io_err)?;

        let mut prefix = [0u8; STREAM_NONCE_PREFIX_LEN];
        prefix.copy_from_slice(&header[5 + WRAPPED_KEY_LEN..]);

        let aad = build_aad(&header, doc_id);
        let stream_nonce = StreamNonce::from(prefix);
        let stream = RawStreamDecryptor::<XChaCha20Poly1305>::new(
            &chacha_key(dek.as_bytes()),
            &stream_nonce,
        );

        Ok(Self {
            reader,
            stream: Some(stream),
            aad,
            out_buf: Zeroizing::new(Vec::new()),
            out_pos: 0,
            pending: None,
            finished: false,
        })
    }

    /// Reads and decrypts the next ciphertext segment into `self.out_buf`.
    ///
    /// A segment is "last" if fewer than `CHUNK_SIZE + TAG_LEN` ciphertext bytes are
    /// available (short read / EOF), or if exactly that many bytes are available *and* a
    /// one-byte probe read afterwards hits EOF. That probe byte, if any, is stashed in
    /// `self.pending` and prepended to the next segment's ciphertext — this is the only extra
    /// state kept to detect the stream's true end without buffering more than one chunk ahead.
    fn fill_next_segment(&mut self) -> io::Result<()> {
        // `ciphertext` becomes the decrypted plaintext chunk in place once `decrypt_*_in_place`
        // succeeds below; `Zeroizing` scrubs it on every exit path (including a decrypt-failure
        // early return) and on the eventual move into `self.out_buf`, per CLAUDE.md's "zeroize
        // every buffer that held ... plaintext".
        let mut ciphertext: Zeroizing<Vec<u8>> =
            Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + TAG_LEN));
        if let Some(byte) = self.pending.take() {
            ciphertext.push(byte);
        }

        let mut tmp = [0u8; 8192];
        while ciphertext.len() < CHUNK_SIZE + TAG_LEN {
            let want = (CHUNK_SIZE + TAG_LEN - ciphertext.len()).min(tmp.len());
            let n = self.reader.read(&mut tmp[..want])?;
            if n == 0 {
                break;
            }
            ciphertext.extend_from_slice(&tmp[..n]);
        }

        let is_short = ciphertext.len() < CHUNK_SIZE + TAG_LEN;
        let last = if is_short {
            true
        } else {
            let mut one = [0u8; 1];
            if self.reader.read(&mut one)? == 0 {
                true
            } else {
                self.pending = Some(one[0]);
                false
            }
        };

        if ciphertext.len() < TAG_LEN {
            return Err(to_io_err(Error::Malformed));
        }

        if last {
            let stream = self.stream.take().ok_or_else(state_err)?;
            stream
                .decrypt_last_in_place(&self.aad, &mut *ciphertext)
                .map_err(to_io_err)?;
            self.finished = true;
        } else {
            let stream = self.stream.as_mut().ok_or_else(state_err)?;
            stream
                .decrypt_next_in_place(&self.aad, &mut *ciphertext)
                .map_err(to_io_err)?;
        }

        self.out_buf = ciphertext;
        self.out_pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.out_pos >= self.out_buf.len() {
            if self.finished {
                return Ok(0);
            }
            self.fill_next_segment()?;
            if self.out_buf.is_empty() {
                return Ok(0);
            }
        }
        let available = &self.out_buf[self.out_pos..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.out_pos += n;
        Ok(n)
    }
}

fn build_header(
    wrapped_dek: &WrappedKey,
    stream_nonce_prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(&MAGIC);
    header[4] = VERSION;
    header[5..5 + WRAPPED_KEY_LEN].copy_from_slice(&wrapped_dek.as_bytes());
    header[5 + WRAPPED_KEY_LEN..].copy_from_slice(stream_nonce_prefix);
    header
}

fn build_aad(header: &[u8; HEADER_LEN], doc_id: DocId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + DOC_ID_LEN);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&doc_id.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Cursor;
    use std::rc::Rc;

    /// A `Read` wrapper that counts total bytes pulled from the inner reader, via a shared
    /// counter the test keeps a handle to. Used to prove [`Decryptor`] does not read the
    /// entire ciphertext up front regardless of how slowly the caller consumes plaintext.
    struct TrackingReader<R> {
        inner: R,
        total_read: Rc<Cell<usize>>,
    }

    impl<R: Read> Read for TrackingReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.total_read.set(self.total_read.get() + n);
            Ok(n)
        }
    }

    /// Proves the streaming claim in this module's doc comment for the read side: reading a
    /// multi-chunk blob a little at a time never lets the underlying (ciphertext) reader run
    /// far ahead of what the caller has actually consumed as plaintext — i.e. `Decryptor`
    /// pulls segments on demand rather than buffering the whole blob up front. Fast and
    /// deterministic (no `/proc` dependency), unlike the peak-RSS test below.
    #[test]
    fn decryptor_never_reads_far_ahead_of_what_the_caller_consumed() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let plaintext = vec![0x11u8; 5 * CHUNK_SIZE];

        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(&plaintext).unwrap();
        let ciphertext = enc.finish().unwrap();
        let ciphertext_len = ciphertext.len();

        let total_read = Rc::new(Cell::new(0usize));
        let tracking = TrackingReader {
            inner: Cursor::new(ciphertext),
            total_read: total_read.clone(),
        };
        let mut dec = Decryptor::new(tracking, &mk, doc_id).unwrap();

        let mut consumed = 0usize;
        let mut buf = [0u8; 4096];
        // A generous bound: at most the header, one in-flight ciphertext segment, and one
        // probe byte should ever be read ahead of what the caller has consumed — nowhere
        // near the full ~5 MiB ciphertext.
        let max_outstanding = HEADER_LEN + CHUNK_SIZE + TAG_LEN + 1;
        loop {
            let n = dec.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            consumed += n;
            let outstanding = total_read.get().saturating_sub(consumed);
            assert!(
                outstanding <= max_outstanding,
                "decryptor read {outstanding} bytes ahead of the {consumed} bytes consumed so \
                 far (budget {max_outstanding}); it looks like it buffered more than one \
                 segment ahead"
            );
        }
        assert_eq!(consumed, plaintext.len());
        assert!(total_read.get() <= ciphertext_len);
    }

    /// A `Write` wrapper that records the size of every individual `write_all` call it
    /// receives (not the total). Used to prove [`Encryptor`] emits many bounded-size writes
    /// to the inner writer as it goes, rather than buffering all ciphertext and writing it
    /// once at the end.
    struct RecordingWriter {
        write_sizes: Vec<usize>,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_sizes.push(buf.len());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Proves the streaming claim in this module's doc comment for the write side: encrypting
    /// several chunks results in several separate, bounded-size writes to the inner writer —
    /// never one write of the whole ciphertext — so a caller writing to a file/socket sees
    /// backpressure and bounded memory use as data flows through.
    #[test]
    fn encryptor_emits_many_bounded_writes_not_one_big_one() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let plaintext = vec![0x22u8; 5 * CHUNK_SIZE];

        let mut enc = Encryptor::new(
            RecordingWriter {
                write_sizes: Vec::new(),
            },
            &mk,
            doc_id,
        )
        .unwrap();
        enc.write_all(&plaintext).unwrap();
        let writer = enc.finish().unwrap();

        // Header + 5 full segments + 1 empty last segment = 7 writes, all individually small.
        assert!(
            writer.write_sizes.len() >= 6,
            "expected several separate writes, got {:?}",
            writer.write_sizes
        );
        for size in &writer.write_sizes {
            assert!(
                *size <= CHUNK_SIZE + TAG_LEN,
                "a single write of {size} bytes is as large as (or larger than) the whole \
                 plaintext would be if it were buffered and written in one shot"
            );
        }
    }

    fn round_trip(plaintext: &[u8]) -> Vec<u8> {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();

        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(plaintext).unwrap();
        let ciphertext = enc.finish().unwrap();

        let mut dec = Decryptor::new(Cursor::new(ciphertext), &mk, doc_id).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn round_trips_empty() {
        assert_eq!(round_trip(&[]), Vec::<u8>::new());
    }

    #[test]
    fn round_trips_small() {
        let data = b"hello, scrigno".to_vec();
        assert_eq!(round_trip(&data), data);
    }

    #[test]
    fn round_trips_exactly_one_chunk() {
        let data = vec![0xABu8; CHUNK_SIZE];
        assert_eq!(round_trip(&data), data);
    }

    #[test]
    fn round_trips_one_chunk_plus_one_byte() {
        let data = vec![0xCDu8; CHUNK_SIZE + 1];
        assert_eq!(round_trip(&data), data);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // `i % 251` always fits in a u8
    fn round_trips_multi_chunk() {
        let mut data = Vec::with_capacity(3 * CHUNK_SIZE + 17);
        for i in 0..(3 * CHUNK_SIZE + 17) {
            data.push((i % 251) as u8);
        }
        assert_eq!(round_trip(&data), data);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(16))]

        /// Round-trips plaintext at and around every chunk boundary CRYPTO.md M1's acceptance
        /// criteria call out: 0 B, 1 B, exactly one chunk minus/plus a byte, and several
        /// chunks. `len` is drawn from that fixed set (not a free-ranging size) because the
        /// interesting behaviour is entirely boundary-adjacent; `seed` varies the content so
        /// each boundary is exercised with different bytes across runs, not just zeros.
        #[test]
        fn round_trips_around_chunk_boundaries(
            len in proptest::prelude::prop_oneof![
                proptest::prelude::Just(0usize),
                proptest::prelude::Just(1usize),
                proptest::prelude::Just(CHUNK_SIZE - 1),
                proptest::prelude::Just(CHUNK_SIZE),
                proptest::prelude::Just(CHUNK_SIZE + 1),
                proptest::prelude::Just(3 * CHUNK_SIZE + 17),
            ],
            seed in proptest::prelude::any::<u8>(),
        ) {
            let data: Vec<u8> = (0..len)
                .map(|i| seed.wrapping_add(u8::try_from(i % 256).unwrap_or(0)))
                .collect();
            proptest::prop_assert_eq!(round_trip(&data), data);
        }
    }

    #[test]
    fn header_has_expected_magic_and_version() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(b"x").unwrap();
        let bytes = enc.finish().unwrap();
        assert_eq!(&bytes[0..4], &MAGIC);
        assert_eq!(bytes[4], VERSION);
        assert_eq!(bytes.len(), HEADER_LEN + 1 + TAG_LEN);
    }

    #[test]
    fn tamper_magic_rejected() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(b"x").unwrap();
        let mut bytes = enc.finish().unwrap();
        bytes[0] = b'X';
        assert!(Decryptor::new(Cursor::new(bytes), &mk, doc_id).is_err());
    }

    #[test]
    fn tamper_version_rejected() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(b"x").unwrap();
        let mut bytes = enc.finish().unwrap();
        bytes[4] = 0x02;
        assert!(Decryptor::new(Cursor::new(bytes), &mk, doc_id).is_err());
    }

    #[test]
    fn tamper_wrapped_dek_rejected() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(b"x").unwrap();
        let mut bytes = enc.finish().unwrap();
        bytes[10] ^= 0xff; // inside the wrapped_dek region
        assert!(Decryptor::new(Cursor::new(bytes), &mk, doc_id).is_err());
    }

    #[test]
    fn tamper_stream_nonce_prefix_rejected() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(&vec![1u8; CHUNK_SIZE + 5]).unwrap();
        let mut bytes = enc.finish().unwrap();
        let idx = HEADER_LEN - 1; // last byte of the stream nonce prefix
        bytes[idx] ^= 0xff;
        let mut dec = Decryptor::new(Cursor::new(bytes), &mk, doc_id).unwrap();
        let mut out = Vec::new();
        assert!(dec.read_to_end(&mut out).is_err());
    }

    #[test]
    fn tamper_segment_ciphertext_rejected() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(b"hello world").unwrap();
        let mut bytes = enc.finish().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff; // flips a byte inside the final segment's tag
        let mut dec = Decryptor::new(Cursor::new(bytes), &mk, doc_id).unwrap();
        let mut out = Vec::new();
        assert!(dec.read_to_end(&mut out).is_err());
    }

    #[test]
    fn tamper_doc_id_rejected() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let other_doc_id = DocId::generate();
        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(b"x").unwrap();
        let bytes = enc.finish().unwrap();
        // Header parses fine (magic/version untouched), but the DEK unwrap uses the wrong AAD.
        assert!(Decryptor::new(Cursor::new(bytes), &mk, other_doc_id).is_err());
    }

    #[test]
    fn truncation_is_rejected() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(&vec![7u8; CHUNK_SIZE + 100]).unwrap();
        let bytes = enc.finish().unwrap();
        let truncated = &bytes[..bytes.len() - 5];
        let mut dec = Decryptor::new(Cursor::new(truncated.to_vec()), &mk, doc_id).unwrap();
        let mut out = Vec::new();
        assert!(dec.read_to_end(&mut out).is_err());
    }

    #[test]
    fn segment_reordering_is_rejected() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = Encryptor::new(Vec::new(), &mk, doc_id).unwrap();
        enc.write_all(&vec![9u8; 2 * CHUNK_SIZE]).unwrap();
        let bytes = enc.finish().unwrap();

        let seg_len = CHUNK_SIZE + TAG_LEN;
        let header = &bytes[..HEADER_LEN];
        let seg0 = &bytes[HEADER_LEN..HEADER_LEN + seg_len];
        let seg1 = &bytes[HEADER_LEN + seg_len..HEADER_LEN + 2 * seg_len];
        let seg2 = &bytes[HEADER_LEN + 2 * seg_len..]; // final empty-last segment

        let mut swapped = Vec::new();
        swapped.extend_from_slice(header);
        swapped.extend_from_slice(seg1);
        swapped.extend_from_slice(seg0);
        swapped.extend_from_slice(seg2);

        let mut dec = Decryptor::new(Cursor::new(swapped), &mk, doc_id).unwrap();
        let mut out = Vec::new();
        assert!(dec.read_to_end(&mut out).is_err());
    }

    /// Peak-RSS regression test for a 50 MiB streaming round trip.
    ///
    /// Crucially, this writes ciphertext to (and reads it back from) a real temp **file**,
    /// not an in-memory `Vec`/`Cursor` — the latter would hold the entire ~50 MiB output in
    /// memory by construction and defeat the point of the test regardless of how streaming
    /// `Encryptor`/`Decryptor` themselves are.
    ///
    /// Reads `/proc/self/status` `VmHWM` (peak resident set size) before and after, and
    /// asserts the *increase* stays under 8 MiB, per the M1 acceptance criterion
    /// ("<8 MiB peak RSS encrypting/decrypting a 50 MiB file in a test"). Linux-only (relies
    /// on `/proc`), `#[ignore]`d because it's slow and RSS measurements are noisier than a
    /// normal unit test. Run it explicitly with:
    ///
    /// ```sh
    /// cargo test -p scrigno-core --release -- --ignored peak_rss
    /// ```
    #[test]
    #[ignore = "slow; run explicitly with `cargo test --release -- --ignored peak_rss`"]
    fn peak_rss_stays_under_budget_for_50_mib() {
        let mk = MasterKey::from_bytes_for_test([4u8; 32]);
        let doc_id = DocId::generate();
        let path =
            std::env::temp_dir().join(format!("scrigno-core-peak-rss-{}.bin", std::process::id()));

        let before = read_vm_hwm_kib();

        let total = 50 * 1024 * 1024;
        let chunk = vec![0x5Au8; CHUNK_SIZE];
        let file = std::fs::File::create(&path).unwrap();
        let mut enc = Encryptor::new(file, &mk, doc_id).unwrap();
        let mut written = 0usize;
        while written < total {
            let take = chunk.len().min(total - written);
            enc.write_all(&chunk[..take]).unwrap();
            written += take;
        }
        enc.finish().unwrap();

        let file = std::fs::File::open(&path).unwrap();
        let mut dec = Decryptor::new(file, &mk, doc_id).unwrap();
        let mut sink = vec![0u8; 65536];
        loop {
            let n = dec.read(&mut sink).unwrap();
            if n == 0 {
                break;
            }
        }

        let after = read_vm_hwm_kib();
        let _ = std::fs::remove_file(&path);

        let increase_kib = after.saturating_sub(before);
        println!(
            "peak RSS before={before} KiB after={after} KiB increase={increase_kib} KiB (budget 8192 KiB)"
        );
        assert!(
            increase_kib < 8 * 1024,
            "peak RSS increased by {increase_kib} KiB, budget is 8192 KiB"
        );
    }

    #[cfg(test)]
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

    fn from_hex_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn from_hex_32(s: &str) -> [u8; 32] {
        from_hex_vec(s).try_into().unwrap()
    }

    fn from_hex_n<const N: usize>(s: &str) -> [u8; N] {
        from_hex_vec(s)
            .try_into()
            .unwrap_or_else(|_| panic!("wrong hex length"))
    }

    /// Loads `tests/vectors/blob_manifest.json` + the sibling `blob_3_segments.bin`
    /// (docs/CRYPTO.md §8): 2 MiB + 5 B of plaintext, so the ciphertext is exactly 3
    /// segments (2 full 1 MiB segments + one short 5 B last segment). Checks that
    /// [`Encryptor::new_for_test`] with the pinned DEK/nonces reproduces the committed
    /// ciphertext byte-for-byte, and that [`Decryptor`] (the normal, non-test path) decrypts
    /// the committed file back to the expected plaintext pattern.
    #[test]
    fn fixed_vector_blob_3_segments() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/blob_manifest.json")).unwrap();
        let ciphertext_file = include_bytes!("../tests/vectors/blob_3_segments.bin");

        let mk = MasterKey::from_bytes_for_test(from_hex_32(
            manifest["master_key_hex"].as_str().unwrap(),
        ));
        let doc_id =
            DocId::from_uuid(uuid::Uuid::parse_str(manifest["doc_id"].as_str().unwrap()).unwrap());
        let dek = Dek::from_bytes_for_test(from_hex_32(manifest["dek_hex"].as_str().unwrap()));
        let wrapped_dek_nonce =
            from_hex_n::<24>(manifest["wrapped_dek_nonce_hex"].as_str().unwrap());
        let stream_nonce_prefix = from_hex_n::<STREAM_NONCE_PREFIX_LEN>(
            manifest["stream_nonce_prefix_hex"].as_str().unwrap(),
        );
        let plaintext_len = usize::try_from(manifest["plaintext_len"].as_u64().unwrap()).unwrap();

        assert_eq!(
            ciphertext_file.len(),
            usize::try_from(manifest["ciphertext_len"].as_u64().unwrap()).unwrap()
        );
        assert_eq!(
            ciphertext_file.len(),
            HEADER_LEN + 2 * (CHUNK_SIZE + TAG_LEN) + (5 + TAG_LEN),
            "vector must be exactly 3 segments (2 full + 1 short last)"
        );

        // Re-encrypting with the same pinned inputs must reproduce the committed bytes exactly.
        let expected_plaintext: Vec<u8> = (0..plaintext_len)
            .map(|i| u8::try_from(i % 256).unwrap_or(0))
            .collect();
        let mut enc = Encryptor::new_for_test(
            Vec::new(),
            &mk,
            doc_id,
            &dek,
            wrapped_dek_nonce,
            stream_nonce_prefix,
        )
        .unwrap();
        enc.write_all(&expected_plaintext).unwrap();
        let reencrypted = enc.finish().unwrap();
        assert_eq!(reencrypted, ciphertext_file);

        // The committed file must decrypt (via the normal, non-test Decryptor) to that pattern.
        let mut dec = Decryptor::new(Cursor::new(ciphertext_file.to_vec()), &mk, doc_id).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, expected_plaintext);
    }
}
