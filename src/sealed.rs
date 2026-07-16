//! Sealed UDP symbol plane: per-datagram AEAD keyed by the TLS exporter.
//!
//! TLS cannot protect fire-and-forget UDP datagrams, so each symbol
//! datagram is sealed with ChaCha20-Poly1305 under a key both peers derive
//! from the TLS 1.3 session ([`crate::tls::export_symbol_key`]). Datagrams
//! carry an explicit 64-bit sequence number checked against an ESP-style
//! anti-replay window (RFC 6479). Sealed symbols are confidential,
//! session-bound, and replay-protected; replaying a recorded session's
//! datagrams at a new session fails because the exporter output differs.
//!
//! Wire layout (clear header doubles as AEAD associated data):
//!
//! ```text
//! magic "ATRS" (4) ‖ transfer_tag (8, LE) ‖ seq (8, LE)   ← AAD
//! encrypted body: block_index (4, LE) ‖ EncodingPacket    ← ciphertext
//! Poly1305 tag (16)
//! ```
//!
//! Failures (bad magic, wrong tag, replay, forgery) are dropped silently
//! before touching any decoder state.
//!
//! Ported from the sealed-datagram prototype written (by a coding agent)
//! for this design inside the asupersync tree
//! (<https://github.com/Dicklesworthstone/asupersync>, MIT + rider — see
//! README § Provenance & credit).

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::tls::SEAL_KEY_LEN;

/// AEAD tag size (ChaCha20-Poly1305).
pub const TAG_LEN: usize = 16;

/// Sealed datagram wire magic.
pub const MAGIC: [u8; 4] = *b"ATRS";

/// Clear-header length (magic ‖ transfer_tag ‖ seq).
pub const HEADER_LEN: usize = 4 + 8 + 8;

/// Total per-datagram overhead beyond the encrypted body.
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN;

/// Anti-replay window width in datagrams (RFC 6479-style bitmap).
const REPLAY_WINDOW_BITS: u64 = 4096;
const REPLAY_WINDOW_WORDS: usize = (REPLAY_WINDOW_BITS as usize) / 64;

// ─── AEAD helpers ────────────────────────────────────────────────────────────

fn aead_cipher(key: &[u8; SEAL_KEY_LEN]) -> chacha20poly1305::ChaCha20Poly1305 {
    use chacha20poly1305::KeyInit;
    chacha20poly1305::ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key))
}

const fn seq_nonce(seq: u64) -> [u8; 12] {
    let seq = seq.to_be_bytes();
    [
        0, 0, 0, 0, seq[0], seq[1], seq[2], seq[3], seq[4], seq[5], seq[6], seq[7],
    ]
}

// ─── Sealer / opener ─────────────────────────────────────────────────────────

/// Sender-side per-datagram sealer. Thread-safe; the sequence counter is a
/// single atomic shared across all spray paths of one transfer session.
pub struct SymbolSealer {
    cipher: chacha20poly1305::ChaCha20Poly1305,
    seq: AtomicU64,
}

impl std::fmt::Debug for SymbolSealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolSealer")
            .field("seq", &self.seq.load(Ordering::Relaxed))
            .finish()
    }
}

impl SymbolSealer {
    /// Build a sealer from TLS-exporter output.
    pub fn new(key: &[u8; SEAL_KEY_LEN]) -> Self {
        Self {
            cipher: aead_cipher(key),
            seq: AtomicU64::new(0),
        }
    }

    /// Allocate the next datagram sequence number.
    ///
    /// A `u64` cannot realistically wrap within one transfer session (at
    /// 10 million datagrams/second this takes ~58,000 years), so the counter
    /// uses a relaxed fetch-add without an overflow branch on the hot path.
    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Seal `body` in place under `seq` with `aad` as associated data,
    /// returning the detached tag to append.
    pub fn seal_in_place(
        &self,
        seq: u64,
        aad: &[u8],
        body: &mut [u8],
    ) -> io::Result<[u8; TAG_LEN]> {
        use chacha20poly1305::{AeadInPlace, Nonce};
        let nonce = seq_nonce(seq);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, body)
            .map_err(|_| io::Error::other("sealed transport: AEAD seal failed"))?;
        Ok(tag.into())
    }
}

/// Why an inbound sealed datagram was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolOpenError {
    /// Sequence number is a replay or fell behind the anti-replay window.
    Replay,
    /// AEAD authentication failed (forged, corrupted, or wrong key).
    BadTag,
}

/// Receiver-side per-datagram opener with an ESP-style anti-replay window.
pub struct SymbolOpener {
    cipher: chacha20poly1305::ChaCha20Poly1305,
    window: Mutex<ReplayWindow>,
}

impl std::fmt::Debug for SymbolOpener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolOpener").finish_non_exhaustive()
    }
}

impl SymbolOpener {
    /// Build an opener from TLS-exporter output.
    pub fn new(key: &[u8; SEAL_KEY_LEN]) -> Self {
        Self {
            cipher: aead_cipher(key),
            window: Mutex::new(ReplayWindow::new()),
        }
    }

    /// Verify + decrypt `body` in place. The replay window is only advanced
    /// after successful authentication so forged sequence numbers cannot
    /// poison it.
    pub fn open_in_place(
        &self,
        seq: u64,
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> Result<(), SymbolOpenError> {
        use chacha20poly1305::{AeadInPlace, Nonce, Tag};
        if tag.len() != TAG_LEN {
            return Err(SymbolOpenError::BadTag);
        }
        let mut window = self.window.lock().expect("replay window lock");
        if !window.would_accept(seq) {
            return Err(SymbolOpenError::Replay);
        }
        let nonce = seq_nonce(seq);
        if self
            .cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), aad, body, Tag::from_slice(tag))
            .is_err()
        {
            return Err(SymbolOpenError::BadTag);
        }
        window.commit(seq);
        Ok(())
    }

    /// Sequence-number span observed so far (`highest accepted + 1`), i.e.
    /// how many datagrams the sender has put on the wire toward us. Loss is
    /// `1 - accepted/span`, independent of what's still in flight.
    pub fn seq_span(&self) -> Option<u64> {
        let w = self.window.lock().expect("replay window lock");
        w.primed.then(|| w.highest + 1)
    }
}

// ─── Datagram framing ────────────────────────────────────────────────────────

/// Seal one symbol datagram: allocates the wire buffer, encrypts the body
/// (block index + encoding packet) in place, appends the tag.
pub fn seal_datagram(
    sealer: &SymbolSealer,
    transfer_tag: u64,
    block_index: u32,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(OVERHEAD + 4 + payload.len());
    seal_datagram_into(sealer, transfer_tag, block_index, payload, &mut buf)?;
    Ok(buf)
}

/// Seal one symbol datagram *appended* to `out` (batch building: no
/// per-packet buffer, AEAD runs in place inside the batch buffer).
pub fn seal_datagram_into(
    sealer: &SymbolSealer,
    transfer_tag: u64,
    block_index: u32,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let seq = sealer.next_seq();
    let start = out.len();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&transfer_tag.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&block_index.to_le_bytes());
    out.extend_from_slice(payload);
    let (aad, body) = out[start..].split_at_mut(HEADER_LEN);
    let tag = sealer.seal_in_place(seq, aad, body)?;
    out.extend_from_slice(&tag);
    Ok(())
}

/// Open one sealed datagram in place. Returns `None` (silent drop) on bad
/// magic, wrong transfer tag, truncation, replay, or authentication failure.
pub fn open_datagram<'a>(
    opener: &SymbolOpener,
    transfer_tag: u64,
    buf: &'a mut [u8],
) -> Option<(u32, &'a [u8])> {
    if buf.len() < OVERHEAD + 4 || buf[..4] != MAGIC {
        return None;
    }
    let wire_tag = u64::from_le_bytes(buf[4..12].try_into().unwrap());
    if wire_tag != transfer_tag {
        return None;
    }
    let seq = u64::from_le_bytes(buf[12..20].try_into().unwrap());
    let tag_start = buf.len() - TAG_LEN;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&buf[tag_start..]);
    let (aad, body) = buf[..tag_start].split_at_mut(HEADER_LEN);
    opener.open_in_place(seq, aad, body, &tag).ok()?;
    let block_index = u32::from_le_bytes(body[..4].try_into().unwrap());
    Some((block_index, &body[4..]))
}

// ─── Replay window ───────────────────────────────────────────────────────────

/// RFC 6479-style sliding anti-replay window over 64-bit sequence numbers.
struct ReplayWindow {
    bitmap: [u64; REPLAY_WINDOW_WORDS],
    highest: u64,
    primed: bool,
}

impl ReplayWindow {
    const fn new() -> Self {
        Self {
            bitmap: [0u64; REPLAY_WINDOW_WORDS],
            highest: 0,
            primed: false,
        }
    }

    fn would_accept(&self, seq: u64) -> bool {
        if !self.primed || seq > self.highest {
            return true;
        }
        let behind = self.highest - seq;
        if behind >= REPLAY_WINDOW_BITS {
            return false;
        }
        !self.is_set(seq)
    }

    fn commit(&mut self, seq: u64) {
        if !self.primed {
            self.primed = true;
            self.highest = seq;
            self.clear_range_for_advance(seq, REPLAY_WINDOW_BITS.min(seq + 1));
            self.set(seq);
            return;
        }
        if seq > self.highest {
            let advance = seq - self.highest;
            self.clear_range_for_advance(seq, advance.min(REPLAY_WINDOW_BITS));
            self.highest = seq;
        }
        self.set(seq);
    }

    /// Clear the bitmap slots that newly advanced sequence numbers map onto.
    fn clear_range_for_advance(&mut self, new_highest: u64, advance: u64) {
        if advance >= REPLAY_WINDOW_BITS {
            self.bitmap = [0u64; REPLAY_WINDOW_WORDS];
            return;
        }
        let mut cursor = new_highest + 1 - advance;
        while cursor <= new_highest {
            self.clear(cursor);
            cursor += 1;
        }
    }

    const fn slot(seq: u64) -> (usize, u64) {
        let bit = (seq % REPLAY_WINDOW_BITS) as usize;
        (bit / 64, 1u64 << (bit % 64))
    }

    fn is_set(&self, seq: u64) -> bool {
        let (word, mask) = Self::slot(seq);
        self.bitmap[word] & mask != 0
    }

    fn set(&mut self, seq: u64) {
        let (word, mask) = Self::slot(seq);
        self.bitmap[word] |= mask;
    }

    fn clear(&mut self, seq: u64) {
        let (word, mask) = Self::slot(seq);
        self.bitmap[word] &= !mask;
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(byte: u8) -> [u8; SEAL_KEY_LEN] {
        [byte; SEAL_KEY_LEN]
    }

    #[test]
    fn symbol_seal_open_roundtrip() {
        let key = test_key(8);
        let sealer = SymbolSealer::new(&key);
        let opener = SymbolOpener::new(&key);

        let aad = b"header-bytes-as-aad";
        let mut body = b"raptorq symbol payload".to_vec();
        let plain = body.clone();
        let seq = sealer.next_seq();
        let tag = sealer.seal_in_place(seq, aad, &mut body).expect("seal");
        assert_ne!(body, plain, "body must be encrypted");
        opener
            .open_in_place(seq, aad, &mut body, &tag)
            .expect("open");
        assert_eq!(body, plain);
    }

    #[test]
    fn symbol_open_rejects_wrong_key_and_wrong_aad() {
        let sealer = SymbolSealer::new(&test_key(1));
        let opener_wrong_key = SymbolOpener::new(&test_key(2));
        let opener_right_key = SymbolOpener::new(&test_key(1));

        let mut body = b"payload".to_vec();
        let seq = sealer.next_seq();
        let tag = sealer.seal_in_place(seq, b"aad", &mut body).expect("seal");

        let mut attempt = body.clone();
        assert_eq!(
            opener_wrong_key.open_in_place(seq, b"aad", &mut attempt, &tag),
            Err(SymbolOpenError::BadTag)
        );
        let mut attempt = body.clone();
        assert_eq!(
            opener_right_key.open_in_place(seq, b"tampered-aad", &mut attempt, &tag),
            Err(SymbolOpenError::BadTag)
        );
        // The failed attempts must not have advanced the replay window.
        let mut attempt = body.clone();
        opener_right_key
            .open_in_place(seq, b"aad", &mut attempt, &tag)
            .expect("legitimate open after failed forgeries");
    }

    #[test]
    fn symbol_open_rejects_replay_and_forgery() {
        let key = test_key(10);
        let sealer = SymbolSealer::new(&key);
        let opener = SymbolOpener::new(&key);

        let aad = b"aad";
        let mut body = b"payload".to_vec();
        let seq = sealer.next_seq();
        let tag = sealer.seal_in_place(seq, aad, &mut body).expect("seal");

        let mut copy = body.clone();
        opener
            .open_in_place(seq, aad, &mut copy, &tag)
            .expect("first delivery");

        // Exact replay is rejected before any decryption.
        let mut replayed = body.clone();
        assert_eq!(
            opener.open_in_place(seq, aad, &mut replayed, &tag),
            Err(SymbolOpenError::Replay)
        );

        // Forged tag under a fresh sequence number is rejected without
        // advancing the window.
        let mut forged = body.clone();
        assert_eq!(
            opener.open_in_place(seq + 1, aad, &mut forged, &[0u8; TAG_LEN]),
            Err(SymbolOpenError::BadTag)
        );

        // The legitimate next datagram still opens.
        let mut next = b"payload-two".to_vec();
        let next_seq = sealer.next_seq();
        let next_tag = sealer
            .seal_in_place(next_seq, aad, &mut next)
            .expect("seal");
        opener
            .open_in_place(next_seq, aad, &mut next, &next_tag)
            .expect("next delivery");
    }

    #[test]
    fn symbol_open_accepts_reordering_within_window() {
        let key = test_key(11);
        let sealer = SymbolSealer::new(&key);
        let opener = SymbolOpener::new(&key);
        let aad = b"aad";

        // Seal seq 0..5, deliver out of order: 3, 1, 4, 0, 2, 5.
        let mut sealed = Vec::new();
        for i in 0..6u64 {
            let seq = sealer.next_seq();
            assert_eq!(seq, i);
            let mut body = format!("payload-{i}").into_bytes();
            let tag = sealer.seal_in_place(seq, aad, &mut body).expect("seal");
            sealed.push((seq, body, tag));
        }
        for &index in &[3usize, 1, 4, 0, 2, 5] {
            let (seq, body, tag) = &sealed[index];
            let mut body = body.clone();
            opener
                .open_in_place(*seq, aad, &mut body, tag)
                .unwrap_or_else(|err| panic!("seq {seq} rejected: {err:?}"));
            assert_eq!(body, format!("payload-{seq}").into_bytes());
        }
        // Every one of them is now a replay.
        for (seq, body, tag) in &sealed {
            let mut body = body.clone();
            assert_eq!(
                opener.open_in_place(*seq, aad, &mut body, tag),
                Err(SymbolOpenError::Replay)
            );
        }
    }

    #[test]
    fn replay_window_expires_stale_sequences() {
        let mut window = ReplayWindow::new();
        window.commit(0);
        window.commit(REPLAY_WINDOW_BITS + 10);
        // seq 0 is far behind the window now.
        assert!(!window.would_accept(0));
        assert!(!window.would_accept(10));
        // In-window untouched slots are accepted.
        assert!(window.would_accept(REPLAY_WINDOW_BITS + 9));
        assert!(window.would_accept(11));
        // The committed head is a replay.
        assert!(!window.would_accept(REPLAY_WINDOW_BITS + 10));
    }

    #[test]
    fn replay_window_reused_slots_after_large_advance() {
        let mut window = ReplayWindow::new();
        // Commit a run, then jump far ahead; slots that alias modulo the
        // window width must have been cleared.
        for seq in 0..64u64 {
            window.commit(seq);
        }
        let jump = REPLAY_WINDOW_BITS * 3 + 7;
        window.commit(jump);
        for probe in (jump - 63)..jump {
            assert!(
                window.would_accept(probe),
                "slot for {probe} should be clear after advance"
            );
        }
        assert!(!window.would_accept(jump));
    }

    #[test]
    fn datagram_seal_open_round_trip_and_tamper() {
        let key = test_key(42);
        let sealer = SymbolSealer::new(&key);
        let opener = SymbolOpener::new(&key);

        let wire = seal_datagram(&sealer, 77, 5, b"encoding-packet-bytes").unwrap();
        assert_eq!(wire.len(), OVERHEAD + 4 + b"encoding-packet-bytes".len());
        // Payload must not appear in clear on the wire.
        assert!(!wire.windows(8).any(|w| w == b"encoding"));

        let mut copy = wire.clone();
        let (block, payload) = open_datagram(&opener, 77, &mut copy).expect("opens");
        assert_eq!(block, 5);
        assert_eq!(payload, b"encoding-packet-bytes");

        // Replay of the same datagram: dropped.
        let mut copy = wire.clone();
        assert!(open_datagram(&opener, 77, &mut copy).is_none());

        // Wrong transfer tag: dropped before any crypto.
        let wire2 = seal_datagram(&sealer, 77, 6, b"x").unwrap();
        let mut copy = wire2.clone();
        assert!(open_datagram(&opener, 78, &mut copy).is_none());

        // Flip one ciphertext bit: dropped.
        let wire3 = seal_datagram(&sealer, 77, 7, b"y").unwrap();
        let mut tampered = wire3.clone();
        tampered[HEADER_LEN] ^= 1;
        assert!(open_datagram(&opener, 77, &mut tampered).is_none());
        // Untampered copy still opens (window not poisoned).
        let mut copy = wire3.clone();
        assert!(open_datagram(&opener, 77, &mut copy).is_some());
    }
}
