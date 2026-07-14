//! UDP symbol-plane datagram formats.
//!
//! Plaintext (`--nocrypto`) layout:
//!
//! ```text
//! magic "ATP2" (4) ‖ transfer_tag (8, LE) ‖ block_index (4, LE) ‖ payload
//! ```
//!
//! `payload` is a serialized `raptorq::EncodingPacket` (4-byte payload id +
//! symbol data). The sealed (default) layout lives in [`crate::sealed`];
//! [`TxPlane`]/[`RxPlane`] pick between the two at runtime.

use crate::sealed::{self, SymbolOpener, SymbolSealer};

/// Wire magic for plaintext datagrams.
pub const MAGIC: [u8; 4] = *b"ATP2";

/// Clear-header length.
pub const HEADER_LEN: usize = 4 + 8 + 4;

/// A parsed datagram, borrowing the payload from the receive buffer.
#[derive(Debug)]
pub struct Datagram<'a> {
    pub block_index: u32,
    pub payload: &'a [u8],
}

/// Encode a datagram into a fresh buffer.
pub fn encode(transfer_tag: u64, block_index: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    encode_into(transfer_tag, block_index, payload, &mut buf);
    buf
}

/// Encode a plaintext datagram appended to `out`.
pub fn encode_into(transfer_tag: u64, block_index: u32, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&transfer_tag.to_le_bytes());
    out.extend_from_slice(&block_index.to_le_bytes());
    out.extend_from_slice(payload);
}

/// Parse a datagram; returns `None` on bad magic, tag mismatch, or truncation.
pub fn decode(transfer_tag: u64, buf: &[u8]) -> Option<Datagram<'_>> {
    if buf.len() < HEADER_LEN || buf[..4] != MAGIC {
        return None;
    }
    let tag = u64::from_le_bytes(buf[4..12].try_into().unwrap());
    if tag != transfer_tag {
        return None;
    }
    let block_index = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    Some(Datagram { block_index, payload: &buf[HEADER_LEN..] })
}

/// Sender-side datagram encoder: plaintext or sealed.
pub enum TxPlane {
    Plain,
    Sealed(SymbolSealer),
}

impl TxPlane {
    pub fn encode(
        &self,
        transfer_tag: u64,
        block_index: u32,
        payload: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        match self {
            TxPlane::Plain => Ok(encode(transfer_tag, block_index, payload)),
            TxPlane::Sealed(sealer) => {
                sealed::seal_datagram(sealer, transfer_tag, block_index, payload)
            }
        }
    }

    /// Append one datagram to a batch buffer (GSO super-buffer building).
    pub fn encode_into(
        &self,
        transfer_tag: u64,
        block_index: u32,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> std::io::Result<()> {
        match self {
            TxPlane::Plain => {
                encode_into(transfer_tag, block_index, payload, out);
                Ok(())
            }
            TxPlane::Sealed(sealer) => {
                sealed::seal_datagram_into(sealer, transfer_tag, block_index, payload, out)
            }
        }
    }

    /// On-the-wire datagram size for a given payload length.
    pub fn wire_len(&self, payload_len: usize) -> usize {
        match self {
            TxPlane::Plain => HEADER_LEN + payload_len,
            TxPlane::Sealed(_) => sealed::OVERHEAD + 4 + payload_len,
        }
    }

    /// Consume a sequence number without sending (test-drop simulation:
    /// a real network drop still consumes seq space on the receiver side).
    pub fn burn_seq(&self) {
        if let TxPlane::Sealed(sealer) = self {
            sealer.next_seq();
        }
    }
}

/// Receiver-side datagram opener: plaintext or sealed (verify + decrypt +
/// replay check; failures are a silent `None`).
pub enum RxPlane {
    Plain,
    // Boxed: the opener carries a 4096-bit replay window.
    Sealed(Box<SymbolOpener>),
}

impl RxPlane {
    pub fn open<'a>(&self, transfer_tag: u64, buf: &'a mut [u8]) -> Option<(u32, &'a [u8])> {
        match self {
            RxPlane::Plain => {
                decode(transfer_tag, buf).map(|dg| (dg.block_index, dg.payload))
            }
            RxPlane::Sealed(opener) => sealed::open_datagram(opener, transfer_tag, buf),
        }
    }

    /// Sequence span for loss measurement (sealed mode only).
    pub fn seq_span(&self) -> Option<u64> {
        match self {
            RxPlane::Plain => None,
            RxPlane::Sealed(opener) => opener.seq_span(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let wire = encode(42, 7, b"symbol-bytes");
        let dg = decode(42, &wire).expect("decodes");
        assert_eq!(dg.block_index, 7);
        assert_eq!(dg.payload, b"symbol-bytes");
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode(42, b"short").is_none());
        let wire = encode(42, 7, b"x");
        assert!(decode(43, &wire).is_none(), "wrong tag");
        let mut bad = wire.clone();
        bad[0] ^= 0xff;
        assert!(decode(42, &bad).is_none(), "wrong magic");
    }
}
