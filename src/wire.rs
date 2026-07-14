//! Control-plane frames: length-prefixed JSON over the TCP connection.
//!
//! Phase 1 runs these in plaintext; phase 2 wraps the same stream in TLS.
//! Frames are small and rare (handshake + one ack per decoded block), so
//! JSON keeps them debuggable at zero real cost.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// Control-protocol version.
pub const VERSION: u32 = 2;

/// Upper bound on a single control frame, to keep a malicious peer from
/// asking us to buffer gigabytes.
const MAX_FRAME_LEN: u32 = 1 << 20;

/// A control frame. Sender → receiver: `Hello`, `Manifest`.
/// Receiver → sender: `HelloAck`, `ManifestAck`, `BlockDecoded`, `Done`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Frame {
    Hello {
        version: u32,
        /// Random per-transfer tag; echoed in every UDP datagram so the
        /// receiver can discard strays.
        transfer_tag: u64,
    },
    HelloAck {
        /// UDP port the receiver bound for the symbol plane.
        udp_port: u16,
    },
    Manifest {
        file_name: String,
        file_size: u64,
        /// Hex-encoded SHA-256 of the whole file.
        sha256: String,
        block_size: u32,
        symbol_size: u16,
        num_blocks: u32,
    },
    ManifestAck,
    /// Receiver decoded this block; sender can stop generating repair for it.
    BlockDecoded { index: u32 },
    /// Periodic receiver report (~100 ms cadence): authenticated datagrams
    /// received so far, and (sealed mode) the sequence-number span they
    /// arrived from. The sender derives its loss estimate as
    /// `1 - pkts/span`, which is exact wire loss — unskewed by datagrams
    /// still in flight — and feeds interval deltas to the adaptive rate
    /// controller (`rate.rs`). `t_ms` is the receiver's monotonic clock
    /// (ms since transfer start): interval durations must be measured
    /// where the packets are counted — sender-side arrival times of these
    /// frames jitter with the return path and would corrupt the delivered-
    /// rate estimate.
    Progress { pkts: u64, span: Option<u64>, t_ms: u64 },
    /// Receiver finished (all blocks decoded and hash checked).
    Done { ok: bool, error: Option<String> },
}

/// Write one length-prefixed frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<()> {
    let body = serde_json::to_vec(frame)?;
    let len = u32::try_from(body.len()).map_err(|_| Error::protocol("frame too large"))?;
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(Error::protocol(format!("frame length {len} exceeds limit")));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let frames = [
            Frame::Hello { version: VERSION, transfer_tag: 0xdead_beef },
            Frame::HelloAck { udp_port: 12345 },
            Frame::Manifest {
                file_name: "x.bin".into(),
                file_size: 1,
                sha256: "00".into(),
                block_size: 2,
                symbol_size: 3,
                num_blocks: 4,
            },
            Frame::ManifestAck,
            Frame::BlockDecoded { index: 7 },
            Frame::Progress { pkts: 123_456, span: Some(130_000), t_ms: 2_500 },
            Frame::Done { ok: false, error: Some("nope".into()) },
        ];
        let mut buf = Vec::new();
        for f in &frames {
            write_frame(&mut buf, f).await.unwrap();
        }
        let mut cursor = &buf[..];
        for f in &frames {
            let got = read_frame(&mut cursor).await.unwrap();
            assert_eq!(format!("{f:?}"), format!("{got:?}"));
        }
    }
}
