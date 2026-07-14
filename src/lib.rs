//! atp-experiment — RaptorQ transmission protocol demo.
//!
//! TLS 1.3 for key exchange over the TCP control connection; kernel UDP
//! for data, sealed with per-datagram AEAD under an exporter-derived key;
//! RaptorQ fountain coding instead of retransmission. See PLAN.md.

pub mod blocks;
pub mod datagram;
pub mod error;
pub mod rate;
pub mod recv;
pub mod sealed;
pub mod send;
pub mod tls;
pub mod udp;
pub mod wire;
