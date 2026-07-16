//! Microbench for the `raptorq` crate at atp-experiment's operating point (~1200 B
//! symbols, ~1 MiB blocks). Run with:
//!
//! ```sh
//! cargo run --release --example rq_bench -- [total_mib] [block_kib] [symbol_bytes]
//! ```
//!
//! PLAN.md gate: encode+decode must sustain multi-Gbps or we vendor a codec.

use std::time::Instant;

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};

fn main() {
    let mut args = std::env::args().skip(1);
    let total_mib: usize = args.next().map_or(64, |s| s.parse().unwrap());
    let block_kib: usize = args.next().map_or(1024, |s| s.parse().unwrap());
    let symbol: u16 = args.next().map_or(1200, |s| s.parse().unwrap());

    let block_len = block_kib * 1024;
    let num_blocks = (total_mib * 1024 * 1024).div_ceil(block_len);
    let total = num_blocks * block_len;
    println!(
        "bench: {num_blocks} blocks × {block_kib} KiB, symbol {symbol} B ({} MiB total)",
        total / (1024 * 1024)
    );

    // Deterministic pseudo-random block (xorshift64*), reused for every block.
    let mut block = vec![0u8; block_len];
    let mut x: u64 = 0x9e3779b97f4a7c15;
    for chunk in block.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let bytes = x.wrapping_mul(0x2545f4914f6cdd1d).to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }

    let repair_per_block = ((block_len as f64 / symbol as f64) * 0.05).ceil() as u32;

    // --- encode -----------------------------------------------------------
    let t = Instant::now();
    let mut all_packets: Vec<Vec<EncodingPacket>> = Vec::with_capacity(num_blocks);
    for _ in 0..num_blocks {
        let enc = Encoder::with_defaults(&block, symbol);
        all_packets.push(enc.get_encoded_packets(repair_per_block));
    }
    let enc_s = t.elapsed().as_secs_f64();
    println!(
        "encode: {:.2} s, {:.2} Gbit/s ({} pkts/block incl. {repair_per_block} repair)",
        enc_s,
        total as f64 * 8.0 / 1e9 / enc_s,
        all_packets[0].len(),
    );

    // --- decode with 3% loss ------------------------------------------
    let config = ObjectTransmissionInformation::with_defaults(block_len as u64, symbol);
    let t = Instant::now();
    for packets in all_packets {
        let mut dec = Decoder::new(config);
        let mut out = None;
        let mut i = 0usize;
        for pkt in packets {
            i += 1;
            if i.is_multiple_of(33) {
                continue; // ~3% simulated loss
            }
            if let Some(data) = dec.decode(pkt) {
                out = Some(data);
                break;
            }
        }
        let out = out.expect("decode completed despite loss");
        assert_eq!(out.len(), block_len);
        assert_eq!(out[..64], block[..64]);
    }
    let dec_s = t.elapsed().as_secs_f64();
    println!(
        "decode: {:.2} s, {:.2} Gbit/s (3% simulated loss)",
        dec_s,
        total as f64 * 8.0 / 1e9 / dec_s
    );
}
