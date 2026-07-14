# atp-experiment — a RaptorQ transmission protocol, from scratch

## The point

Demo a cool transmission protocol. Not an rsync replacement — no metadata
preservation, no delta resync, no journal/resume, no daemon, no
compatibility surface. A single binary that moves bytes in a way TCP-based
tools fundamentally can't, and is fun to watch doing it.

## Main technical goal: TLS key exchange + kernel-UDP data plane

The original atp repo documents the encrypted-tier gap (`../atp/README.md`:
"userspace QUIC vs kernel TCP"): its only encrypted transport was QUIC, and
userspace QUIC — packetization, ACKs, congestion control, crypto framing
all in userspace — lost ~1.5× to kernel-TCP tools on clean links.

atp-experiment's answer, the **sealed tier**:

- **TLS 1.3 for key exchange only.** Real rustls handshake over the TCP
  control connection: ECDHE, certificate identity, forward secrecy. No PSK,
  no key material on the wire.
- **Kernel UDP for data.** Both peers derive a 32-byte session key via the
  RFC 8446 §7.5 keying-material exporter; every UDP datagram is sealed with
  per-datagram AEAD (ChaCha20-Poly1305, explicit seq, replay window —
  `sealed.rs`, already written and runtime-agnostic).
- **RaptorQ instead of retransmission.** Loss is repaired by fountain-code
  overhead, not round trips. On a lossy/high-latency link there is no
  retransmit stall, no congestion-collapse backoff — the receiver just
  collects any K-ish symbols and decodes.
- **GSO/sendmmsg spray.** Line-rate UDP batching with the kernel doing
  segmentation; crypto is one AEAD pass per datagram (the same bill ssh
  pays), transport logic stays in the kernel.

## The demo

The punchline is loss tolerance. Side-by-side on a netem link
(latency + loss sweep, e.g. 50 ms / 0–10% loss): scp/any-TCP-tool
collapses; atp-experiment throughput stays roughly flat until overhead runs out.

- `atp-experiment recv` prints a self-signed cert fingerprint (SSH-style);
  `atp-experiment send --pin <fp>` connects. Zero cert ceremony (rcgen), real crypto.
- Live TUI-ish progress: symbols sprayed / received / decoded, loss
  estimate, effective rate. Watching decode complete *through* 10% loss is
  the demo.
- `demo/` scripts: netns + netem setup, loss sweep, comparison table
  (adapted from the old repo's `scripts/atp_bench/` harness).

## What gets written vs. reused

| Piece | Source | ~lines |
|---|---|---|
| RaptorQ codec | `raptorq` crate (cberner, RFC 6330, SIMD) — dependency | 0 |
| Symbol-plane AEAD (`sealed.rs`) | already written this week; moves as-is | 0.5k |
| Async runtime | tokio + tokio-rustls | 0 |
| Wire format: control frames (hello, manifest, feedback/NeedMore, done) | new — serde + length-prefixed frames over TCP/TLS | ~0.5k |
| UDP datagram format + spray/receive loops | new; sealed layout from this week's design (magic ‖ tag ‖ seq ‖ AEAD body) | ~1.5k |
| GSO/sendmmsg batching on `AsyncFd<socket2::Socket>` | new, with old `net/udp.rs` cmsg code as reference | ~0.8k |
| Sender pacing + adaptive overhead (start simple: `--rate`, then loss-driven) | new; tuning constants read from old transport_rq as documentation | ~0.5k |
| Block scheduler: file → blocks → symbols, feedback loop, sha256 verify | new | ~1.5k |
| CLI (`send`, `recv`, `--pin`, rates/knobs) + progress display | new | ~0.8k |
| demo harness | adapted from old scripts | shell |

Total: **~6k lines of Rust**, seconds-fast rebuilds, every piece testable in
isolation. The old asupersync/atp tree is reference reading only — the copied
tree currently in this repo moves to `reference/` (or gets deleted on your
say-so) and nothing links against asupersync.

Deps: tokio, tokio-rustls, rustls, rcgen, raptorq, socket2, libc,
chacha20poly1305, sha2, hex, serde, serde_json, thiserror, clap.

## Phases

1. **Skeleton + plaintext loopback transfer.** Crate, CLI, control frames,
   naive UDP spray (no GSO), `raptorq` encode/decode, sha256-verified
   file transfer over loopback. *Proves the shape end-to-end.*
2. **Sealed tier.** rcgen self-signed + fingerprint pinning, rustls over the
   control stream, exporter-derived key, drop `sealed.rs` onto the datagram
   path. Mismatch/tamper/replay tests.
3. **Speed.** GSO/sendmmsg batching, recvmmsg/GRO, pacing, adaptive repair
   overhead from receiver feedback. Loopback + netem tuning until the
   loss-sweep curve looks the part.
4. **Demo polish.** Progress display, `demo/` netns scripts, loss-sweep
   table/chart, README with the pitch.

Microbench early in phase 1: `raptorq` crate encode/decode throughput at our
symbol sizes (~1200 B) to confirm it sustains multi-Gbps; fall back to
vendoring the old codec only if it can't.

## Non-goals (v1)

- rsync parity of any kind: metadata, permissions-fidelity, delta, resume
- channel bonding / multi-donor
- QUIC (the sealed tier exists to make it unnecessary)
- HMAC-tier (`auth`) compatibility with old atp — sealed and nocrypto only
- Windows/macOS datapath (GSO is Linux; others can fall back later)
