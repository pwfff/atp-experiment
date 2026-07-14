# atp-experiment

> **⚠️ Warning: unvetted AI slop.** This entire codebase was written by an
> LLM coding agent. The human who owns this repo has not read the code.
> The benchmark numbers below were produced by the same agent that wrote
> the code it was benchmarking. Do not mistake any of this for reviewed,
> trustworthy software — especially not the cryptography.

Encrypted single-file transfer that treats packet loss as arithmetic
instead of tragedy. TLS 1.3 negotiates the keys; the payload travels as
AEAD-sealed UDP datagrams carrying RaptorQ fountain-code symbols, so lost
packets are never retransmitted — the stream is simply oversized by the
measured loss rate until the file decodes. One binary, `send`/`recv`,
~6k lines of Rust.

```
$ atp-experiment recv out.bin --listen 0.0.0.0:9440
recv: cert sha256 fingerprint (give to sender as --pin):
recv:   055951b19c666f1f0e920b846b9aa2dee8a8270cc84d8694dabd64e10f765c8d

$ atp-experiment send big.bin host:9440 --pin 055951b19c666f1f0e920b846b9aa2dee8a8270cc84d8694dabd64e10f765c8d
send: complete in 5.59s — 384.3 Mbit/s goodput
```

## Why

TCP (and everything on it: scp, rsync, https) reads packet loss as
congestion and halves its window. On a path with real stochastic loss its
throughput is bounded by `MSS / (RTT·√p)` — at 50 ms RTT and 5% loss
that's about **1 Mbit/s, no matter how fat the pipe is**. The loss isn't
costing you 5%; it's costing you 99%.

A fountain code inverts the economics. Any `k` of `k+ε` symbols decode a
block, so a 5% lossy link is just a link with 5% overhead tax — *if* the
sender keeps its rate matched to what the path actually delivers, backing
off only when loss *exceeds* the link's intrinsic floor (congestion)
rather than on loss itself. That controller (`src/rate.rs`) plus sealed
datagrams is the whole trick.

## Measured

**Real internet** (42 ms RTT, ~500 Mbit path, clean link — TCP's best
case), adaptive pacing, medians, SHA-256 verified, vs rsync-over-ssh at
its fastest configuration (`-aW --inplace`, no compression, aes128-gcm):

| payload | atp-experiment (sealed) | rsync-ssh | wall ratio |
|---|---|---|---|
| 8 MiB | 0.63 s (106 Mbit/s) | 1.40 s (48 Mbit/s) | **0.45** |
| 64 MiB | 2.10 s (256 Mbit/s) | 2.54 s (211 Mbit/s) | **0.82** |
| 256 MiB | 5.59 s (384 Mbit/s) | 6.56 s (327 Mbit/s) | **0.85** |

Small transfers win on handshake economics (one TLS round trip, then
spray); large ones on ramp speed and wire efficiency. No rate flag was
set — the controller found the path by itself.

**Emulated loss** (256 MiB, 500 Mbit / 50 ms RTT, `tc netem`, medians
of 3): goodput holds **315 / 347 / 346 / 258 Mbit/s at 0 / 5 / 10 / 20%
loss**. The TCP formula gives rsync ~1 Mbit/s at the 5% point of that
table. Reproduce with `demo/netns.sh` (rootless netns + netem pair, no
sudo) — see `demo/README.md`.

## Design

- **Control plane**: TCP + rustls, TLS 1.3 only. The receiver generates a
  throwaway self-signed cert (rcgen) and prints its SHA-256 fingerprint;
  the sender pins it with `--pin` — SSH-style trust, zero CA ceremony,
  and the pin is verified against the actual handshake signature.
- **Key bridge**: a 32-byte symbol key is derived from the TLS session
  via the RFC 8446 §7.5 exporter. No second key exchange, no key on the
  wire; the UDP plane inherits the TLS channel's authentication.
- **Data plane**: kernel UDP, not QUIC. Each ~1200 B RaptorQ symbol rides
  one datagram: `ATRS ‖ transfer_tag ‖ seq` in clear as AEAD associated
  data, ChaCha20-Poly1305 body, 24 B total overhead. Sequence numbers
  drive an RFC 6479 replay window, and — because they're authenticated —
  give the receiver an *exact* wire-loss measurement for free.
- **Batching**: GSO (`UDP_SEGMENT`) sends ~52 datagrams per syscall with
  `sendmmsg` fallback; GRO + `recvmmsg` on receive; seal-in-place, no
  per-packet allocation.
- **Repair**: the file is 1 MiB blocks; the receiver acks decoded blocks
  and reports authenticated-packet counts at 100 ms cadence; the sender
  sprays repair symbols sized by the measured interval loss until every
  block decodes, then the receiver verifies SHA-256 end-to-end.
- **Rate control**: delivery-rate matching. Startup doubles until the
  delivered rate plateaus; steady state cuts only on loss in excess of
  the measured intrinsic floor, deliberately dipping below the bottleneck
  after each cut so the floor re-measures. Random loss does not slow it
  down; a filling queue does. `--rate-mbps` pins a static rate if you
  want the controller out of the picture.

`--nocrypto` runs a plaintext tier of the same protocol for comparison.

## Build & test

Linux only (GSO/GRO, `sendmmsg`). `cargo build --release`, `cargo test`.
`demo/remote_bench.sh <ssh-host>` reproduces the WAN table against any
host you have ssh access to; `demo/netns.sh` builds the loss-sweep link.

## Provenance & credit

atp-experiment descends from [atp](https://github.com/Dicklesworthstone/atp) by
Jeffrey Emanuel ([asupersync](https://github.com/Dicklesworthstone/asupersync)),
which is the origin of the core idea as productized software — RaptorQ
fountain symbols over UDP beating TCP tools on real networks — and of the
benchmark methodology this repo's `demo/` harness follows (incompressible
payloads, tuned-rsync opponent, medians, verified transfers, failures
reported). The judgment atp-experiment exists to demonstrate — that the original's
clean-link gap came from running a userspace QUIC transport, and that a
TLS-1.3-keyed, AEAD-sealed **kernel**-UDP data plane closes it — belongs
to this repo's owner. The sealed-datagram module (`src/sealed.rs`) was
ported from a prototype written (by a coding agent) inside the asupersync
tree for that design, and low-level GSO/`sendmmsg` handling details
derive from the original's UDP code; the rest of this crate was written
fresh here, also by agents, at every step.

The original carries an MIT license with a rider denying use to
OpenAI/Anthropic and parties acting on their behalf. This repo was built
entirely by such an agent, openly.

## License

[AGPL-3.0-or-later](LICENSE) — a deliberate choice: this is a tech demo,
not a product, and if it's useful the terms ensure improvements flow
back, network services included. Two honest qualifiers: the license can
only speak for what is original here (the sealed module's ancestry
carries the original's terms, linked above), and since this code is
openly agent-written and unreviewed, its copyright status — and thus the
copyleft's teeth — is legally murky. Treat the AGPL here as a clear
statement of intent.

## What this is not

A demo, deliberately small: one file per invocation, no resume, no
metadata fidelity, no directory trees, no congestion-control fairness
proofs, no Windows. The point is the shape of the thing — TLS-keyed
sealed UDP + fountain repair + excess-loss rate control — and the
numbers above.
