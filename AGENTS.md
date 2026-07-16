# AGENTS.md — atp-experiment

Read `PLAN.md` first. It is the spec: goals, architecture, phases, scope
cuts. This file is just operational context.

## What this repo is

A from-scratch RaptorQ transmission protocol demo (**not** an rsync
replacement, **not** part of asupersync). Encrypted UDP data plane keyed by
a TLS 1.3 exporter, loss repaired by fountain coding instead of
retransmission. Single binary, `send`/`recv`.

## Status

- **Phase:** 4 complete — demo-ready. Adaptive rate control, rootless
  netem harness, WAN-validated vs rsync-ssh, top-level README pitch.
- **Pull mode (client-initiated download)** added on top of 4: `send
  --listen`/`recv --connect` invert who dials, so the client opens both the
  TCP control connection and the UDP data flow (a first `flow_open`
  datagram — `datagram.rs`; the sender learns the client's address from it,
  since a NAT'd endpoint is only observable from outside). Data still flows
  sender→receiver; this just makes it traverse a receiver's NAT the way any
  download does. Push mode (`send <dest>`) is unchanged/default. Control
  wire bumped to VERSION 3 (`Hello.data_port`, `HelloAck.udp_port` now
  optional). Not hole-punching (server is public); no STUN/ICE. Sealed pull
  mode needs the receiver's cert pinned ahead of time — chicken-and-egg,
  so pull demos use `--nocrypto` until a persistent/pre-shared identity
  exists. `spawn_flow_keepalive` refreshes the mapping on slow transfers.
  Test: `pull_mode_plaintext` in `tests/loopback.rs`.
  - Phase 1: control frames (`src/wire.rs`, length-prefixed JSON over TCP
    — control plane only, data plane is raw byte layout), block layout
    (`src/blocks.rs`), sender spray + feedback-driven repair rounds
    (`src/send.rs`), receiver decode + sha256 verify (`src/recv.rs`).
    `examples/rq_bench.rs`: raptorq sustains ≈3.2/3.8 Gbit/s enc/dec at
    1200 B symbols — no vendored codec needed.
  - Phase 2: `src/tls.rs` (rcgen self-signed identity, SHA-256 fingerprint
    pinning via custom rustls verifier that still checks the handshake
    signature, TLS 1.3 only — no tls12 feature, ring provider, exporter
    key derivation), `src/sealed.rs` (port of the sealed-datagram design
    written for this project:
    ChaCha20-Poly1305 per-datagram AEAD, seq nonces, RFC 6479 replay
    window, `ATRS ‖ tag ‖ seq` header as AAD + encrypted body). Sealed is
    the default; `--nocrypto` keeps the plaintext tier for comparison.
    Tests: tamper/replay/wrong-key/reorder units, sealed + plaintext e2e
    loopback, wrong-pin and missing-pin rejection.
  - Phase 3: `src/udp.rs` — GSO (`UDP_SEGMENT`) send batching (~52
    datagrams/syscall) with `sendmmsg` fallback, GRO (`UDP_GRO`) +
    `recvmmsg` receive batching, raw libc cmsg on `AsyncFd<socket2>`.
    Batch buffers with seal-in-place (no per-packet allocs on the hot
    path). Loss-adaptive repair: receiver reports authenticated count +
    seq-number span (sealed seq gives *exact* wire loss, unskewed by
    in-flight data — do NOT regress to sent-vs-received comparison, and
    never let a pkts=0 report prime the estimator). Ack-settle between
    repair rounds. `--test-drop` (hidden) simulates send-path loss and
    burns seq space like a real drop; `--rate-mbps 0` = unpaced.
  - 1 GiB sealed loopback, unpaced: ≈1.84 Gbit/s at 91.8% wire
    efficiency; goodput stays flat through simulated loss (2%→1.87,
    5%→1.72, 10%→1.67, 20%→1.63 Gbit/s, all >90% efficient). Receiver
    single-thread decode+AEAD is the current ceiling.
- **Phase 4 detail** (progress display/TUI: cut on user's call; repo is
  demo-ready — remaining ideas live under "known waste" below):
  - Done: `demo/remote_bench.sh` — real-internet bench vs tuned
    rsync-ssh/scp over any ssh host (see `demo/README.md`). Local-only
    harness: rsyncs the release binary to `~/.cache/atp-experiment-bench/` on the
    remote, everything else is inline ssh; no scripts shipped. First
    results (home→Linode, 42 ms, ~500 Mbit): atp-experiment sealed wins all cells,
    0.30×/0.75×/0.96× rsync-ssh wall time at 8/64/256 MiB (static
    `--rate-mbps 450`, pre-controller).
  - Done: adaptive rate control (`src/rate.rs`), now the default —
    delivery-rate-matching controller, BBR-flavored. Backs off only on
    *excess* loss above an intrinsic-loss floor — stochastic (netem-style)
    loss must never starve the rate; do NOT regress to absolute-loss
    back-off. Hard-won invariants (each fixed a real netem failure, see
    the module docs + sim tests): interval durations come from the
    receiver clock (`t_ms` in Progress; sender-side arrival jitter
    inflates delivered into the max filter); cuts go to max-delivered
    *without* loss credit, deliberately undershooting the pipe so the
    floor gets re-measured (cheap PROBE_RTT — a controller that never
    dips below the bottleneck ratchets upward forever); cuts force ≥10%
    reduction; the floor never relaxes during cut cooldown (queue-drain
    samples are stale) and tracks down exponentially (single lucky
    intervals on bursty links must not pin it); growth needs ≥90%-
    saturated intervals (repair-round bursts fit in the queue and read
    "clean at high rate"); startup aborts on one raw interval ≥15% over
    floor (smoothed signal is one doubling too slow). Repair sizing
    (`LossEstimator`) is interval-based, not lifetime-cumulative.
    Receiver Progress cadence is 100 ms. `--rate-mbps` pins static
    (0 = unpaced), `--max-rate-mbps` caps adaptive. There is deliberately
    NO flag that changes datapath behavior for testing (a `--no-gso`
    flag existed briefly and was removed on principle — and removing it
    exposed a real emulation bug, see netns.sh below): benchmarks must
    run the shipped GSO path.
  - Done: `demo/netns.sh` — rootless (no sudo) netns pair via an
    unprivileged user namespace: `up`/`exec a|b`/`netem …`/`down`,
    project-private veth on 10.77.0.0/24, invisible to the host.
    Loss sweep, 256 MiB @ netem 500 Mbit/50 ms/limit 5000, adaptive:
    313/328/317/283 Mbit/s goodput at 0/5/10/20% loss (84/≈75/66/52%
    wire efficiency) — goodput flat through 20% loss. Loopback
    unaffected: 91.8% eff, adaptive finds the receiver decode ceiling.
    The `netem` subcommand stacks root tbf → child netem — load-bearing:
    qdiscs act on qdisc packets, so root netem applied to a GSO sender
    drops whole ~64 KB super-packets (52-datagram loss bursts) and
    counts them singly against `limit` (5000 pkts ≈ 320 MB of
    bufferbloat, which drowned the TCP feedback channel and stalled
    block acks for entire repair rounds). tbf segments GSO skbs at
    enqueue, so netem sees real MTU packets — fix the emulator, never
    the system under test. Re-swept on the shipped GSO path (medians of
    3): 315/347/346/258 Mbit/s at 0/5/10/20% loss.
  - Done: WAN re-validation with adaptive default (home→Linode, 42 ms,
    GSO on): 0.63/2.10/5.59 s at 8/64/256 MiB — 0.45×/0.82×/0.85×
    rsync-ssh. Beats the old hand-probed static 450 at 256 MiB (5.59 vs
    6.30 s; controller found ~832 Mbit/s send rate, 83% wire eff); pays
    a slow-start tax at 8 MiB (0.63 vs 0.42 s, ends mid-ramp).
    Remaining known waste: startup overshoot burn (~1 doubling); late
    repair symbols for already-decoded blocks at high loss (22% of
    received pkts at 20% loss); `LossEstimator` absorbs app-limited
    repair-burst samples (WAN logs show est loss drifting 5→33% across
    repair rounds at fixed pacing), oversizing late repair — all repair
    scheduling, not rate control.
- Note: `[profile.dev.package."*"] opt-level = 3` in Cargo.toml is
  load-bearing — raptorq at opt-level 0 makes tests take minutes.

## Hard rules

- **Never depend on, import from, or link against asupersync.** The old
  implementation (Dicklesworthstone/asupersync's atp; a `reference/`
  salvage mirror existed during development and was purged — along with
  all pre-publication history — before the initial public commit) was
  reference reading only. If something
  is worth reusing, copy it in sparingly, make it idiomatic here, and
  keep the attribution in README § Provenance & credit truthful — the
  original is MIT + a rider restricting OpenAI/Anthropic-affiliated use;
  the owner's position is ethical attribution over provenance laundering
  (no fake clean-room rewrites: an agent that has read the code cannot
  un-read it, and the original was agent-written from spec anyway).
- Keep it small. The whole point is a ~6k-line crate that rebuilds in
  seconds. Reject scope creep (metadata fidelity, resume, bonding, QUIC,
  Windows datapath — see PLAN.md non-goals).
- Plain `cargo build` / `cargo test` locally. No rch, no remote workers,
  no bead/mail tooling in this repo.
- **Run `cargo fmt` before committing** — the tree must be `cargo fmt
  --check` clean. Don't hand-format; let rustfmt decide, and don't leave
  fmt drift for the next session to churn.
- Keep `cargo clippy --all-targets` warning-free too.

## Key design facts (from the sealed-tier work that led here)

- Sealed datagram layout: `magic("ATRS") ‖ transfer_tag(8) ‖ seq(8)` clear
  header as AEAD AAD, encrypted body, 16-byte tag. 24 B overhead/datagram.
- Symbol key: 32 bytes via RFC 8446 §7.5 exporter, label
  `EXPORTER-atp-rq-sealed-v1-symbol-key`, empty context. With tokio-rustls,
  export off `conn.get_ref().1`.
- Replay window: 4096-bit RFC 6479 style, advance only after successful
  auth. Drop failures silently before touching decoder state.
- Symbol size ~1200 B (fits datagram + overhead under common MTU); GSO
  batches many datagrams per sendmmsg.
- Demo trust model: rcgen self-signed on recv, SHA-256 fingerprint printed,
  sender pins with `--pin` (SSH-style). No CA ceremony.
