# demo/ — benchmark harnesses

## netns.sh — rootless netem link (no sudo)

A project-private network namespace pair for loss/latency benchmarks.
One unprivileged user namespace owns two net namespaces joined by a veth
pair on `10.77.0.0/24`; inside it we hold `CAP_NET_ADMIN`, so `tc netem`
works without root. The host sees no interface, no route, no netns name —
nothing else can touch the link. State is held by two pause processes
(per-user, gone on `down` or reboot).

```bash
demo/netns.sh up
demo/netns.sh netem delay 25ms loss 5% rate 500mbit limit 5000   # per direction
demo/netns.sh exec b target/release/atp-experiment recv /tmp/out.bin --listen 10.77.0.2:9440 &
demo/netns.sh exec a target/release/atp-experiment send FILE 10.77.0.2:9440 --pin <fp>
demo/netns.sh down
```

The `netem` subcommand realizes `rate` as a root tbf with netem as its
child rather than netem's own rate stage. This matters for fidelity, not
taste: qdiscs act on qdisc packets, and a GSO sender emits ~64 KB
super-packets — root netem would drop whole super-packets (52-datagram
loss bursts no real path produces) and count them singly against `limit`
(a 5000-packet queue silently becomes ~320 MB of bufferbloat that drowns
the TCP feedback channel). tbf segments GSO skbs at enqueue, so netem
sees, drops, delays, and queues real MTU-sized packets — the same thing
a bottleneck router sees after the sender's NIC segments. The system
under test runs exactly its production datapath; only the emulator is
corrected. Sanity-check with `tc -s qdisc` (netem's pkt count must match
datagrams sent). Pick `limit` around 2× the bandwidth-delay product in
MTU packets.

### Loss sweep (256 MiB, 500 Mbit / 50 ms RTT, adaptive pacing, medians of 3)

| netem loss | goodput | wire efficiency |
|---|---|---|
| 0% | 315 Mbit/s | 80% |
| 5% | 347 Mbit/s | 66% |
| 10% | 346 Mbit/s | 67% |
| 20% | 258 Mbit/s | 51% |

Goodput is flat through 10% loss and degrades gently at 20% — the demo
claim. (TCP throughput ∝ `MSS/(RTT·√p)` gives scp well under 1 Mbit/s
at 20%/50 ms.)

## remote_bench.sh — real-internet bench vs rsync/scp/rclone

Benchmarks atp-experiment against maximally-tuned rsync-over-ssh, scp, and
rclone-over-sftp between this machine and a real remote host. The rclone
cell rides the same tuned openssh transport (external ssh binary,
aes128-gcm, no compression, `--sftp-concurrency 128 --inplace`) and
disables work rsync doesn't do — shell/hash-command discovery and the
post-transfer remote re-hash cost five extra ssh handshakes plus a full
remote file read per run (`--sftp-shell-type unix
--sftp-disable-hashcheck`; the harness sha256-verifies every transfer
out-of-band regardless). Note `--multi-thread-streams` cannot help here:
the sftp backend supports neither `OpenWriterAt` nor `OpenChunkWriter`,
so rclone silently falls back to a single stream — verified with
`rclone backend features` and by timing 4/8/16 streams (no change).
Parallel-stream rclone is a cloud-backend (S3/GCS/B2) trick, not an ssh
trick. The other sftp knobs were swept on the 256 MiB payload and don't
move it either: chunk-size 32k/255k × concurrency 64/128/256 ×
connections 1/16 all land at 6.6–6.9 s (~315–325 Mbit/s). Once the
request window (chunk × concurrency) covers the path's BDP, sftp sits
at the same single-TCP-stream openssh ceiling rsync sits at — their
256 MiB medians agreeing at ~320 Mbit/s is that ceiling, measured
twice. (`--sftp-connections` is a pool cap, not a parallelizer; a
single-file copy uses one connection regardless.) Methodology follows that of the
original [atp](https://github.com/Dicklesworthstone/atp) (see the
top-level README's Provenance section): incompressible urandom payloads,
always-empty destination, rsync at its fastest (`-aW --inplace`, no
compression, `aes128-gcm`), 1 warmup + N measured runs, SHA-256
verification of every transfer, medians reported, failures recorded rather
than hidden.

Everything runs from the local machine. The remote host is only touched by:

- `~/.cache/atp-experiment-bench/bin/atp-experiment` — the release binary, rsync'd over
- `~/.cache/atp-experiment-bench/recv/` — transfer targets (removed unless `--keep`)
- inline ssh commands (`mkdir`, `sha256sum`, `rm`, running the binary)

No scripts are copied to the remote. Remove all remote state with
`ssh <host> 'rm -rf ~/.cache/atp-experiment-bench'`.

### Usage

```bash
demo/remote_bench.sh <ssh-host> [--sizes 8m,64m,256m] \
    [--runs 3] [--warmup 1] [--tools atp-experiment,atp-experiment-plain,rsync-ssh,scp,rclone-sftp] \
    [--rate-mbps N] [--addr <network-name>] [--port 9440] [--out <dir>] [--keep]
```

Requirements: the remote's TCP `--port` and inbound UDP must be reachable,
and its glibc must be ≥ the binary's requirement (currently 2.34; check
with `objdump -T target/release/atp-experiment | grep -o 'GLIBC_2\.[0-9]*' | sort -Vu`).

atp-experiment paces adaptively by default (`src/rate.rs`: delivery-rate matching
from receiver feedback, backing off only on *excess* loss above the link's
intrinsic floor — stochastic loss never slows it down). No link probing
needed. `--rate-mbps N` pins a static rate for controlled comparisons
(0 = unpaced); the sender logs its pacing decision per repair round
(`pacing … Mbit/s` in `logs/*.send`).

Results land in `demo/results/<utc-timestamp>/`: `report.md` (markdown
table, medians + atp-experiment/rsync ratio), `results.tsv` (raw runs),
`conditions.txt` (link/host facts), `logs/` (per-run sender/receiver
stderr, including atp-experiment's loss/efficiency lines).

### Sample result (2026-07-15, home → Linode, 43 ms RTT, ~500 Mbit path)

Adaptive pacing (default, no link probing), medians of 3 verified runs
(run `20260715T165807Z` in `results/`):

| payload | atp-experiment (sealed, adaptive) | rsync-ssh | rclone-sftp | atp-experiment / rsync-ssh |
|---|---|---|---|---|
| 8 MiB | 0.72 s (94 Mbit/s) | 1.36 s (50 Mbit/s) | 1.68 s (40 Mbit/s) | **0.53** |
| 64 MiB | 2.17 s (248 Mbit/s) | 2.57 s (209 Mbit/s) | 2.72 s (198 Mbit/s) | **0.84** |
| 256 MiB | 5.15 s (417 Mbit/s) | 6.71 s (320 Mbit/s) | 6.67 s (322 Mbit/s) | **0.77** |

An earlier same-day run (`20260715T163133Z`) measured rclone-sftp before
the fairness flags: 4.24 / 5.58 / 9.98 s — the delta is five ssh
handshakes of discovery plus the post-transfer remote md5sum, not
transfer speed.

### Earlier run (2026-07-14, same link, pre-rclone)

Adaptive pacing, medians of 2 verified runs:

| payload | atp-experiment (sealed, adaptive) | rsync-ssh | atp-experiment / rsync-ssh |
|---|---|---|---|
| 8 MiB | 0.63 s (106 Mbit/s) | 1.40 s (48 Mbit/s) | **0.45** |
| 64 MiB | 2.10 s (256 Mbit/s) | 2.54 s (211 Mbit/s) | **0.82** |
| 256 MiB | 5.59 s (384 Mbit/s) | 6.56 s (327 Mbit/s) | **0.85** |

For comparison, an earlier run with a hand-probed static `--rate-mbps 450`
measured 0.42 / 1.97 / 6.30 s on the same link: the controller beats the
hand-picked rate at 256 MiB (it found ~832 Mbit/s of send rate the probe
left on the table, 83% wire efficient), matches it at 64 MiB, and pays a
slow-start tax on 8 MiB (the transfer ends mid-ramp from the 100 Mbit
starting rate — still 2.2× faster than rsync). The small-payload win is
handshake economics (one TLS 1.3 round trip + immediate spray vs ssh's
multi-RTT setup); the large-payload win is the fountain holding high wire
efficiency at a rate TCP only reaches after a long ramp — without anyone
having to pick that rate by hand.
