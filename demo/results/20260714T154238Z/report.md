# atp2 remote bench — 20260714T154238Z

    run_id: 20260714T154238Z
    port: 9440
    tools: atp2,rsync-ssh sizes: 8m,64m,256m runs: 2 warmup: 1 rate_mbps: adaptive
    local: Linux 7.0.12-zen1-1-zen x86_64
    remote: Linux 6.10.2-x86_64-linode165 x86_64
    2
    rtt: rtt min/avg/max/mdev = 41.848/42.806/43.244/0.494 ms
    atp2: be7852c

Median of 2 runs (after 1 warmup), SHA-256 verified.
atp2 is TLS-1.3-keyed + per-datagram AEAD; its crypto-symmetric
opponent is rsync-ssh/scp. atp2-plain (--nocrypto) is a plaintext
control with no matching plaintext baseline here (no rsyncd).

| payload | atp2 | rsync-ssh | atp2 / rsync-ssh |
|---|---|---|---|
| 8m | 0.634 s (105.8 Mbit/s) | 1.397 s (48.0 Mbit/s) | **0.45** |
| 64m | 2.098 s (255.9 Mbit/s) | 2.544 s (211.0 Mbit/s) | **0.82** |
| 256m | 5.588 s (384.3 Mbit/s) | 6.563 s (327.2 Mbit/s) | **0.85** |

Ratio < 1.0 = atp2 faster. Raw data: results.tsv, per-run logs in logs/.
