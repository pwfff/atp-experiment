# atp2 remote bench — 20260714T102637Z

    run_id: 20260714T102637Z
    port: 9440
    tools: atp2,atp2-plain,rsync-ssh,scp sizes: 8m,64m,256m runs: 3 warmup: 1 rate_mbps: 250
    local: Linux 7.0.12-zen1-1-zen x86_64
    remote: Linux 6.10.2-x86_64-linode165 x86_64
    2
    rtt: rtt min/avg/max/mdev = 40.213/41.758/42.752/0.834 ms
    atp2: 33bc01d

Median of 3 runs (after 1 warmup), SHA-256 verified.
atp2 is TLS-1.3-keyed + per-datagram AEAD; its crypto-symmetric
opponent is rsync-ssh/scp. atp2-plain (--nocrypto) is a plaintext
control with no matching plaintext baseline here (no rsyncd).

| payload | atp2 | atp2-plain | rsync-ssh | scp | atp2 / rsync-ssh |
|---|---|---|---|---|---|
| 8m | 0.553 s (121.4 Mbit/s) | 0.499 s (134.5 Mbit/s) | 1.396 s (48.1 Mbit/s) | 1.584 s (42.4 Mbit/s) | **0.40** |
| 64m | 2.720 s (197.4 Mbit/s) | 2.745 s (195.6 Mbit/s) | 2.583 s (207.8 Mbit/s) | 2.625 s (204.5 Mbit/s) | **1.05** |
| 256m | 10.473 s (205.0 Mbit/s) | 10.018 s (214.4 Mbit/s) | 6.563 s (327.2 Mbit/s) | 6.550 s (327.9 Mbit/s) | **1.60** |

Ratio < 1.0 = atp2 faster. Raw data: results.tsv, per-run logs in logs/.
