# atp2 remote bench — 20260714T102520Z

    run_id: 20260714T102520Z
    port: 9440
    tools: atp2,atp2-plain,rsync-ssh,scp sizes: 8m runs: 1 warmup: 0 rate_mbps: 200
    local: Linux 7.0.12-zen1-1-zen x86_64
    remote: Linux 6.10.2-x86_64-linode165 x86_64
    2
    rtt: rtt min/avg/max/mdev = 40.529/42.025/42.742/0.792 ms
    atp2: 33bc01d

Median of 1 runs (after 0 warmup), SHA-256 verified.
atp2 is TLS-1.3-keyed + per-datagram AEAD; its crypto-symmetric
opponent is rsync-ssh/scp. atp2-plain (--nocrypto) is a plaintext
control with no matching plaintext baseline here (no rsyncd).

| payload | atp2 | atp2-plain | rsync-ssh | scp | atp2 / rsync-ssh |
|---|---|---|---|---|---|
| 8m | 0.620 s (108.2 Mbit/s) | 0.580 s (115.7 Mbit/s) | 1.378 s (48.7 Mbit/s) | 1.458 s (46.0 Mbit/s) | **0.45** |

Ratio < 1.0 = atp2 faster. Raw data: results.tsv, per-run logs in logs/.
