# atp2 remote bench — 20260714T102546Z

    run_id: 20260714T102546Z
    port: 9440
    tools: atp2 sizes: 64m runs: 1 warmup: 0 rate_mbps: 500
    local: Linux 7.0.12-zen1-1-zen x86_64
    remote: Linux 6.10.2-x86_64-linode165 x86_64
    2
    rtt: rtt min/avg/max/mdev = 42.307/42.669/42.802/0.184 ms
    atp2: 33bc01d

Median of 1 runs (after 0 warmup), SHA-256 verified.
atp2 is TLS-1.3-keyed + per-datagram AEAD; its crypto-symmetric
opponent is rsync-ssh/scp. atp2-plain (--nocrypto) is a plaintext
control with no matching plaintext baseline here (no rsyncd).

| payload | atp2 | atp2 / rsync-ssh |
|---|---|---|
| 64m | 2.561 s (209.6 Mbit/s) | — |

Ratio < 1.0 = atp2 faster. Raw data: results.tsv, per-run logs in logs/.
