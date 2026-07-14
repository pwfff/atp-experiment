# atp2 remote bench — 20260714T103233Z

    run_id: 20260714T103233Z
    port: 9440
    tools: atp2,atp2-plain,rsync-ssh,scp sizes: 8m,64m,256m runs: 3 warmup: 1 rate_mbps: 450
    local: Linux 7.0.12-zen1-1-zen x86_64
    remote: Linux 6.10.2-x86_64-linode165 x86_64
    2
    rtt: rtt min/avg/max/mdev = 41.923/42.302/42.588/0.255 ms
    atp2: 33bc01d

Median of 3 runs (after 1 warmup), SHA-256 verified.
atp2 is TLS-1.3-keyed + per-datagram AEAD; its crypto-symmetric
opponent is rsync-ssh/scp. atp2-plain (--nocrypto) is a plaintext
control with no matching plaintext baseline here (no rsyncd).

| payload | atp2 | atp2-plain | rsync-ssh | scp | atp2 / rsync-ssh |
|---|---|---|---|---|---|
| 8m | 0.418 s (160.5 Mbit/s) | 0.377 s (178.0 Mbit/s) | 1.387 s (48.4 Mbit/s) | 1.464 s (45.8 Mbit/s) | **0.30** |
| 64m | 1.965 s (273.2 Mbit/s) | 2.192 s (244.9 Mbit/s) | 2.605 s (206.1 Mbit/s) | 2.659 s (201.9 Mbit/s) | **0.75** |
| 256m | 6.296 s (341.1 Mbit/s) | 6.258 s (343.2 Mbit/s) | 6.535 s (328.6 Mbit/s) | 6.749 s (318.2 Mbit/s) | **0.96** |

Ratio < 1.0 = atp2 faster. Raw data: results.tsv, per-run logs in logs/.
