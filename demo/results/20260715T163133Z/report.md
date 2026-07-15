# atp-experiment remote bench — 20260715T163133Z

    run_id: 20260715T163133Z
    port: 9440
    tools: atp-experiment,rsync-ssh,rclone-sftp sizes: 8m,64m,256m runs: 3 warmup: 1 rate_mbps: adaptive
    local: Linux 7.0.12-zen1-1-zen x86_64
    remote: Linux 6.10.2-x86_64-linode165 x86_64
    2
    rtt: rtt min/avg/max/mdev = 42.028/42.104/42.327/0.112 ms
    atp-experiment: 70cc1ac

Median of 3 runs (after 1 warmup), SHA-256 verified.
atp-experiment is TLS-1.3-keyed + per-datagram AEAD; its crypto-symmetric
opponent is rsync-ssh/scp. atp-experiment-plain (--nocrypto) is a plaintext
control with no matching plaintext baseline here (no rsyncd).

| payload | atp-experiment | rsync-ssh | rclone-sftp | atp-experiment / rsync-ssh |
|---|---|---|---|---|
| 8m | 1.065 s (63.0 Mbit/s) | 1.361 s (49.3 Mbit/s) | 4.243 s (15.8 Mbit/s) | **0.78** |
| 64m | 2.243 s (239.4 Mbit/s) | 2.501 s (214.7 Mbit/s) | 5.579 s (96.2 Mbit/s) | **0.90** |
| 256m | 5.129 s (418.7 Mbit/s) | 6.620 s (324.4 Mbit/s) | 9.984 s (215.1 Mbit/s) | **0.77** |

Ratio < 1.0 = atp-experiment faster. Raw data: results.tsv, per-run logs in logs/.
