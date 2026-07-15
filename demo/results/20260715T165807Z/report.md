# atp-experiment remote bench — 20260715T165807Z

    run_id: 20260715T165807Z
    port: 9440
    tools: atp-experiment,rsync-ssh,rclone-sftp sizes: 8m,64m,256m runs: 3 warmup: 1 rate_mbps: adaptive
    local: Linux 7.0.12-zen1-1-zen x86_64
    remote: Linux 6.10.2-x86_64-linode165 x86_64
    2
    rtt: rtt min/avg/max/mdev = 42.976/43.344/43.890/0.307 ms
    atp-experiment: 0d6be38

Median of 3 runs (after 1 warmup), SHA-256 verified.
atp-experiment is TLS-1.3-keyed + per-datagram AEAD; its crypto-symmetric
opponent is rsync-ssh/scp. atp-experiment-plain (--nocrypto) is a plaintext
control with no matching plaintext baseline here (no rsyncd).

| payload | atp-experiment | rsync-ssh | rclone-sftp | atp-experiment / rsync-ssh |
|---|---|---|---|---|
| 8m | 0.716 s (93.7 Mbit/s) | 1.357 s (49.5 Mbit/s) | 1.680 s (39.9 Mbit/s) | **0.53** |
| 64m | 2.166 s (247.9 Mbit/s) | 2.568 s (209.1 Mbit/s) | 2.716 s (197.7 Mbit/s) | **0.84** |
| 256m | 5.154 s (416.7 Mbit/s) | 6.711 s (320.0 Mbit/s) | 6.666 s (322.2 Mbit/s) | **0.77** |

Ratio < 1.0 = atp-experiment faster. Raw data: results.tsv, per-run logs in logs/.
