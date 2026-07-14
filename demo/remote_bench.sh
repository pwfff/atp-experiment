#!/usr/bin/env bash
# remote_bench.sh — benchmark atp-experiment against tuned rsync/scp over a real link.
#
# Runs entirely from the local machine. The only remote state is:
#   ~/.cache/atp-experiment-bench/bin/atp-experiment   (rsync'd release binary)
#   ~/.cache/atp-experiment-bench/recv/      (transfer targets, removed unless --keep)
# No scripts are shipped to the remote host; all remote operations are
# inline ssh commands (mkdir/sha256sum/rm/exec-binary).
#
# Methodology follows the original atp bench harness (scripts/atp_bench in
# https://github.com/Dicklesworthstone/atp — see README § Provenance & credit):
#   - incompressible urandom payloads, destination always empty
#   - rsync at its fastest: -aW --inplace, no -z, ssh -T -x aes128-gcm
#   - 1 warmup + N measured runs per (tool x payload)
#   - SHA-256 verification of every transfer; failures recorded, not hidden
#   - each tool pays its own connection setup inside the timed window
#     (harness ssh traffic uses a ControlMaster; timed scp/rsync explicitly
#     bypass it with ControlPath=none)
set -euo pipefail

usage() {
    cat <<EOF
usage: $0 <ssh-host> [options]

options:
  --addr <host>       network address for atp-experiment's control/data planes
                      (default: same as <ssh-host>; set this if the ssh
                      name is an alias that does not resolve)
  --port <n>          atp-experiment control port on the remote host (default 9440)
  --sizes <list>      comma-separated payload sizes (default 8m,64m,256m)
  --runs <n>          measured runs per cell (default 3)
  --warmup <n>        warmup runs per cell, untimed (default 1)
  --tools <list>      default atp-experiment,atp-experiment-plain,rsync-ssh,scp
  --rate-mbps <n>     pin atp-experiment to a static pacing rate (default: adaptive
                      rate control; 0 = unpaced)
  --out <dir>         results dir (default demo/results/<utc-timestamp>)
  --keep              keep received files on the remote host
EOF
    exit 1
}

[ $# -ge 1 ] || usage
HOST=$1; shift
ADDR="" PORT=9440 SIZES="8m,64m,256m" RUNS=3 WARMUP=1
TOOLS="atp-experiment,atp-experiment-plain,rsync-ssh,scp" RATE="" OUT="" KEEP=0

while [ $# -gt 0 ]; do
    case $1 in
        --addr)      ADDR=$2; shift 2 ;;
        --port)      PORT=$2; shift 2 ;;
        --sizes)     SIZES=$2; shift 2 ;;
        --runs)      RUNS=$2; shift 2 ;;
        --warmup)    WARMUP=$2; shift 2 ;;
        --tools)     TOOLS=$2; shift 2 ;;
        --rate-mbps) RATE=$2; shift 2 ;;
        --out)       OUT=$2; shift 2 ;;
        --keep)      KEEP=1; shift ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done
ADDR=${ADDR:-$HOST}

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN="$REPO/target/release/atp-experiment"
PAYLOAD_DIR="$REPO/demo/payloads"
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
OUT=${OUT:-$REPO/demo/results/$RUN_ID}
REMOTE_BASE=".cache/atp-experiment-bench"
CTL="/tmp/atp-experiment-bench-ctl-$$"

mkdir -p "$OUT/logs" "$PAYLOAD_DIR"
RESULTS="$OUT/results.tsv"
echo -e "tool\tsize\tbytes\trun\twall_s\tmbit_s\tverified" >"$RESULTS"

# ---- ssh plumbing ----------------------------------------------------------
# Harness traffic (receiver launch, sha checks, cleanup) rides one shared
# ControlMaster so we don't pay a handshake per bookkeeping call. Timed
# transfers never touch it.
rssh() { ssh -o ControlPath="$CTL" "$HOST" "$@"; }

RECV_PID=""
cleanup() {
    [ -n "$RECV_PID" ] && kill "$RECV_PID" 2>/dev/null || true
    ssh -o ControlPath="$CTL" -O exit "$HOST" 2>/dev/null || true
}
trap cleanup EXIT

echo "== preflight"
ssh -o ControlMaster=yes -o ControlPath="$CTL" -o ControlPersist=yes -fN "$HOST"
rssh "mkdir -p $REMOTE_BASE/bin $REMOTE_BASE/recv"

( cd "$REPO" && cargo build --release --quiet )
# ship a stripped copy: debuginfo is ~60 MB we don't need remotely
strip -o "$OUT/atp-experiment.stripped" "$BIN"
rsync -az -e "ssh -o ControlPath=$CTL" "$OUT/atp-experiment.stripped" "$HOST:$REMOTE_BASE/bin/atp-experiment"
rm -f "$OUT/atp-experiment.stripped"
rssh "chmod +x $REMOTE_BASE/bin/atp-experiment && $REMOTE_BASE/bin/atp-experiment recv --help >/dev/null" \
    || { echo "remote binary does not run (glibc? arch?)" >&2; exit 1; }

{   echo "run_id: $RUN_ID"
    echo "port: $PORT"
    echo "tools: $TOOLS sizes: $SIZES runs: $RUNS warmup: $WARMUP rate_mbps: ${RATE:-adaptive}"
    echo "local: $(uname -srm)"
    echo "remote: $(rssh 'uname -srm; nproc')"
    echo "rtt: $(ping -c 5 -q "$ADDR" 2>/dev/null | tail -1 || echo unavailable)"
    echo "atp-experiment: $(cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo untracked)"
} >"$OUT/conditions.txt"
cat "$OUT/conditions.txt"

# ---- payloads --------------------------------------------------------------
declare -A PAYLOAD PAYLOAD_BYTES PAYLOAD_SHA
IFS=, read -ra SIZE_LIST <<<"$SIZES"
for size in "${SIZE_LIST[@]}"; do
    bytes=$(numfmt --from=iec "$(echo "$size" | tr a-z A-Z)")
    f="$PAYLOAD_DIR/payload-$size.bin"
    if [ ! -f "$f" ] || [ "$(stat -c%s "$f")" != "$bytes" ]; then
        echo "== generating $size payload ($bytes bytes)"
        head -c "$bytes" /dev/urandom >"$f.tmp" && mv "$f.tmp" "$f"
    fi
    PAYLOAD[$size]=$f
    PAYLOAD_BYTES[$size]=$bytes
    PAYLOAD_SHA[$size]=$(sha256sum "$f" | cut -d' ' -f1)
done

# ---- one transfer ----------------------------------------------------------
now() { date +%s.%N; }

# run_one <tool> <size> <label>  -> sets WALL (seconds or NA) and VERIFIED (0/1)
run_one() {
    local tool=$1 size=$2 label=$3
    local payload=${PAYLOAD[$size]} rfile="$REMOTE_BASE/recv/$tool-$size.bin"
    local log="$OUT/logs/$tool-$size-$label" t0 t1 rc=0
    WALL=NA VERIFIED=0
    rssh "rm -f $rfile"

    case $tool in
    atp-experiment|atp-experiment-plain)
        local plain="" ready_pat='sender runs:'
        [ "$tool" = atp-experiment-plain ] && { plain="--nocrypto"; ready_pat='control listening'; }
        ssh -o ControlPath="$CTL" "$HOST" \
            "exec $REMOTE_BASE/bin/atp-experiment recv $rfile --listen 0.0.0.0:$PORT $plain" \
            2>"$log.recv" &
        RECV_PID=$!
        local ready="" i
        for i in $(seq 100); do
            grep -q "$ready_pat" "$log.recv" 2>/dev/null && { ready=1; break; }
            kill -0 "$RECV_PID" 2>/dev/null || break
            sleep 0.1
        done
        if [ -z "$ready" ]; then
            echo "  receiver failed to start:" >&2; cat "$log.recv" >&2
            wait "$RECV_PID" 2>/dev/null || true; RECV_PID=""
            return 0
        fi
        local pinflag=()
        if [ -z "$plain" ]; then
            local pin
            pin=$(grep -oE '\b[0-9a-f]{64}\b' "$log.recv" | head -1)
            pinflag=(--pin "$pin")
        else
            pinflag=(--nocrypto)
        fi
        local rateflag=()
        [ -n "$RATE" ] && rateflag=(--rate-mbps "$RATE")
        t0=$(now)
        "$BIN" send "$payload" "$ADDR:$PORT" "${pinflag[@]}" \
            "${rateflag[@]}" 2>"$log.send" || rc=$?
        t1=$(now)
        if [ $rc -ne 0 ]; then
            kill "$RECV_PID" 2>/dev/null || true
            wait "$RECV_PID" 2>/dev/null || true
        else
            wait "$RECV_PID" 2>/dev/null || rc=$?
        fi
        RECV_PID=""
        ;;
    rsync-ssh)
        t0=$(now)
        rsync -aW --inplace \
            -e "ssh -T -x -o Compression=no -o ControlPath=none -c aes128-gcm@openssh.com" \
            "$payload" "$HOST:$rfile" 2>"$log.send" || rc=$?
        t1=$(now)
        ;;
    scp)
        t0=$(now)
        scp -q -o Compression=no -o ControlPath=none -c aes128-gcm@openssh.com \
            "$payload" "$HOST:$rfile" 2>"$log.send" || rc=$?
        t1=$(now)
        ;;
    *) echo "unknown tool: $tool" >&2; exit 1 ;;
    esac

    if [ $rc -ne 0 ]; then
        echo "  TRANSFER FAILED (rc=$rc), see $log.send" >&2
        return 0
    fi
    local rsha
    rsha=$(rssh "sha256sum $rfile" | cut -d' ' -f1)
    if [ "$rsha" = "${PAYLOAD_SHA[$size]}" ]; then
        VERIFIED=1
        WALL=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f", b-a}')
    else
        echo "  HASH MISMATCH on $tool/$size" >&2
    fi
    [ $KEEP -eq 1 ] || rssh "rm -f $rfile"
}

# ---- matrix ----------------------------------------------------------------
IFS=, read -ra TOOL_LIST <<<"$TOOLS"
for size in "${SIZE_LIST[@]}"; do
    for tool in "${TOOL_LIST[@]}"; do
        for w in $(seq "$WARMUP"); do
            echo "== $tool $size warmup $w/$WARMUP"
            run_one "$tool" "$size" "warmup$w"
        done
        for r in $(seq "$RUNS"); do
            echo "== $tool $size run $r/$RUNS"
            run_one "$tool" "$size" "run$r"
            local_mbit=NA
            [ "$WALL" != NA ] && local_mbit=$(awk -v b="${PAYLOAD_BYTES[$size]}" -v w="$WALL" \
                'BEGIN{printf "%.1f", b*8/1e6/w}')
            echo -e "$tool\t$size\t${PAYLOAD_BYTES[$size]}\t$r\t$WALL\t$local_mbit\t$VERIFIED" >>"$RESULTS"
            echo "   wall=${WALL}s throughput=${local_mbit} Mbit/s verified=$VERIFIED"
        done
    done
done

# ---- anonymize -------------------------------------------------------------
# Results may be committed or shared: scrub the remote name and any peer
# IPs (receiver logs record the *sender's* public address) from artifacts.
find "$OUT" -type f -exec sed -i \
    -e "s/${HOST//./\\.}/remote-host/g" \
    -e "s/${ADDR//./\\.}/remote-host/g" \
    -e 's/connection from [0-9a-fA-F.:]*/connection from [peer]/g' {} +

# ---- report ----------------------------------------------------------------
REPORT="$OUT/report.md"
{
    echo "# atp-experiment remote bench — $RUN_ID"
    echo
    sed 's/^/    /' "$OUT/conditions.txt"
    echo
    echo "Median of $RUNS runs (after $WARMUP warmup), SHA-256 verified."
    echo "atp-experiment is TLS-1.3-keyed + per-datagram AEAD; its crypto-symmetric"
    echo "opponent is rsync-ssh/scp. atp-experiment-plain (--nocrypto) is a plaintext"
    echo "control with no matching plaintext baseline here (no rsyncd)."
    echo
    header="| payload |"; sep="|---|"
    for tool in "${TOOL_LIST[@]}"; do header+=" $tool |"; sep+="---|"; done
    header+=" atp-experiment / rsync-ssh |"; sep+="---|"
    echo "$header"; echo "$sep"
    for size in "${SIZE_LIST[@]}"; do
        row="| $size |"
        declare -A med=()
        for tool in "${TOOL_LIST[@]}"; do
            m=$(awk -F'\t' -v t="$tool" -v s="$size" \
                    '$1==t && $2==s && $7==1 {print $5}' "$RESULTS" \
                | sort -g \
                | awk '{v[NR]=$1} END{if (NR) print v[int((NR+1)/2)]; else print "NA"}')
            med[$tool]=$m
            if [ "$m" = NA ]; then row+=" failed |"; else
                mb=$(awk -v b="${PAYLOAD_BYTES[$size]}" -v w="$m" \
                    'BEGIN{printf "%.1f", b*8/1e6/w}')
                row+=" ${m} s (${mb} Mbit/s) |"
            fi
        done
        if [ "${med[atp-experiment]:-NA}" != NA ] && [ "${med[rsync-ssh]:-NA}" != NA ]; then
            row+=" $(awk -v a="${med[atp-experiment]}" -v r="${med[rsync-ssh]}" \
                'BEGIN{printf "**%.2f**", a/r}') |"
        else
            row+=" — |"
        fi
        echo "$row"
    done
    echo
    echo "Ratio < 1.0 = atp-experiment faster. Raw data: results.tsv, per-run logs in logs/."
} >"$REPORT"

echo
cat "$REPORT"
echo
echo "results: $OUT"
