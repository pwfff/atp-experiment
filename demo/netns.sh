#!/usr/bin/env bash
# netns.sh — rootless, project-private network namespace pair for netem
# benchmarks. No sudo anywhere.
#
# `up` starts two unprivileged pause processes: "a" unshares a user+net
# namespace (and owns the user namespace), "b" joins that user namespace
# and unshares its own net namespace. A veth pair on 10.77.0.0/24 joins
# the two net namespaces. Inside the user namespace we hold CAP_NET_ADMIN
# over both, so ip/tc/netem work unprivileged.
#
# Isolation: the veth and its subnet exist only inside net namespaces
# owned by this private user namespace. The host sees no interface, no
# route, no netns name; there is no path to the host network or the
# internet. Other traffic cannot accidentally use the link — nothing else
# lives there. State persists until `down`, logout cleanup, or reboot,
# and is per-user (held by the pause pids, no system-wide names taken).
#
# usage:
#   demo/netns.sh up                  create the pair (idempotent)
#   demo/netns.sh exec a|b <cmd...>   run a command in netns a/b
#   demo/netns.sh netem <args...>     tc netem on BOTH directions, e.g.:
#                                       netem delay 25ms loss 5% rate 500mbit limit 6250
#                                     (per direction: delay 25ms ⇒ 50 ms RTT)
#   demo/netns.sh netem off           remove shaping
#   demo/netns.sh status              show pids, links, qdiscs
#   demo/netns.sh down                tear everything down
#
# Typical bench:
#   demo/netns.sh up
#   demo/netns.sh netem delay 25ms loss 5% rate 500mbit limit 6250
#   demo/netns.sh exec b target/release/atp-experiment recv /tmp/out.bin --listen 10.77.0.2:9440 &
#   demo/netns.sh exec a target/release/atp-experiment send FILE 10.77.0.2:9440 --pin ...
set -euo pipefail

RUN_DIR="${XDG_RUNTIME_DIR:-/tmp/atp-experiment-$(id -u)}/atp-experiment-netns"
DEV_A=veth-a DEV_B=veth-b
IP_A=10.77.0.1 IP_B=10.77.0.2

usage() { sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

pid_of() { # a|b -> pid, or fail if not running
    local f="$RUN_DIR/pid.$1" pid
    [ -f "$f" ] || return 1
    pid=$(cat "$f")
    kill -0 "$pid" 2>/dev/null || return 1
    echo "$pid"
}

# Run a command inside netns a or b (root in the shared userns; the mount
# namespace is untouched, so the filesystem view is completely normal).
in_ns() {
    local ns=$1 pid; shift
    pid=$(pid_of "$ns") || { echo "netns pair is not up (run: $0 up)" >&2; exit 1; }
    nsenter --preserve-credentials -U --net -t "$pid" "$@"
}

dev_of() { [ "$1" = a ] && echo "$DEV_A" || echo "$DEV_B"; }

check_ns_arg() {
    case "$1" in a|b) ;; *) echo "expected 'a' or 'b', got '$1'" >&2; exit 1 ;; esac
}

cmd_up() {
    if pid_a=$(pid_of a) && pid_b=$(pid_of b); then
        echo "already up (pids $pid_a/$pid_b)"
        return 0
    fi
    cmd_down >/dev/null 2>&1 || true
    mkdir -p "$RUN_DIR"

    # Pause "a": owns the user namespace + netns a. No --pid, so unshare
    # doesn't fork and $! is the sleep's pid.
    unshare --user --map-root-user --net sleep infinity &
    echo $! >"$RUN_DIR/pid.a"
    local pid_a
    pid_a=$(cat "$RUN_DIR/pid.a")
    # Wait until the userns is enterable (unshare needs a beat to set up).
    local ok=""
    for _ in $(seq 50); do
        if nsenter --preserve-credentials -U --net -t "$pid_a" true 2>/dev/null; then
            ok=1; break
        fi
        sleep 0.1
    done
    [ -n "$ok" ] || { echo "failed to enter userns of pid $pid_a" >&2; cmd_down; exit 1; }

    # Pause "b": same userns, own netns.
    nsenter --preserve-credentials -U -t "$pid_a" unshare --net sleep infinity &
    echo $! >"$RUN_DIR/pid.b"
    local pid_b
    pid_b=$(cat "$RUN_DIR/pid.b")
    for _ in $(seq 50); do
        if nsenter --preserve-credentials -U --net -t "$pid_b" true 2>/dev/null; then
            ok=2; break
        fi
        sleep 0.1
    done
    [ "$ok" = 2 ] || { echo "failed to enter netns of pid $pid_b" >&2; cmd_down; exit 1; }

    # veth pair: created in a, peer moved to b (CAP_NET_ADMIN over both —
    # same owning userns).
    in_ns a ip link add "$DEV_A" type veth peer name "$DEV_B"
    in_ns a ip link set "$DEV_B" netns "$pid_b"
    in_ns a ip link set lo up
    in_ns b ip link set lo up
    in_ns a ip addr add "$IP_A/24" dev "$DEV_A"
    in_ns b ip addr add "$IP_B/24" dev "$DEV_B"
    in_ns a ip link set "$DEV_A" up
    in_ns b ip link set "$DEV_B" up

    echo "up: a($IP_A) <-veth-> b($IP_B), pause pids $pid_a/$pid_b"
    echo "clean link; shape it with: $0 netem delay 25ms loss 5% rate 500mbit limit 6250"
}

cmd_down() {
    local any=""
    for x in a b; do
        if pid=$(pid_of "$x"); then
            kill "$pid" 2>/dev/null || true
            any=1
        fi
    done
    rm -rf "$RUN_DIR"
    [ -n "$any" ] && echo "down" || echo "not up"
}

cmd_exec() {
    [ $# -ge 2 ] || usage
    check_ns_arg "$1"
    local ns=$1; shift
    in_ns "$ns" "$@"
}

cmd_netem() {
    [ $# -ge 1 ] || usage
    if [ "$1" = off ]; then
        in_ns a tc qdisc del dev "$DEV_A" root 2>/dev/null || true
        in_ns b tc qdisc del dev "$DEV_B" root 2>/dev/null || true
        echo "shaping removed"
        return 0
    fi
    # Applied to each direction independently (delay is per-direction:
    # halve your target RTT). Bump `limit` for high-BDP settings — the
    # netem default of 1000 packets drops tails at high rate×delay.
    #
    # `rate X` is pulled out of the netem args and realized as a root tbf
    # with netem as its child. This is deliberate, not cosmetic: a GSO
    # sender emits ~64 KB super-packets, and qdiscs act on qdisc packets —
    # root netem would apply `loss` to whole super-packets (52-datagram
    # loss bursts no real path produces; real NICs segment to MTU before
    # the bottleneck) and count them singly against `limit` (a 5000-packet
    # queue silently becomes ~320 MB of bufferbloat). tbf segments GSO
    # skbs at enqueue (tbf_segment), so the child netem sees, drops,
    # delays, and queues real MTU-sized packets. Verify with
    # `tc -s qdisc`: netem's pkt count must match datagrams sent.
    local rate="" args=()
    while [ $# -gt 0 ]; do
        if [ "$1" = rate ] && [ $# -ge 2 ]; then
            rate=$2; shift 2
        else
            args+=("$1"); shift
        fi
    done
    for x in a b; do
        local dev; dev=$(dev_of "$x")
        in_ns "$x" tc qdisc del dev "$dev" root 2>/dev/null || true
        if [ -n "$rate" ]; then
            in_ns "$x" tc qdisc add dev "$dev" root handle 1: \
                tbf rate "$rate" burst 32k limit 100k
            in_ns "$x" tc qdisc add dev "$dev" parent 1:1 handle 10: \
                netem "${args[@]}"
        else
            # No rate stage: nothing segments GSO super-packets before
            # netem, so `loss` would arrive in ~52-datagram bursts.
            # Force segmentation with an effectively-unlimited tbf.
            in_ns "$x" tc qdisc add dev "$dev" root handle 1: \
                tbf rate 100gbit burst 32k limit 10m
            in_ns "$x" tc qdisc add dev "$dev" parent 1:1 handle 10: \
                netem "${args[@]}"
        fi
        echo "$x: $(in_ns "$x" tc qdisc show dev "$dev" | tr '\n' ' ')"
    done
}

cmd_status() {
    local pid_a pid_b
    if ! { pid_a=$(pid_of a) && pid_b=$(pid_of b); }; then
        echo "not up"
        return 1
    fi
    echo "pause pids: a=$pid_a b=$pid_b  (state: $RUN_DIR)"
    for x in a b; do
        echo "--- $x"
        in_ns "$x" ip -brief addr show "$(dev_of "$x")" | sed 's/^/  /'
        in_ns "$x" tc qdisc show dev "$(dev_of "$x")" | sed 's/^/  qdisc: /'
    done
}

[ $# -ge 1 ] || usage
cmd=$1; shift
case "$cmd" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    exec)   cmd_exec "$@" ;;
    netem)  cmd_netem "$@" ;;
    status) cmd_status ;;
    *)      usage ;;
esac
