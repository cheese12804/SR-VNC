#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    cat <<USAGE
Usage: sudo $0 <interface> <profile>
Profiles:
  clear       Remove any qdisc configured by this script
  loss15      Apply 15% random packet loss
  jitter80    Add 80ms base RTT with ±5ms jitter
  throttle2m  Shape bandwidth to ~2 Mbps downstream
USAGE
    exit 1
fi

DEV="$1"
PROFILE="$2"

if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] This script requires root privileges (tc)." >&2
    exit 1
fi

function clear_qdisc() {
    tc qdisc del dev "$DEV" root 2>/dev/null || true
}

case "$PROFILE" in
    clear)
        clear_qdisc
        ;;
    loss15)
        clear_qdisc
        tc qdisc add dev "$DEV" root netem loss 15%
        ;;
    jitter80)
        clear_qdisc
        tc qdisc add dev "$DEV" root netem delay 80ms 5ms distribution normal
        ;;
    throttle2m)
        clear_qdisc
        tc qdisc add dev "$DEV" root handle 1: htb default 10
        tc class add dev "$DEV" parent 1: classid 1:10 htb rate 2mbit ceil 2mbit
        tc qdisc add dev "$DEV" parent 1:10 handle 10: netem delay 20ms
        ;;
    *)
        echo "Unknown profile: $PROFILE" >&2
        exit 2
        ;;
esac

tc qdisc show dev "$DEV"
