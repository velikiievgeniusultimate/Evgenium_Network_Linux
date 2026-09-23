#!/usr/bin/env bash
set -euo pipefail

# Optional, server-side TCP tuning for VPN paths affected by loss or reordering.
# This script does not restart Xray or change the network queue discipline.

CONF=/etc/sysctl.d/99-evgenium-bbr.conf
MODULE_CONF=/etc/modules-load.d/evgenium-bbr.conf
STATE_DIR=/var/lib/evgenium-network
PREVIOUS_CC="$STATE_DIR/bbr-previous-congestion-control"

if (( EUID != 0 )); then
    echo 'Run as root on the VPN server.' >&2
    exit 1
fi

usage() {
    echo "Usage: $0 {status|enable|disable}" >&2
    exit 2
}

status() {
    sysctl net.ipv4.tcp_congestion_control
    sysctl net.ipv4.tcp_available_congestion_control
    if [[ -f "$CONF" ]]; then
        echo "Persistent BBR setting: $CONF"
    else
        echo 'Persistent BBR setting: absent'
    fi
    if [[ -f "$PREVIOUS_CC" ]]; then
        echo "Previous algorithm: $(<"$PREVIOUS_CC")"
    fi
}

case "${1:-}" in
    status)
        status
        ;;
    enable)
        if [[ -e "$CONF" || -e "$MODULE_CONF" || -e "$PREVIOUS_CC" ]]; then
            echo 'Evgenium BBR files already exist; inspect them before enabling.' >&2
            exit 1
        fi
        previous=$(sysctl -n net.ipv4.tcp_congestion_control)
        modprobe tcp_bbr
        if ! sysctl -n net.ipv4.tcp_available_congestion_control | grep -qw bbr; then
            echo 'The running kernel does not offer TCP BBR.' >&2
            exit 1
        fi
        install -d -m 700 "$STATE_DIR"
        printf '%s\n' "$previous" > "$PREVIOUS_CC"
        chmod 600 "$PREVIOUS_CC"
        printf '%s\n' 'tcp_bbr' > "$MODULE_CONF"
        printf '%s\n' 'net.ipv4.tcp_congestion_control = bbr' > "$CONF"
        if ! sysctl -q -w net.ipv4.tcp_congestion_control=bbr; then
            sysctl -q -w "net.ipv4.tcp_congestion_control=$previous" || true
            rm -f -- "$CONF" "$MODULE_CONF" "$PREVIOUS_CC"
            echo 'Could not enable BBR; restored the previous setting.' >&2
            exit 1
        fi
        echo "BBR enabled for new TCP connections. Previous algorithm: $previous"
        ;;
    disable)
        if [[ ! -f "$CONF" || ! -f "$MODULE_CONF" || ! -f "$PREVIOUS_CC" ]]; then
            echo 'Evgenium BBR state is incomplete; inspect it manually.' >&2
            exit 1
        fi
        if [[ "$(<"$CONF")" != 'net.ipv4.tcp_congestion_control = bbr' ||
              "$(<"$MODULE_CONF")" != 'tcp_bbr' ]]; then
            echo 'An Evgenium BBR file was changed; refusing to remove it.' >&2
            exit 1
        fi
        previous=$(<"$PREVIOUS_CC")
        if [[ ! "$previous" =~ ^[a-z0-9_]+$ ]]; then
            echo 'Saved congestion control algorithm is invalid.' >&2
            exit 1
        fi
        sysctl -q -w "net.ipv4.tcp_congestion_control=$previous"
        rm -f -- "$CONF" "$MODULE_CONF" "$PREVIOUS_CC"
        echo "Restored $previous for new TCP connections."
        ;;
    *)
        usage
        ;;
esac
