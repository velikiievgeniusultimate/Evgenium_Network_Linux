#!/bin/bash
set -euo pipefail
wg=/opt/evgenium-link/package/usr/bin/wg
stop() {
 ip -n evg-link link del evg-wg 2>/dev/null || true
 ip link del evg-wg 2>/dev/null || true
 nft delete table inet evg_link_transport 2>/dev/null || true
 # Keep the empty namespace: resident test processes remain fail-closed.
}
case "${1:-}" in
start)
 trap 'stop' ERR
 if ! test -e /run/netns/evg-link; then ip netns add evg-link; fi
 test ! -e /sys/class/net/evg-wg
 ip link add evg-wg type wireguard
 ip link set evg-wg netns evg-link
 mode=$(cat /var/lib/evgenium-link/mode 2>/dev/null || echo direct)
 case "$mode" in
  hy|tcp|direct) ;;
  *) exit 2;;
 esac
 ip netns exec evg-link "$wg" set evg-wg private-key /etc/evgenium-link/private.key listen-port 24444 peer "$(cat /etc/evgenium-link/peer.key)" allowed-ips 0.0.0.0/0 persistent-keepalive 25
 /usr/bin/python3 /opt/evgenium-link/transport.py "$mode"
 ip -n evg-link addr add 10.203.71.2/30 dev evg-wg
 ip -n evg-link link set lo up
 ip -n evg-link link set evg-wg mtu 1280 up
 ip -n evg-link route add default dev evg-wg
 trap - ERR
 ;;
stop) stop;;
*) exit 2;;
esac
