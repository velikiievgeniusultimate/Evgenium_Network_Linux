#!/bin/bash
set -euo pipefail
wg=/opt/evgenium-link/package/usr/bin/wg
stop() {
 ip link del evg-wg 2>/dev/null || true
 if test -f /var/lib/evgenium-link/forwarding-owned; then
  sysctl -q -w net.ipv4.conf.eth0.forwarding="$(cat /var/lib/evgenium-link/before-eth0-forwarding)"
  rm -f /var/lib/evgenium-link/forwarding-owned
 fi
 nft delete table inet evg_link 2>/dev/null || true
 nft delete table ip evg_link_nat 2>/dev/null || true
}
case "${1:-}" in
start)
 trap 'stop' ERR
 test ! -e /sys/class/net/evg-wg
 nft -f /etc/evgenium-link/firewall.nft
 ip link add evg-wg type wireguard
 "$wg" set evg-wg private-key /etc/evgenium-link/private.key listen-port 24447 peer "$(cat /etc/evgenium-link/peer.key)" allowed-ips 10.203.71.2/32
 ip addr add 10.203.71.1/30 dev evg-wg
 ip link set evg-wg mtu 1280 up
 sysctl -q -w net.ipv4.conf.evg-wg.forwarding=1
 touch /var/lib/evgenium-link/forwarding-owned
 sysctl -q -w net.ipv4.conf.eth0.forwarding=1
 trap - ERR
 ;;
stop) stop;;
*) exit 2;;
esac
