#!/bin/bash
set -euo pipefail
ns=evg-direct
host=evg-dir-host
peer=evg-dir-peer
if [ "$1" = stop ]; then
 nft delete table inet evg_direct 2>/dev/null || true
 nft delete table ip evg_direct_nat 2>/dev/null || true
 ip netns del "$ns" 2>/dev/null || true
 ip link del "$host" 2>/dev/null || true
 exit 0
fi
test ! -e /run/netns/$ns
test ! -e /sys/class/net/$host
ip netns add "$ns"
ip link add "$host" type veth peer name "$peer"
ip link set "$peer" netns "$ns"
ip addr add 10.203.93.1/30 dev "$host"
ip link set "$host" up
ip netns exec "$ns" ip addr add 10.203.93.2/30 dev "$peer"
ip netns exec "$ns" ip link set "$peer" up
ip netns exec "$ns" ip link set lo up
ip netns exec "$ns" ip addr add 10.77.0.1/32 dev lo
ip netns exec "$ns" ip route add default via 10.203.93.1
ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.forwarding=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.lo.disable_xfrm=0 net.ipv4.conf.lo.disable_policy=0
sysctl -qw net.ipv4.conf.evg-dir-host.forwarding=1
nft -f - <<'NFT'
table inet evg_direct {
 set permit { type ipv4_addr; }
 chain local_ingress {
  type filter hook output priority -6; policy accept;
  ip daddr 10.203.93.2 tcp dport 24578 ip daddr != @permit counter drop comment "evgenium-device-cf-crl"
 }
 chain input { type filter hook input priority -6; policy accept;
  iifname "evg-dir-host" ct state established,related accept
  iifname "evg-dir-host" drop
 }
 chain forward { type filter hook forward priority -6; policy accept;
  iifname "evg-dir-host" ip saddr != @permit drop
  iifname "evg-dir-host" ip daddr {0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,224.0.0.0/3} drop
  iifname "evg-dir-host" oifname "eth0" accept
  iifname "evg-dir-host" drop
  oifname "evg-dir-host" ip daddr != @permit drop
  oifname "evg-dir-host" ip daddr 10.203.93.2 udp dport 4500 accept
  oifname "evg-dir-host" ip daddr 10.203.93.2 tcp dport {24571,24578} accept
  oifname "evg-dir-host" ct state established,related accept
  oifname "evg-dir-host" drop
 }
}
table ip evg_direct_nat {
 chain pre { type nat hook prerouting priority dstnat; policy accept;
  iifname "eth0" udp dport { 443, 24570 } dnat to 10.203.93.2:4500
  iifname "eth0" tcp dport {24571,24578} dnat to 10.203.93.2
 }
 chain post { type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.203.93.2 oifname "eth0" masquerade
 }
}
NFT
ip netns exec "$ns" nft -f - <<'NFT'
table inet evg_direct_inside {
 chain input { type filter hook input priority filter; policy drop;
  iifname "lo" accept
  ct state established,related accept
  udp dport 4500 accept
  tcp dport {24571,24578} accept
  ip saddr 10.77.0.0/24 ip daddr 10.77.0.1 tcp dport 8443 ipsec in reqid 271 accept
  ip protocol icmp accept
 }
 chain forward { type filter hook forward priority filter; policy drop;
  ip saddr 10.77.0.0/24 ip daddr {0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,224.0.0.0/3} drop
  ip saddr 10.77.0.0/24 ipsec in reqid 271 accept
  ip daddr 10.77.0.0/24 ipsec out reqid 271 ct state established,related accept
 }
 chain mss { type filter hook forward priority mangle; policy accept;
  tcp flags syn tcp option maxseg size > 1200 tcp option maxseg size set 1200
 }
}
table ip evg_direct_inside_nat {
 chain post { type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.77.0.0/24 oifname "evg-dir-peer" ipsec out reqid 271 return
  ip saddr 10.77.0.0/24 oifname "evg-dir-peer" snat to 10.203.93.2
 }
}
NFT
