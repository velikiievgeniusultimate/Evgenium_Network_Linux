#!/bin/bash
set -euo pipefail
umask 077
install -d -m 700 /root/evgenium-ikev2-pki /etc/swanctl/{x509,x509ca,private,conf.d} /var/log/evgenium-experimental
pki=/root/evgenium-ikev2-pki
if [ ! -f "$pki/ca.pem" ]; then
 openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$pki/ca-key.pem" 2>/dev/null
 openssl req -new -x509 -sha256 -days 3650 -key "$pki/ca-key.pem" -subj '/CN=Evgenium private VPN CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out "$pki/ca.pem"
fi
touch "$pki/index.txt"
test -f "$pki/serial" || openssl rand -hex 16 > "$pki/serial"
cat > "$pki/ca.conf" <<'EOF'
[ca]
default_ca = vpn_ca
[vpn_ca]
dir = /root/evgenium-ikev2-pki
database = $dir/index.txt
serial = $dir/serial
new_certs_dir = $dir
certificate = $dir/ca.pem
private_key = $dir/ca-key.pem
default_md = sha256
default_days = 30
default_crl_days = 3650
crl_extensions = crl_ext
policy = device_policy
unique_subject = no
[device_policy]
commonName = supplied
[crl_ext]
authorityKeyIdentifier = keyid:always
EOF
install -d -m 700 /etc/swanctl/x509crl
openssl ca -batch -config "$pki/ca.conf" -gencrl -out /etc/swanctl/x509crl/devices.pem
if [ ! -f /etc/swanctl/private/starfive.pem ]; then
 openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /etc/swanctl/private/starfive.pem 2>/dev/null
 openssl req -new -key /etc/swanctl/private/starfive.pem -subj '/CN=109.194.67.159' -out "$pki/server.csr"
 cat > "$pki/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:109.194.67.159,IP:10.77.0.1
EOF
 openssl x509 -req -sha256 -days 365 -in "$pki/server.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca-key.pem" -CAcreateserial -extfile "$pki/server.ext" -out /etc/swanctl/x509/starfive.pem
fi
install -m 644 "$pki/ca.pem" /etc/swanctl/x509ca/starfive-ca.pem
cat > /etc/swanctl/conf.d/evgenium.conf <<'EOF'
connections {
 evgenium {
  version = 2
  local_addrs = %any
  remote_addrs = %any
  pools = evgenium
  proposals = aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048
  fragmentation = yes
  encap = yes
  mobike = yes
  dpd_delay = 30s
  local {
   auth = pubkey
   id = 109.194.67.159
   certs = starfive.pem
  }
  remote {
   auth = eap-tls
   eap_id = %any
   cacerts = starfive-ca.pem
   revocation = strict
  }
  children {
   internet {
    local_ts = 0.0.0.0/0
    remote_ts = dynamic
    esp_proposals = aes256gcm16,aes256-sha256
    dpd_action = clear
    rekey_time = 1h
   }
  }
 }
}
pools {
 evgenium {
  addrs = 10.77.0.16-10.77.0.254
  dns = 77.88.8.8,77.88.8.1
 }
}
EOF
# Restrict service logs to errors during the test. No packet payload logging.
mkdir -p /etc/strongswan.d
cat > /etc/strongswan.d/evgenium.conf <<'EOF'
charon {
 plugins {
  forecast {
   load = no
  }
  farp {
   load = no
  }
  dhcp {
   load = no
  }
 }
}
charon-systemd {
 journal {
  default = -1
 }
}
EOF
cat > /etc/sysctl.d/70-evgenium-vpn.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
EOF
sysctl --system >/dev/null
cat > /etc/systemd/network/10-vpn-health.netdev <<'EOF'
[NetDev]
Name=vpn-health
Kind=dummy
EOF
cat > /etc/systemd/network/10-vpn-health.network <<'EOF'
[Match]
Name=vpn-health
[Network]
Address=10.77.0.1/32
LinkLocalAddressing=no
[Link]
RequiredForOnline=no
EOF
chmod 644 /etc/systemd/network/10-vpn-health.netdev /etc/systemd/network/10-vpn-health.network
systemctl restart systemd-networkd
# No access to the domestic LAN; only authenticated IPsec clients may forward.
test -f /root/evgenium-ikev2-pki/nftables.before || cp -a /etc/nftables.conf /root/evgenium-ikev2-pki/nftables.before
cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet firewall {
 chain input {
  type filter hook input priority 0; policy drop;
  iifname "lo" accept
  ct state invalid drop
  ct state established,related accept
  ip protocol icmp accept
  meta l4proto ipv6-icmp accept
  udp sport 67 udp dport 68 accept
  udp sport 547 udp dport 546 accept
  udp dport {500,4500} accept
  ip saddr 10.77.0.0/24 ip daddr 10.77.0.1 tcp dport 8443 ipsec in reqid > 0 accept
  meta nfproto ipv4 tcp dport 22 ct state new meter ssh4 { ip saddr timeout 1m limit rate over 10/minute burst 10 packets } drop
  meta nfproto ipv6 tcp dport 22 ct state new meter ssh6 { ip6 saddr timeout 1m limit rate over 10/minute burst 10 packets } drop
  tcp dport 22 accept
 }
 chain forward {
  type filter hook forward priority 0; policy drop;
  ct state invalid drop
  ip saddr 10.77.0.0/24 ipsec in reqid > 0 ip daddr {10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16} drop
  ip daddr 10.77.0.0/24 ipsec out reqid > 0 ct state established,related accept
  ip saddr 10.77.0.0/24 ipsec in reqid > 0 oifname "eth0" accept
 }
 chain output { type filter hook output priority 0; policy accept; }
 chain mss {
  type filter hook forward priority mangle;
  tcp flags syn tcp option maxseg size > 1360 tcp option maxseg size set 1360
 }
}
table ip vpn_nat {
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.77.0.0/24 oifname "eth0" ipsec out reqid > 0 return
  ip saddr 10.77.0.0/24 oifname "eth0" masquerade
 }
}
EOF
nft -c -f /etc/nftables.conf
nft -f /etc/nftables.conf
install -m 755 /tmp/diagnostic_collector.py /usr/local/sbin/evgenium-diagnostic-collector
install -m 755 /tmp/issue-device.sh /usr/local/sbin/evgenium-issue-device
install -m 755 /tmp/revoke-device.sh /usr/local/sbin/evgenium-revoke-device
cat > /etc/systemd/system/evgenium-diagnostic-collector.service <<'EOF'
[Unit]
Description=Private temporary Evgenium VPN diagnostic collector
After=systemd-networkd.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/sbin/evgenium-diagnostic-collector
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/evgenium-experimental
PrivateTmp=yes
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/evgenium-diagnostic-prune.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/usr/bin/find /var/log/evgenium-experimental -type f -name *.jsonl -mtime +6 -delete
EOF
cat > /etc/systemd/system/evgenium-diagnostic-prune.timer <<'EOF'
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF
: > /etc/evgenium-diagnostics-enabled
systemctl daemon-reload
systemctl enable --now strongswan.service evgenium-diagnostic-collector.service evgenium-diagnostic-prune.timer
swanctl --load-all >/dev/null
systemctl is-active strongswan evgenium-diagnostic-collector
