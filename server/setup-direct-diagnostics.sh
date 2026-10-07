#!/bin/bash
# Add only the experimental, report-only public mTLS listener. No VPN restart.
set -euo pipefail
umask 077
base=$(cd -- "$(dirname -- "$0")" && pwd)
backup=/root/evgenium-before-direct-diagnostics
mkdir -p "$backup"
for file in /etc/nftables.conf /usr/local/sbin/evgenium-diagnostic-collector /usr/local/sbin/evgenium-revoke-device; do
    test -f "$backup/$(basename "$file")" || cp -a "$file" "$backup/"
done
install -o root -g root -m 0755 "$base/diagnostic_collector.py" /usr/local/sbin/evgenium-diagnostic-collector
install -o root -g root -m 0755 "$base/revoke-device.sh" /usr/local/sbin/evgenium-revoke-device
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/nftables.conf');text=p.read_text()
if '192.168.0.163 tcp dport 8443' not in text:
    key='  udp dport {500,4500} accept\n'
    assert key in text
    text=text.replace(key,key+'  ip daddr 192.168.0.163 tcp dport 8443 ct state new limit rate over 10/second burst 20 packets drop\n  ip daddr 192.168.0.163 tcp dport 8443 accept\n')
    Path('/etc/nftables-direct.new').write_text(text)
PY
if test -f /etc/nftables-direct.new; then
    nft -c -f /etc/nftables-direct.new
    install -o root -g root -m 0644 /etc/nftables-direct.new /etc/nftables.conf
    nft -f /etc/nftables.conf
    rm /etc/nftables-direct.new
fi
sed -e 's/Private temporary Evgenium VPN diagnostic collector/Experimental public report-only mTLS collector/' \
    -e 's@ExecStart=.*@ExecStart=/usr/bin/python3 /usr/local/sbin/evgenium-diagnostic-collector --listen 192.168.0.163 --direct-only@' \
    /etc/systemd/system/evgenium-diagnostic-collector.service > /etc/systemd/system/evgenium-diagnostic-direct.service
chmod 0644 /etc/systemd/system/evgenium-diagnostic-direct.service
systemctl daemon-reload
systemctl restart evgenium-diagnostic-collector.service
systemctl enable evgenium-diagnostic-direct.service
systemctl restart evgenium-diagnostic-direct.service
systemctl is-active evgenium-diagnostic-collector.service evgenium-diagnostic-direct.service
