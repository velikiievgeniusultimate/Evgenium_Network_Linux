#!/bin/bash
# Run only on StarFive, after the independent interserver link was installed.
set -euo pipefail
umask 077
base=$(cd -- "$(dirname -- "$0")" && pwd)
test "$(id -u)" = 0
test -f /opt/evgenium-link/link.sh
mkdir -p /var/lib/evgenium-link/relay-backup /etc/nftables.d
if ! test -f /var/lib/evgenium-link/relay-backup/nftables.conf; then
 cp -a /etc/nftables.conf /var/lib/evgenium-link/relay-backup/nftables.conf
fi
install -m 0700 "$base/relay-star.py" /opt/evgenium-link/relay-star.py
for name in evgenium-relay.service evgenium-relay-check.service evgenium-relay-check.timer; do
 install -m 0644 "$base/$name" "/etc/systemd/system/$name"
done
systemctl daemon-reload
systemctl start evgenium-relay
nft list table inet evg_relay_guard > /etc/nftables.d/evgenium-relay-guard.nft
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/nftables.conf');s=p.read_text();line='include "/etc/nftables.d/evgenium-relay-guard.nft"'
if line not in s:p.write_text(s+'\n'+line+'\n')
PY
nft -c -f /etc/nftables.conf
systemctl enable evgenium-relay
systemctl enable --now evgenium-relay-check.timer
