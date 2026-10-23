#!/bin/bash
# Run as root on the existing StarFive. No new public port; existing VPN stays up.
set -euo pipefail
base=$(cd -- "$(dirname -- "$0")" && pwd)
[[ -f /root/evgenium-ikev2-pki/ca.conf ]] || { echo 'Existing StarFive PKI required' >&2; exit 1; }
python3 -m py_compile "$base/token_issuer.py" "$base/diagnostic_collector.py"
backup="/root/evgenium-before-enrollment-$(date +%Y%m%d%H%M%S)"
mkdir -m 700 "$backup"
cp -a /usr/local/sbin/evgenium-diagnostic-collector "$backup/"
cp -a /etc/systemd/system/evgenium-diagnostic-direct.service "$backup/"
rollback() {
    cp -a "$backup/evgenium-diagnostic-collector" /usr/local/sbin/evgenium-diagnostic-collector
    cp -a "$backup/evgenium-diagnostic-direct.service" /etc/systemd/system/evgenium-diagnostic-direct.service
    rm -f /etc/systemd/system/evgenium-diagnostic-direct.service.d/enrollment.conf
    systemctl daemon-reload
    systemctl restart evgenium-diagnostic-direct.service
    echo "Enrollment installation failed; public collector restored from $backup" >&2
}
trap rollback ERR
install -m 755 "$base/token_issuer.py" /usr/local/sbin/evgenium-token-issuer
install -m 755 "$base/diagnostic_collector.py" /usr/local/sbin/evgenium-diagnostic-collector
install -m 644 "$base/android_reports.py" /usr/local/sbin/android_reports.py
install -m 644 "$base/packet_probe.py" /usr/local/sbin/packet_probe.py
install -m 644 "$base/../src/support_reports.py" /usr/local/sbin/support_reports.py
install -d -m 700 /var/lib/evgenium-enrollment
cat > /etc/systemd/system/evgenium-enrollment.service <<'EOF'
[Unit]
Description=Evgenium token enrollment certificate issuer
After=network.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/sbin/evgenium-token-issuer serve
RuntimeDirectory=evgenium-enrollment
RuntimeDirectoryMode=0700
UMask=0077
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/root/evgenium-ikev2-pki /var/lib/evgenium-enrollment
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
MemoryMax=128M
[Install]
WantedBy=multi-user.target
EOF
install -d -m 755 /etc/systemd/system/evgenium-diagnostic-direct.service.d
cat > /etc/systemd/system/evgenium-diagnostic-direct.service.d/enrollment.conf <<'EOF'
[Unit]
Wants=evgenium-enrollment.service
After=evgenium-enrollment.service
[Service]
ExecStart=
ExecStart=/usr/bin/python3 /usr/local/sbin/evgenium-diagnostic-collector --listen 192.168.0.163 --direct-only --enrollment
EOF
systemctl daemon-reload
systemctl enable --now evgenium-enrollment.service
systemctl restart evgenium-diagnostic-direct.service
systemctl is-active --quiet evgenium-enrollment.service evgenium-diagnostic-direct.service strongswan.service
trap - ERR
printf 'Enrollment installed; existing strongSwan was not restarted. Backup: %s\n' "$backup"
