#!/bin/bash
# Native server installation. No VPN service or global firewall reload.
set -euo pipefail
base=$(cd -- "$(dirname -- "$0")" && pwd)
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
[[ -f /usr/local/sbin/evgenium-token-issuer ]] || { echo 'Existing enrollment service required' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3-flask python3-gunicorn python3-qrcode python3-cryptography
getent passwd evg-panel >/dev/null || useradd --system --home-dir /var/lib/evgenium-panel --shell /usr/sbin/nologin evg-panel
getent group evg-panel-tunnel >/dev/null || groupadd --system evg-panel-tunnel
install -d -m 2750 -o evg-panel -g evg-panel-tunnel /var/lib/evgenium-panel-http
install -d -m 755 /opt/evgenium-panel /opt/evgenium-panel/templates /opt/evgenium-panel/static
install -d -m 700 -o evg-panel -g evg-panel /var/lib/evgenium-panel
install -d -m 700 /var/lib/evgenium-panel-broker
install -d -m 750 -o root -g evg-panel /etc/evgenium-panel
install -m 644 "$base"/{app,broker,wsgi}.py /opt/evgenium-panel/
install -m 644 "$base"/templates/* /opt/evgenium-panel/templates/
install -m 644 "$base"/static/* /opt/evgenium-panel/static/
python3 - <<'PY'
import hashlib,json,secrets,time,grp,os
from pathlib import Path
from cryptography.fernet import Fernet
path=Path('/etc/evgenium-panel/config.json')
if not path.exists():
 os.umask(0o077)
 bootstrap=secrets.token_urlsafe(32)
 config={'state_dir':'/var/lib/evgenium-panel','encryption_key':Fernet.generate_key().decode(),
         'allowed_hosts':['panel.velikiievgenius.com'],'https_proxy':True,
         'broker_socket':'/run/evgenium-panel-broker/admin.sock',
         'bootstrap_hash':hashlib.sha256(bootstrap.encode()).hexdigest(),'bootstrap_expires':int(time.time())+86400}
 path.write_text(json.dumps(config));path.chmod(0o640);os.chown(path,0,grp.getgrnam('evg-panel').gr_gid)
 Path('/root/evgenium-panel-bootstrap.txt').write_text(bootstrap+'\n')
PY
cat > /etc/systemd/system/evgenium-panel-broker.service <<'EOF'
[Unit]
Description=Evgenium restricted account administration broker
After=evgenium-enrollment.service strongswan.service
[Service]
ExecStart=/usr/bin/python3 /opt/evgenium-panel/broker.py
RuntimeDirectory=evgenium-panel-broker
RuntimeDirectoryMode=0750
UMask=0077
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/evgenium-enrollment /var/lib/evgenium-panel-broker
RestrictAddressFamilies=AF_UNIX AF_NETLINK
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
MemoryMax=128M
CPUQuota=25%
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/evgenium-panel.service <<'EOF'
[Unit]
Description=Evgenium owner web panel
After=evgenium-panel-broker.service
Requires=evgenium-panel-broker.service
[Service]
User=evg-panel
Group=evg-panel
WorkingDirectory=/opt/evgenium-panel
ExecStart=/usr/bin/python3 -m gunicorn --bind 127.0.0.1:9081 --bind unix:/var/lib/evgenium-panel-http/panel.sock --umask 7 --workers 2 --threads 2 --timeout 120 --limit-request-line 4096 --limit-request-field_size 4096 wsgi:application
Environment=EVG_PANEL_CONFIG=/etc/evgenium-panel/config.json
UMask=0077
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/evgenium-panel /var/lib/evgenium-panel-http
InaccessiblePaths=/root /var/lib/evgenium-enrollment /var/lib/evgenium-panel-broker
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
MemoryMax=256M
CPUQuota=40%
[Install]
WantedBy=multi-user.target
EOF
# The root issuer owns CA operations; the unprivileged web app never gains CA access.
install -d -m 755 /etc/systemd/system/evgenium-enrollment.service.d
cat > /etc/systemd/system/evgenium-enrollment.service.d/panel-revocation.conf <<'EOF'
[Service]
ReadWritePaths=/etc/swanctl/x509crl
RestrictAddressFamilies=
RestrictAddressFamilies=AF_UNIX AF_NETLINK
EOF
systemctl daemon-reload
systemctl restart evgenium-enrollment
systemctl enable --now evgenium-panel-broker.service evgenium-panel.service
# Subsequent installation updates only these two dedicated services.
systemctl restart evgenium-panel-broker.service evgenium-panel.service
systemctl is-active --quiet evgenium-panel-broker evgenium-panel
echo 'Panel installed on loopback 127.0.0.1:9081; bootstrap is root-only.'
