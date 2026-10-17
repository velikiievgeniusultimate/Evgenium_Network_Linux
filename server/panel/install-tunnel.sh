#!/bin/bash
# Usage: sudo ./install-tunnel.sh /path/to/native/cloudflared /root/connector-token
# The second file is a tunnel connector credential, never the Cloudflare API token.
set -euo pipefail
[[ $EUID -eq 0 && $# -eq 2 ]] || { echo 'Usage: sudo install-tunnel.sh BINARY TOKEN_FILE' >&2; exit 1; }
base=$(cd -- "$(dirname -- "$0")" && pwd)
[[ -f $1 && -s $2 ]] || { echo 'Binary and credential file required' >&2; exit 1; }
test -e /run/netns/evg-link
test -f /etc/netns/evg-link/resolv.conf
"$1" --version
getent passwd evg-panel-tunnel >/dev/null || useradd --system --gid evg-panel-tunnel --no-create-home --shell /usr/sbin/nologin evg-panel-tunnel
install -d -m 755 /usr/local/lib/evgenium-panel
install -m 755 "$1" /usr/local/lib/evgenium-panel/cloudflared
install -d -m 700 /etc/evgenium-panel-tunnel
install -m 600 "$2" /etc/evgenium-panel-tunnel/token
install -m 644 "$base/evgenium-panel-tunnel.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable evgenium-panel-tunnel
systemctl restart evgenium-panel-tunnel
systemctl is-active --quiet evgenium-panel-tunnel
