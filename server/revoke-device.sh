#!/bin/bash
# Revocation affects IKEv2 and the mTLS diagnostic endpoint.
set -euo pipefail
umask 077
identity=${1:-}
[[ "$identity" =~ ^device-[a-f0-9]{24}$ ]] || { echo 'Expected device-<24 hex digits>' >&2; exit 1; }
pki=/root/evgenium-ikev2-pki
openssl ca -batch -config "$pki/ca.conf" -revoke "$pki/$identity/cert.pem"
openssl ca -batch -config "$pki/ca.conf" -gencrl -out /etc/swanctl/x509crl/devices.pem.new
mv /etc/swanctl/x509crl/devices.pem.new /etc/swanctl/x509crl/devices.pem
swanctl --load-creds --noprompt >/dev/null
# End existing sessions too: certificate checks happen during authentication.
swanctl --terminate --ike evgenium >/dev/null || true
systemctl restart evgenium-diagnostic-collector
echo 'Certificate revoked. Existing test VPN sessions were disconnected; unrevoked devices may reconnect.'
