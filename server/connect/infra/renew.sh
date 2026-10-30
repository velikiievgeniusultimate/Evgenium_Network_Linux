#!/bin/sh
set -eu
if [ "${RENEWED_LINEAGE:-}" != /etc/letsencrypt/live/evgenium-connect ]; then exit 0; fi
umask 077
cat /etc/letsencrypt/live/evgenium-connect/fullchain.pem /etc/letsencrypt/live/evgenium-connect/privkey.pem > /etc/evgenium-connect/tls.new
chmod 600 /etc/evgenium-connect/tls.new
mv /etc/evgenium-connect/tls.new /etc/evgenium-connect/tls.pem
systemctl reload evgenium-connect-front.service
