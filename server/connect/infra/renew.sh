#!/bin/sh
set -eu
case "${RENEWED_LINEAGE:-}" in
 /etc/letsencrypt/live/evgenium-connect) destination=/etc/evgenium-connect/tls.pem ;;
 /etc/letsencrypt/live/evgenium-panel-direct) destination=/etc/evgenium-panel/tls.pem ;;
 *) exit 0 ;;
esac
umask 077
temporary=$(mktemp "${destination}.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
openssl x509 -in "$RENEWED_LINEAGE/fullchain.pem" -noout
openssl pkey -in "$RENEWED_LINEAGE/privkey.pem" -noout
cat "$RENEWED_LINEAGE/fullchain.pem" "$RENEWED_LINEAGE/privkey.pem" > "$temporary"
chmod 600 "$temporary"
# Preserve the last usable PEM if an unrelated front configuration is invalid.
cp -p "$destination" "${destination}.previous"
mv "$temporary" "$destination"
if ! LD_LIBRARY_PATH=/opt/evgenium-connect-infra/root/usr/lib/x86_64-linux-gnu /opt/evgenium-connect-infra/root/usr/sbin/haproxy -c -f /opt/evgenium-connect-infra/haproxy.cfg; then
 mv "${destination}.previous" "$destination"
 exit 1
fi
rm -f "${destination}.previous"
systemctl reload evgenium-connect-front.service
