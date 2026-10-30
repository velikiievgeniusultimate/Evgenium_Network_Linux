# Direct enrollment and Windows/iPhone ingress on HSVDS

Production hostname: https://connect.velikiievgenius.com/ . DNS is an unproxied
A record for 195.209.211.163, TTL 300. The public HTTPS page and token enrollment
stay on HSVDS; neither uses Cloudflare Tunnel or the Estonian egress. A working
backbone is required for client Internet access, not for TLS termination.

## Independent services and secrets

- `/opt/evgenium-connect`: unprivileged Flask application, loopback 9082.
- `/etc/evgenium-connect/config.json`: public-service configuration, root:evg-portal 0640.
- `/var/lib/evgenium-connect`: private sessions and limits, evg-connect 0700.
- `/run/evgenium-wireguard/enroll.sock`: only `wireguard-enroll`, root:evg-portal 0660.
- `/usr/local/sbin/evgenium-token-issuer` and sibling `wireguard_backend.py`.
- `/etc/evgenium-wireguard/server.key` and `config.json`: root 0600, never publish.
- Existing `/var/lib/evgenium-enrollment/accounts.json`: shared account/device database.
- `/etc/letsencrypt/live/evgenium-connect`: TLS private key and certificate.
- `/etc/evgenium-connect/tls.pem`: root-only combined PEM for HAProxy.
- `/opt/evgenium-connect-infra/backup`: predeployment private backups.

The public process cannot read the owner panel database, credentials, CA,
WireGuard private key or administrative issuer socket. Its only enrollment
privilege is granted by a high-entropy EVN1 token and the restricted RPC socket.
Client private keys are generated in the browser or official Windows wg.exe.
The owner panel keeps password/TOTP authentication and can revoke one device.

Dependencies are installed from the official distribution/package registries.
HAProxy 2.8.30 and liblua5.4 are extracted from verified Ubuntu APT downloads
under `/opt/evgenium-connect-infra/root`; no distro HAProxy daemon replaces the
existing 443 listener. Upgrade these extracted packages deliberately when new
Ubuntu security fixes are available; apt upgrades do not update extracted copies.
Certbot is installed normally and its timer renews the dedicated certificate.
The deploy hook assembles `tls.pem` atomically and gracefully reloads HAProxy.

## Sharing 443 without replacing the existing service

The existing POCO Xray listener, PID/configuration and TLS keys are retained.
`public_front.py up` inserts one owned `evg_connect_public` NAT table for new
inbound IPv4 TCP 443 connections to HAProxy 9444. Existing conntrack flows are
not remapped. SNI `connect.velikiievgenius.com` selects TLS frontend 127.0.0.1:9443
and then gunicorn. All other names use the unchanged original listener at
127.0.0.1:443, with TLS still terminated there. Only the portal backend receives
PROXYv2, allowing HAProxy to replace X-Forwarded-For with the real client IP.
Port 9444 itself is not open to ordinary unsolicited Internet connections.
HTTP 80 serves only ACME challenges and redirects the portal to HTTPS.
Request bodies, token values and query strings are not logged; the app rejects
query strings. No TLS validation bypass is used.

The `evgenium-connect-front` service removes only its own NAT/input rules on
stop/failure, restoring new 443 connections to the original listener. Reload
uses SIGUSR2, retaining established proxy streams. A certificate renewal must
not restart the original Xray service.

## Client routing and fail-closed behavior

`evg-clients` is a separate kernel WireGuard interface, UDP 51820, address
10.78.0.1/24, MTU1280. It is unrelated to the interserver WireGuard private key.
Each device receives one 10.78.0.2–254/32 address and distinct key. Profiles
capture 0.0.0.0/0 and ::/0; IPv6 is deliberately blocked until an IPv6 exit exists.
There is no direct Russian Internet fallback for this client subnet.

Policy priority211 sends source10.78/24 to table51828: a relay default through
10.203.82.2 and a persistent unreachable fallback. Early nft drops deny other
forwarding paths, private destinations, spoofed addresses, unsolicited return
traffic and client-to-client communication. Existing `evg_relay_guard` must also
whitelist authenticated `evg-clients` forwarding: `relay-hsvds.py` contains that
narrow extension. Deploy it to `/opt/evgenium-link/relay-star.py`; applying only
its `guard()` updates root guards without restarting production relay links.
Its namespace forward rules retain the same narrow whitelist on future repair.
A separate namespace NAT table SNATs this subnet to10.203.81.2 before Estonia.

`evgenium-wireguard-sync.timer` reconciles only this entry every60 seconds. It
restores enabled database peers and removes disabled/unknown peers; revocation
writes durable disabled state before removing the kernel peer. It also restores
own forwarding rules after a namespace/firewall restart. No resource hold is
cleared automatically. Stopping the ingress deletes only its own interface;
the fail-closed policy remains. The existing IKE client subnet, default routes,
DNS, backbone, 3X-UI and strongSwan configuration are not replaced.

At most12 active/reserved devices per account. Revoked devices retain their
names/numbers in history but free an account slot. A revoked ID/key cannot be
reused. The first pool reserves at most253 addresses including tombstones;
address recycling is intentionally deferred until safe conntrack cleanup is
implemented. Monitor this limit before broad deployment. Reusing a downloaded
profile on several devices is unsupported: WireGuard would roam one shared peer.

## Verification and rollback

Read-only checks:

```sh
systemctl is-active evgenium-connect-front evgenium-connect evgenium-wireguard-issuer evgenium-wireguard-ingress
curl --fail --silent --show-error https://connect.velikiievgenius.com/
wg show evg-clients latest-handshakes
wg show evg-clients transfer
ip rule show
ip route show table 51828
ip netns exec evg-link nft list table inet evg_wg_entry
systemctl list-timers certbot.timer evgenium-wireguard-sync.timer
```

Do not use `wg ... dump`, `wg showconf`, print account JSON or copy token/private
profile material into diagnostic logs. Latest handshake proves a peer's recent
reachability, not application-level Internet availability.

To withdraw only this new entry, stop `evgenium-wireguard-sync.timer`,
`evgenium-connect`, `evgenium-wireguard-issuer`, `evgenium-wireguard-ingress` and
`evgenium-connect-front`. Existing Linux/Android IKE traffic and original443
listener remain. Keep the new disabled device records and backups; do not roll
accounts.json back over new users or remove CRL/tombstones. Restore source/unit
files from private backups only with a reviewed migration and fresh snapshot.
Do not disable or reset other project services or root firewall rules.

2026-10-30 real StarFive proof: direct public HTTPS200, valid public certificate,
idempotent EVN1 enrollment, private namespace handshake, expected exit
38.180.164.67, Google204 and DiscordAPI200. Bare CDN root returned HTTP403 (TLS
and HTTP reachable; this is not a successful CDN download test). Revoking only
the disposable device blocked its subsequent Internet request. IPv6 was blocked,
and StarFive default routes, rules and DNS matched the original values after
cleanup. Real iPhone import/activation is still untested.

Downloaded browser profiles assign a deterministic private IPv6 address as well
as IPv4 to the client adapter, and capture the IPv6 default route. This address
is local to the VPN interface; it does not provide an IPv6 Internet exit. The
server only authorizes the peer's IPv4 source and blocks forwarded IPv6. Native
clients retain the original `address` field for protocol compatibility; browser
profiles use the additional validated `addresses` list.

`evgenium-connect-front-check.timer` restores only the owned NAT/input rules
after a firewall reload while the front service is active. It never starts a
front service that the operator stopped; inactive fronts have their own redirect
removed so the original443 listener remains available.

The public enrollment hostname must also work while the client VPN is active.
The shared443 redirect therefore also accepts incoming evg-clients packets to
the server's own public IPv4. An early input exception permits only its already
public control endpoints80/8443 and the redirected original443 connection. SSH,
metadata, private services and unsolicited9444 remain blocked. This is encrypted
client-to-entry control traffic; it does not create an Internet WAN fallback.
