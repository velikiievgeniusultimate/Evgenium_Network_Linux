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


## Windows GUI 0.2.0 — 31 октября 2026

Существующий клиентский WireGuard и GRE до Эстонии сохранены. Добавлен отдельный
`evgenium-windows-ingress.service`: Reality TCP 24580 и Reality XHTTP 24581,
собственный закреплённый Xray 26.10.29 в `/opt/evgenium-windows-ingress`.
UUID/публичные Reality-реквизиты входят в клиент. Это только оболочка: сервер
разрешает строго UDP к 127.0.0.1:51820, а WireGuard проверяет отдельный ключ устройства.
Свободного прокси через эти общие реквизиты нет. В `freedom.finalRules` явно разрешён
этот единственный адрес/порт; остальное блокируется. Приватный Reality-ключ —
только в root-конфигурации 0600, служба получает её через systemd LoadCredential.

Диагностический `evgenium-windows-udp-probe.service` слушает 10.78.0.1:24588/UDP.
Доступ разрешён только через evg-clients из 10.78.0.0/24, до запрещающего правила
и в основной input-цепочке. Случайные тестовые пакеты 64–1400 байт возвращаются
один к одному, без усиления, максимум 100 пакетов/с на клиента. Содержимое не пишется.
Правила добавлены в `ingress.py` для сохранения после перезапуска входа.

POST `/api/report` в существующем сервисе регистрации требует его же HTTPS/Host,
сессию, CSRF, токен и привязанный публичный ключ устройства. Windows-отчёт очищается
по белому списку числовых метрик; сырые логи, история и содержимое трафика не принимаются.
Хранилище `/var/lib/evgenium-connect/reports`: 0700/0600, 7 дней, общий предел 64 МиБ.
Нельзя включать в коммиты реальные отчёты или приватные конфигурации.

Откат приложения: `/root/evg-windows-20261031/connect-app.before.py`.
Первоначальный ingress.py и снимок nft находятся рядом. Отдельная закрытая копия
новых конфигураций сохранена в `Russia-HSVDS/windows-2026-10-31-secrets.tar.gz`
на компьютере владельца. Это секретный архив, не Git-артефакт.
Для отключения новых резервов остановите только evgenium-windows-ingress.service;
нативный WireGuard и остальные клиенты продолжат работать. Основные маршруты/DNS,
3X-UI и strongSwan при этой работе не изменялись.


## Direct owner panel — 31 October 2026

`panel.velikiievgenius.com` now has an unproxied A record for `195.209.211.163`,
TTL300. The previous proxied CNAME/Cloudflare Tunnel path is no longer used by DNS.
The unchanged panel application/database/broker stay on HSVDS. Password, TOTP,
trusted-browser cookies and all account/device tokens are preserved.

The shared frontend recognizes the panel's SNI and sends PROXYv2 only to the
new loopback9445 TLS frontend. It uses `/etc/evgenium-panel/tls.pem`, overwrites
X-Forwarded-Proto and X-Forwarded-For, then uses loopback9081. The panel trusts
one proxy for protocol and source IP; an incoming forged header cannot bypass
per-client rate limits. Authentication is still required for administrative APIs.
Both domains receive HTTP301 from80 toHTTPS; ACME HTTP paths use the existing
9083 webroot server. Other SNI still uses the unchanged original443 listener.
The HAProxy source now requires both portal and owner-panel PEM files; provision
these before deploying this shared configuration on a new server.

Certbot lineage `/etc/letsencrypt/live/evgenium-panel-direct` was initially
issued with one temporary DNS TXT record. The Cloudflare API token remained on
the operator computer. That TXT record was deleted after issuance. Renewal was
then reconfigured to webroot/HTTP-01 and tested against the staging CA. No DNS
API credential or manual DNS hook is needed on the server for renewal.
The shared deploy hook handles each lineage separately and checks the full
HAProxy configuration before a graceful reload, restoring the previous PEM if
configuration validation fails. Certbot's existing timer remains enabled.

Rollback files, including a private online SQLite backup, are under
`/root/evg-panel-direct-20261031`. These files contain credentials; never publish.
For rollback, restore only the saved frontend/app/deploy-hook source and the
previous proxied CNAME DNS record after testing the retained cloudflared service.
Do not restore an old SQLite database over new owner/account/device changes.
The original443 PID/configuration, VPN routing/firewall/DNS and Estonian services
were not replaced. The Cloudflare connector is retained for operator rollback,
not enabled as an automatic fallback. DNS caches may retain the previous edge
addresses for up to the old TTL after a cutover.
