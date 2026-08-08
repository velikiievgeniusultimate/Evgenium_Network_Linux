# Changelog

## 0.2.3

- add `vpn port add/remove/list` for inbound services behind full-TUN
- default `vpn port add PORT` to TCP; support UDP and both
- policy-route established server replies through the normal main table
- keep unrelated process traffic inside the VPN
- persist server-port rules in `~/Vpn/SERVER ports.txt`
- atomically replace the nftables kill-switch table during live rule changes
- remove tracked Python bytecode from the repository

## 0.2.2

- add `vpn direct` command family
- add/remove DIRECT domains, individual IPs and CIDRs without editing text files manually
- add DNS snapshot discovery using system DNS plus Cloudflare, Google and Quad9 recursive resolvers
- follow DNS CNAMEs and collect both A and AAAA answers
- managed DNS snapshots can be refreshed with `vpn direct refresh`
- active VPN rules are re-applied automatically after DIRECT changes
- warn before broad IP snapshots because CDN IPs may be shared

## 0.2.1 — 2026-08-08

First stable GitHub baseline.

- Xray-core engine replaces Mihomo.
- VLESS + XHTTP + REALITY share-link importer.
- Native Xray TUN routing.
- nftables kill switch.
- Real IPv4 DNS/HTTPS health check before `vpn on` reports success.
- Automatic IPv6 VPN-egress probe.
- IPv4-only fail-closed fallback when the remote VPS has no IPv6.
- UDP-over-VLESS health test.
- IPv4 and IPv6 direct-leak tests.
- DIRECT domain/network routing files.
- Atomic local manager updater with `current` / `previous` release layout.
- Compatible Xray core pinned to 26.6.27.

## 0.2.0

- Initial Xray-based migration release.

## 0.1.x

- Early Mihomo-based prototypes. Deprecated.
