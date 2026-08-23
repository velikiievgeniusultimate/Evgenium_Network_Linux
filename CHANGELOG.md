# Changelog

## 0.2.16

- retry transient HTTPS failures (including HTTP 429/500/502/503/504) while downloading GitHub manifests, checksums and Xray assets
- keep certificate verification fail-closed; TLS certificate errors are never retried with weaker security
- retry the whole response read so interrupted release-asset transfers cannot leave a partial core download
- make rerunning `install.sh` recover an installation where the manager/GUI were installed but the final Xray download failed
- explicitly run the idempotent core repair step after updating an existing/partial installation
- keep Xray 26.7.28 and all VPN routing, kill-switch, Waydroid and DIRECT behavior unchanged

## 0.2.15

- add clean-install support for Fedora Linux alongside Arch Linux
- install only official distro dependencies with dnf on Fedora, including the Qt 6 QML runner used by the standalone KDE GUI
- support Fedora's `qml-qt6` and `/usr/lib64/qt6/bin/qml` runtime locations
- use `python3` portably instead of assuming an unversioned `python` command during installation
- discover the distro `nologin` path and restore SELinux labels when `restorecon` is available
- keep Xray 26.7.28, the fail-closed kill switch, Waydroid routing and existing VPN behavior unchanged

## 0.2.14

- update the pinned official Xray core from 26.6.27 to 26.7.28
- pick up upstream Linux TUN `autoOutboundsInterface` fix merged in Xray-core PR #6413
- keep the existing fail-closed kill switch, DIRECT rules, Waydroid policy and profile behavior unchanged
- preserve SHA-256 verification, config validation and automatic Xray binary rollback during core updates

## 0.2.13

- add an independent `VPN для Waydroid` switch in the standalone E-VPN application
- when the main VPN is off, Waydroid is always direct regardless of the stored Waydroid preference
- when the main VPN is on, Waydroid can either follow Xray TUN or use a dedicated IPv4 physical policy route
- add a Waydroid-specific fail-closed FORWARD guard so a TUN failure cannot silently leak Waydroid traffic
- apply Waydroid changes live without restarting Xray and keep the Plasma widget intentionally unchanged

## 0.2.12

- fix the standalone GUI sidebar layout and make every navigation row fully clickable
- add a dedicated VPN profiles page with one-click switching between configs
- expose VPN profiles and config directory through the existing local UI state API
- add an original E-VPN application icon inspired by an anime drill-pigtail silhouette and install it for the desktop entry and Plasma widget

## 0.2.11

- replace the Plasma-owned settings dialog with a standalone Evgenium Network application
- keep the desktop widget minimal: `E-VPN`, ON/OFF switch and a gear that launches the standalone GUI
- add a custom Qt Quick interface for VPN status, DIRECT applications, sites/IPs, server ports and diagnostics
- add one-click exclusions from currently running applications in the standalone GUI
- install an `evgenium-network` launcher and desktop-menu entry without adding new package dependencies
- keep the manager release archive backward-compatible with old updaters by embedding GUI assets inside `vpnctl.py`

## 0.2.10

- fix the Plasma settings gear by explicitly enabling the configuration interface
- trigger Plasma 6's shell-owned `configure` action through `Applet::internalAction()` with the older action API kept as a fallback
- show a widget tooltip error if Plasma still fails to expose a configure action

## 0.2.9

- shrink the Plasma desktop widget to `E-VPN` + one switch + one settings gear
- open the native Plasma configuration window instead of expanding the desktop widget
- add graphical tabs for DIRECT applications, domains/IP networks, server ports and VPN status
- add one-click DIRECT exclusions from currently running desktop processes
- add safe machine-readable `vpn ui state|running|action` helpers for the Plasma settings UI

## 0.2.8

- fix Plasma 6 widget loading: representation and tooltip properties now use the direct `PlasmoidItem` API
- keep the 0.2.7 widget behavior and local `vpn status --json` / `vpn toggle` contract unchanged

## 0.2.7

- add a Plasma 6 desktop widget with a one-click VPN ON/OFF switch and a compact settings gear
- add `vpn toggle` and remember the last successful VPN profile across `vpn off`
- add `vpn status --json` for a stable machine-readable local UI interface
- add `vpn widget install|remove`; the widget is embedded in the signed/hashed manager release rather than downloaded separately
- expose current DIRECT app/domain/network counts in the widget settings scaffold for future GUI editing

## 0.2.6

- automatically rebuild an active Xray runtime after manager migration
- apply new DIRECT application and localhost SOCKS rules without a manual VPN cycle

## 0.2.5

- add `vpn app add/remove/list` for case-sensitive Xray process DIRECT rules
- migrate existing installs to `~/Vpn/DIRECT apps.txt` and include EWM by default
- add a localhost-only DIRECT SOCKS endpoint at `127.0.0.1:18443`
- let EWM route only its updater downloads outside the VPN without excluding all `curl` traffic

## 0.2.4

- fix SERVER-port bypass: 0.2.3 incorrectly sent the mark back to `main`, whose preferred default is still `xraytun`
- build dedicated routing table 51820 from the physical interface routes
- send marked established server replies to table 51820 instead of `main`
- verify the marked route resolves to the physical interface and never to `xraytun`
- migrate an active 0.2.3 installation during `vpn update` without requiring VPN off/on

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
