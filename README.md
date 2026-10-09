# Evgenium Network Linux

A small Linux VPN manager built around **Xray-core**.

Current stable release: **0.2.25** (Estonian DNS through the VPN).

Existing supported Arch/Fedora installations on x86_64 and aarch64 receive the
same architecture-independent manager archive through `vpn update`. Xray-core
remains architecture-specific and pinned to 26.7.28. Update availability is not
a claim that every distribution/architecture has been runtime-tested.

## Install

Fresh **Arch Linux** or **Fedora Linux (KDE Plasma 6)** installation:

```bash
curl -fsSL https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main/install.sh | bash
```

The installer runs as the normal desktop user, asks for `sudo` only for system changes, installs the required packages from the distribution's official repositories (`pacman` on Arch, `dnf` on Fedora), creates the isolated `vpn-xray` service account, verifies the stable manager archive by SHA-256, runs compile/self-tests, installs the pinned compatible Xray-core, configures the GitHub stable update channel and creates the `vpn` command plus the standalone Evgenium Network GUI. Fedora x86_64 and aarch64 are supported by the same installer; Xray's architecture-specific official asset is selected automatically.

After installation, normal updates are simply:

```bash
vpn update
```

Running the installer again on an existing Xray edition installation is safe: it reconnects the stable channel and calls the transactional updater instead of rebuilding the installation.

## What it does

- VLESS share links and HTTPS subscriptions
- XHTTP + REALITY support
- native Xray TUN routing
- nftables kill switch
- real IPv4 HTTPS health checks before declaring the VPN online
- automatic IPv6 probe; if the remote VPN has no IPv6 egress, public IPv6 is blocked instead of leaked
- UDP health check
- DIRECT domain/network lists
- DIRECT application rules by process name or executable path
- a localhost-only DIRECT SOCKS channel for narrowly scoped updater traffic
- CLI management for DIRECT domains, IPs and CIDRs
- optional DNS snapshot discovery across the system resolver plus multiple public resolvers
- inbound server-port bypass for services hosted behind the full-TUN VPN
- atomic manager updates with `current` / `previous` rollback layout
- Xray version pinning instead of blindly tracking latest

For VPN servers whose download path to clients is slow despite fast server
internet access, see the optional [server-side BBR guide](docs/SERVER-BBR.md).

## User commands

```bash
vpn list
vpn inspect Estonia
vpn on Estonia
vpn switch Estonia
vpn off
vpn toggle
vpn status --ip
vpn status --json
vpn test
vpn diagnostic on Estonia
vpn diagnostic status
vpn diagnostic mark "Discord висит, YouTube работает"
vpn diagnostic report > ~/vpn-diagnostic.jsonl
vpn diagnostic off
vpn route example.com
vpn direct list
vpn direct add example.com
vpn direct add 203.0.113.10
vpn direct add 203.0.113.0/24
vpn direct discover example.com
vpn direct refresh
vpn app list
vpn app add evgenium-waydroid-mapper
vpn app remove evgenium-waydroid-mapper
vpn widget install
vpn widget remove
vpn port list
vpn port add 25565
vpn port remove 25565
vpn reload-rules
vpn logs -n 200
vpn doctor
vpn update
vpn core-update
vpn version
```

## Non-invasive diagnostic mode

`vpn diagnostic on [PROFILE]` starts the selected VPN normally and runs a
separate observer every five seconds. It never restarts Xray, changes routes or
repairs failures. The observer combines independent DNS/TLS/UDP quorum probes
with passive inspection of the connections already in use, including XHTTP
socket queues, retransmissions, repeated transport failures for active domains,
TUN counters, Xray resource growth and physical route/DNS changes.

A one-off failure of one website is suppressed. A domain name is retained only
when Xray reports at least three transport failures for that active destination
inside the rolling window. Healthy lightweight samples are stored once per
minute so gradual resource or retransmission growth remains visible without a
huge log. Diagnostic JSONL uses two rotating 50 GiB segments (100 GiB maximum
export size), so capture depth is not reduced during an extended investigation.
When you notice a visible problem, add a timestamped marker so it can be
correlated with transport state and counters around that exact moment:

```bash
vpn diagnostic mark "Discord висит, YouTube работает"
```

Export it without exposing VPN credentials:

```bash
vpn diagnostic report > ~/vpn-diagnostic.jsonl
```

The normal `vpn on` command disables the observer; `vpn diagnostic off` stops
only the observer and leaves the current VPN connection running.

VPN configs are stored in:

```text
~/Vpn/VPN configs/
```

DIRECT lists:

```text
~/Vpn/DIRECT sites.txt
~/Vpn/DIRECT networks.txt
~/Vpn/DIRECT apps.txt
```

`DIRECT apps.txt` uses Xray's case-sensitive Linux process matching. A line can
be a process name, an absolute executable path, or an absolute directory path
ending in `/`. EWM is added on migration so its own connections bypass the VPN.

While the VPN is active, the manager also exposes a no-auth SOCKS endpoint on
localhost only (`127.0.0.1:18443`). EWM automatically detects this endpoint and
uses it only for its GitHub update downloads. Other applications and ordinary
browser traffic remain on the VPN.


## KDE Plasma 6 widget

Version 0.2.9 keeps the desktop widget deliberately tiny: **E-VPN**, one ON/OFF switch, and one settings gear.

Install it once with:

```bash
vpn widget install
```

Then right-click the desktop, choose **Add Widgets**, search for **Evgenium Network**, and place it on the desktop.

The gear opens Plasma's separate native configuration window. Its tabs manage:

- application DIRECT exclusions;
- domain/IP/CIDR DIRECT exclusions;
- inbound server-port bypass rules;
- current VPN status.

Application exclusions can be entered manually by process name/path, or selected from a live list of processes currently running under the desktop user. Selecting a running application adds its process name to the existing Xray DIRECT application rules. Changes are applied immediately.

The desktop widget itself only calls the local manager (`vpn status --json` and `vpn toggle`). The settings window uses the restricted `vpn ui ...` helper; user-entered values are encoded into a data payload and the manager accepts only a fixed allow-list of actions. VLESS credentials are never exposed to the widget.

## Update channel

Stable manifest:

```text
https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main/update/stable.json
```

`vpn update` checks the manager manifest first and then ensures the Xray-core version pinned by that manager release is installed.

## Repository layout

```text
install.sh           one-line bootstrap installer
src/vpnctl.py        privileged CLI / runtime manager
src/vpnadmin.py      explicit administrative maintenance commands
update/stable.json   stable update channel
update/testing.json  testing update channel
dist/                manager release archives
scripts/             release builder
.github/workflows/   CI self-tests
```

## Security model

The ordinary `vpn` command is allowed to invoke only the root-owned `vpnctl` entry point through sudoers. Installing an arbitrary local manager archive stays behind explicit `sudo vpn-manager-admin local ...`.

The kill switch is fail-closed for ordinary application traffic. The Xray service account is allowed to reach the physical network so the encrypted transport can reach the VPN server. If the VPN server has no working IPv6 egress, public IPv6 is blocked rather than sent directly outside the tunnel.

The bootstrap installer downloads the stable manifest over HTTPS, constrains the release URL to this repository, verifies the archive SHA-256, validates its exact contents and runs Python compile/self-tests before installing it.

Manager archives are SHA-256 verified and self-tested before the `current` symlink is changed. A future release will add a detached signature layer so compromise of the GitHub repository alone is not enough to authorize an update.

## DIRECT rules

Prefer a domain rule for websites:

```bash
vpn direct add example.com
```

It matches the domain and its subdomains in Xray routing. IP and CIDR exclusions are also supported directly.

For applications that connect to numeric addresses, `vpn direct discover example.com` can create a DNS snapshot. It queries the system resolver and several public recursive resolvers for A/AAAA records, follows CNAMEs and stores the observed host IPs as `/32` or `/128` DIRECT networks. Re-run `vpn direct refresh` to update managed snapshots.

A DNS snapshot is intentionally described as a snapshot: CDNs can rotate or geo-shard addresses, and the root domain cannot reveal every hostname/API used by a site. Shared CDN IPs are especially broad exclusions because other sites on the same destination IP may also become DIRECT. The command therefore shows the discovered set and asks for confirmation unless `--yes` is supplied.


## Hosting inbound services while the VPN is on

A full-TUN client changes the normal route for locally generated replies. If an
Internet client connects to a service on this machine's public address, the
reply must leave through the normal physical route rather than through the VPN.

For a Minecraft Java server on the default port:

```bash
vpn port add 25565
```

TCP is the default. UDP or both protocols can be selected explicitly:

```bash
vpn port add 19132 udp
vpn port add 27015 both
```

The manager marks only established reply traffic whose local source port matches
a configured SERVER port, policy-routes that marked traffic through the normal
`main` table, and permits only that marked reply through the kill switch. Other
traffic from the same Java/process remains on the VPN.

Persistent SERVER-port entries are stored in:

```text
~/Vpn/SERVER ports.txt
```

## Экспериментальный StarFive IKEv2

Начиная с 0.2.20 в левом меню есть «Экспериментальное». Режим требует
персональный сертификат, включается вручную и пока использует выход в России.
Инструкция и ограничения: [docs/STARFIVE-IKEV2.md](docs/STARFIVE-IKEV2.md).

### Прямая экспериментальная диагностика (0.2.22)

Ошибки подключения, потери туннеля и итог глобального теста отправляются отдельным HTTPS/mTLS-каналом к StarFive, без зависимости от работающего IKEv2. В экспериментальном разделе видны очередь, состояние и категория ошибки доставки; кнопка «Отправить диагностику напрямую» работает и без VPN. Ошибки подключения отправляются автоматически.

Неотправленные отчёты сохраняются root-only: до 10 диагностик подключения плюс последний глобальный тест. Отправитель повторяет попытки с паузами 15–300 секунд и продолжает очередь после перезагрузки. Kill switch разрешает обход только маркированному служебному сокету root к фиксированному адресу и порту. Выключение временной диагностики останавливает доставку; выключение самого VPN оставляет возможность доставить уже сохранённый отчёт. Сервер недоступен — отчёт остаётся на устройстве.

Диагностика псевдонимная, не анонимная: сервер видит IP соединения, хотя этот IP не сохраняется в отчёте. Сырые журналы, пароли, ключи и содержимое пользовательского трафика не передаются. На сервере отчёты хранятся 7 дней.

Администрирование шлюза: `server/setup-direct-diagnostics.sh` добавляет публичный report-only mTLS-коллектор на LAN IPv4:8443 с ограничением новых соединений; требуется проброс TCP 8443. Приватные `/blob`, `/upload`, `/control` через публичный порт недоступны. Отзыв сертификата перезапускает оба коллектора. `server/selftest-direct.sh` проверяет доставку при закрытом интернете в отдельном network namespace и требует выделенного тестового сертификата.

Обновление тестера: выключить экспериментальный режим, выполнить `vpn update`, закрыть и вновь открыть GUI, повторить подключение. Само обновление не запускает экспериментальный VPN.

### Зависшая операция VPN (0.2.24)

Новая версия ждёт занятую блокировку до 15 секунд и показывает PID и команду
владельца. Внешние команды ограничены 60 секундами, вся операция — 10 минутами.
При завершении или ошибке блокировка освобождается. Таймаут не означает, что
VPN подключён: проверь `vpn status` и повтори нужную команду. Kill switch не
снимается автоматически при ошибке подключения.

Если **старая** версия постоянно отклоняет даже `vpn update`, перезагрузи
ноутбук, затем сразу выполни `vpn update` и проверь `vpn version` (0.2.24).
Не удаляй `/run/vpn-manager/operation.lock`: это может запустить две операции
одновременно.

### DNS protection (0.2.25)

While Xray VPN is active, host TCP/UDP DNS on port 53 is redirected to
loopback-only Xray listeners and forwarded through the selected VLESS node to
independent Cloudflare (`1.1.1.1`) and Google (`8.8.8.8`) resolvers for A/AAAA.
Other query types use Cloudflare through the same VLESS node. With the Estonia
profile, all captured DNS leaves through the Estonian VPN exit.

The capture covers router DNS, IPv6 link-local DNS and local resolver stubs,
regardless of application/LAN DIRECT exceptions. The dedicated Xray UID is
excluded to avoid transport recursion. Existing unredirected DNS connections
are blocked on physical interfaces. DNS is encrypted inside VLESS up to the
exit; the exit-to-resolver hop uses normal DNS. Browser-configured DoH/DoT and
forwarded container traffic are outside this port-53 host capture.

`vpn update` installs the new archive and rebuilds an active Xray configuration.
Capture is enabled only after the DNS listeners start. `vpn off` removes it;
rollback to an older config removes capture if that config has no listeners.
No changes to `/etc/resolv.conf` are made. The systemd resolver cache is flushed
on activation and shutdown. Restart a browser if it retains its own old DNS cache.

The kernel must provide nftables NAT (`nft_chain_nat`, `nft_redir`). A preflight
checks this before switching an active VPN. Reboot first if a rolling distro
has replaced the running kernel modules during an upgrade.

### Safe startup and isolated diagnostics (0.2.26)

`vpn on` checks the cold-start route and TCP connection to the selected server
before changing TUN routes, DNS interception or kill-switch rules. If another
VPN carries the server route, startup refuses without switching that connection.
An unreachable TCP endpoint is reported as a transport problem before DNS can
be redirected into an unusable tunnel. Switching an already-active Evgenium
profile retains the existing guarded transaction and rollback behavior.

To inspect a profile while keeping the current VPN running:

```bash
vpn diagnostic probe Estonia
```

The probe starts a temporary authenticated SOCKS listener on a random localhost
port, verifies HTTPS through VLESS against two providers, then stops the child
and removes its temporary credentials. It never installs a TUN, edits routes,
changes DNS, starts/stops the system VPN service, or modifies firewall rules.
Success confirms the profile over the current network; it does not validate TUN,
UDP DNS, or direct ISP reachability when another VPN is active.

If `vpn diagnostic on Estonia` fails to activate, `vpn diagnostic report` now
includes a `startup_failed` record instead of omitting the failed startup.
This update does not bypass an unreachable or blocked server automatically.

### Independent DNS providers (0.2.28)

After the initial fix, all four CERT-EE addresses became unreachable through
the Estonia exit while Cloudflare and Google still answered over UDP and TCP.
The active pool now spans those two providers rather than one service.
A/AAAA requests run in parallel; other types use the reachable Cloudflare primary.
All requests remain tunneled through VLESS. CERT-EE filtering is no longer used.

### DNS/startup and desktop fixes (0.2.27)

A profile can successfully carry HTTPS while the DNS server used by host capture
is unreachable. In the reproduced failure, `195.80.119.99` did not answer UDP or
TCP through Estonia, while three other `dns.cert.ee` addresses did. Version
0.2.27 uses Xray's native DNS resolver with parallel CERT-EE backends for A/AAAA
queries, instead of depending on that one endpoint. Other query types are
forwarded to the primary CERT-EE address through the same VLESS outbound.
No system/LAN resolver fallback is used. DNS is carried through the selected VPN
exit; no change to `/etc/resolv.conf` is made.

`vpn diagnostic probe Estonia` now checks the actual DNS handler over UDP and
TCP as well as VLESS/HTTPS. This still does not replace a full TUN test.

GUI polling cannot unlock an in-flight action or erase its error. Polling is
bounded and nonoverlapping; an action has a client watchdog. CLI/GUI/widget
share operation state, and core process startup alone is not reported as a
completed VPN connection. Unexpected activation failures/interrupts trigger
bounded recovery, with the previous guard retained if warm recovery fails.

After `vpn update`, close and reopen an already-running GUI. Existing Plasma
applet objects keep their loaded QML: reload the widget/Plasma panel when no VPN
operation is running to use the updated widget code. The updater does not
restart the desktop automatically or disconnect another VPN.
