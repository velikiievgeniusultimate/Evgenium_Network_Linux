# Evgenium Network Linux

A small Linux VPN manager built around **Xray-core**.

Current stable baseline: **0.2.1**.

## What it does

- VLESS share links and HTTPS subscriptions
- XHTTP + REALITY support
- native Xray TUN routing
- nftables kill switch
- real IPv4 HTTPS health checks before declaring the VPN online
- automatic IPv6 probe; if the remote VPN has no IPv6 egress, public IPv6 is blocked instead of leaked
- UDP health check
- DIRECT domain/network lists
- atomic manager updates with `current` / `previous` rollback layout
- Xray version pinning instead of blindly tracking latest

## User commands

```bash
vpn list
vpn inspect Estonia
vpn on Estonia
vpn switch Estonia
vpn off
vpn status --ip
vpn test
vpn route example.com
vpn reload-rules
vpn logs -n 200
vpn doctor
vpn update
vpn core-update
vpn version
```

## Update channel

Stable manifest:

```text
https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main/update/stable.json
```

Connect an existing installation once:

```bash
sudo vpn-manager-admin source https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main/update/stable.json
```

After that, normal updates are:

```bash
vpn update
```

`vpn update` checks the manager manifest first and then ensures the Xray core version pinned by that manager release is installed.

## Repository layout

```text
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

Manager archives are SHA-256 verified and self-tested before the `current` symlink is changed. A future release will add a detached signature layer so compromise of the GitHub repository alone is not enough to authorize an update.
