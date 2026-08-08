# Evgenium Network Linux

A small Linux VPN manager built around **Xray-core**.

Current stable baseline: **0.2.1**.

## Install

Fresh Arch Linux installation:

```bash
curl -fsSL https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main/install.sh | bash
```

The installer runs as the normal desktop user, asks for `sudo` only for system changes, installs the required official Arch packages, creates the isolated `vpn-xray` service account, verifies the stable manager archive by SHA-256, runs compile/self-tests, installs the pinned compatible Xray-core, configures the GitHub stable update channel and creates the `vpn` command.

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

VPN configs are stored in:

```text
~/Vpn/VPN configs/
```

DIRECT lists:

```text
~/Vpn/DIRECT sites.txt
~/Vpn/DIRECT networks.txt
```

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
