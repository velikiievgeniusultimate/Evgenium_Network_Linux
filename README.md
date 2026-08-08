# Evgenium Network Linux

A small Linux VPN manager built around **Xray-core**.

Current stable baseline: **0.2.2**.

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
- CLI management for DIRECT domains, IPs and CIDRs
- optional DNS snapshot discovery across the system resolver plus multiple public resolvers
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
vpn direct list
vpn direct add example.com
vpn direct add 203.0.113.10
vpn direct add 203.0.113.0/24
vpn direct discover example.com
vpn direct refresh
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

## DIRECT rules

Prefer a domain rule for websites:

```bash
vpn direct add example.com
```

It matches the domain and its subdomains in Xray routing. IP and CIDR exclusions are also supported directly.

For applications that connect to numeric addresses, `vpn direct discover example.com` can create a DNS snapshot. It queries the system resolver and several public recursive resolvers for A/AAAA records, follows CNAMEs and stores the observed host IPs as `/32` or `/128` DIRECT networks. Re-run `vpn direct refresh` to update managed snapshots.

A DNS snapshot is intentionally described as a snapshot: CDNs can rotate or geo-shard addresses, and the root domain cannot reveal every hostname/API used by a site. Shared CDN IPs are especially broad exclusions because other sites on the same destination IP may also become DIRECT. The command therefore shows the discovered set and asks for confirmation unless `--yes` is supplied.
