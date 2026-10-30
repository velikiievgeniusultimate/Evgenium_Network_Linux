# Direct GRE carrier for the HSVDS–Estonia WireGuard link

This is a server-side delivery change. Linux 0.5.5 and Android 0.2.7-beta continue to connect to HSVDS using their existing tokens and certificates. No GRE support is required on client devices. GRE does not provide encryption; the authenticated WireGuard session remains inside it.

The fixed keyed GRE interface `evg-gre-wan` uses 10.203.119.0/30 and MTU 1440. The existing inner WG uses MTU 1280. The GRE key is a demultiplexing identifier, not a secret. Only the opposite public IPv4 endpoint is accepted. Own nftables chains permit only peer WG UDP and ICMP on the GRE interface; forwarding plaintext through it is denied. Existing default routes, DNS, 3X-UI/Xray and strongSwan configurations remain unchanged.

`link.py` runs from `/opt/evgenium-direct-gre` with `config.json` chosen for the server role, with root-only ownership records. It refuses unowned interfaces/tables and subnet collisions, and removes only its own objects. The oneshot systemd service persists the link across boot; a separate path unit honors the existing `resource-hold`. A hold is never cleared automatically.

On HSVDS the runtime selector is `/opt/evgenium-link/transport.py`; `transport-hsvds.py` documents its current deployment and GRE endpoint. It is separate from the historical StarFive selector in the parent directory. Mode `gre` uses 10.203.119.1:24547. Mode `evgt` retains the prior Ygg/mTLS relay as fallback. The preferred-mode file names `gre`; authenticated independent probes are required before automatic selection. The existing resilient-health daemon validates the actual WG endpoint and private connectivity, and checks the Estonian exit IP. It does not restart a working data path merely because a separate probe misses.

A fresh independent probe uses 10.203.90.9, a separate private key kept only on HSVDS, and namespace `evg-probe-gre`. The key is never committed. `resilience/path-probes.py` supports an optional per-probe endpoint address, including bracketed IPv6. Existing loopback endpoints retain their defaults.

## Deployed verification, 2026-10-30

- Raw direct GRE and experimental IP protocol 253 echoed authenticated test nonces. TCP/UDP and ICMP tests between the same IPv4 endpoints timed out. This shows protocol-selective reachability; it does not identify the filtering operator.
- Isolated complete WG over direct GRE: SHA-256 verified 4 MiB each way at 76.906/40.203 Mbit/s, then 16 MiB each way at 186.206/138.013 Mbit/s (receive/send from HSVDS). These are short private link measurements, not client Internet throughput.
- Production switched with a 120-second rollback timer armed. Five private pings passed, with 31.2 ms average RTT, and HTTPS exit check returned 38.180.164.67; the rollback timer was then cancelled. The old carrier remained running and independently probed.
- Linux 0.5.5 package on StarFive: existing token, connection 1.271 s, expected Estonian exit, DNS and Google/Discord API/CDN passed. Separate 4 MiB Internet transfers measured 44.302/9.707 Mbit/s; original host routes and DNS were restored unchanged.
- Android 0.2.7-beta on the physical 4G phone: expected exit and Google/Discord API/CDN passed, 4 MiB Internet transfers measured 14.436/12.946 Mbit/s. The app remained connected, Wi-Fi off and cellular on. No speed guarantee across operators is implied.
- Selector regression tests cover authenticated GRE preference, fallback eligibility and promotion stability. Live loss injection was not performed on client traffic during this rollout.

Deployment backups, probe key and rollback helper stay under `/opt/evgenium-direct-gre` on the servers. They are not release assets. IPv6 allocation is a separate task and is not enabled by this change.

Health sampling observed occasional missed main-peer ICMP replies and automatic
fallback to EVGT, followed by a return to GRE after 180 seconds of healthy
independent probes. The cause is not yet established: a paired 46-second capture
contained all 48 requests and replies, and 60 endpoint samples showed no roaming.
A diagnostic-only update now records each main probe's exit code, reason and
process duration; it does not relax failover thresholds or claim continuous GRE
uptime.
