# 0.2.3 server-port routing bug

Observed on a live full-TUN host:

- normal route: `1.1.1.1 dev xraytun`
- policy rule: `fwmark 0x45564e01 lookup main`
- marked route: still `1.1.1.1 dev xraytun`
- `main` contains both `default dev xraytun metric 1` and the physical DHCP default with a larger metric.

Therefore `lookup main` cannot bypass the TUN. The fix is to build a dedicated routing table containing only the physical interface routes and send marked server replies to that table. The updater must also replace the legacy active rule during 0.2.3 -> 0.2.4 migration.
