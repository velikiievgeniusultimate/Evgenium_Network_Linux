# Optional BBR setting for a slow route to a VPN server

This is a **server-side** option for Xray/3x-ui hosts. It helps when the
server can download quickly, but sending to a particular client is slow and
TCP shows retransmissions or packet reordering. It cannot repair a bad ISP
route or guarantee the client's full line rate.

In one measured case, a 50 MB SSH transfer from the VPS to the client took
16.9 and 9.0 seconds with the original `cubic` algorithm, versus 7.0 and
5.8 seconds with BBR. The same VPS downloaded 20 MB directly from the source
at about 466 Mbit/s, while the client received that source through VPN at
about 14–22 Mbit/s. These figures are path-specific; repeat the comparison
on your own server before treating BBR as a fix.

## Enable and verify

Copy `scripts/server-bbr.sh` to the VPN server, then run there as root:

```bash
bash server-bbr.sh status
bash server-bbr.sh enable
bash server-bbr.sh status
```

`enable` loads the kernel's `tcp_bbr` module, selects BBR for **new** TCP
connections, and installs files in `/etc/modules-load.d/` and
`/etc/sysctl.d/` so the choice survives reboot. It saves the previous
algorithm for rollback. It does not restart 3x-ui/Xray, change qdisc, or
disconnect current users. Existing Xray transport connections keep their
current algorithm until they naturally reconnect. To see the actual algorithm
on an active socket, run `ss -tin` on the server and look for `bbr` or
`cubic` in the connection detail.

To restore the previous algorithm for new connections:

```bash
bash server-bbr.sh disable
```

Run this on the VPN server, not on an Evgenium Network Linux client. A single
server setting applies to clients whose traffic is sent by that server, but
the measured benefit depends on each client's route.
