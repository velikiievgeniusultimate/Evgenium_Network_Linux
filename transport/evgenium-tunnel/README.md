# EvgeniumTunnel — experimental UDP transport

Independent Go implementation of a bounded UDP carrier over mutually authenticated TLS 1.3. Designed to carry an existing encrypted WireGuard session between two controlled hosts. The transport is one optional ranked candidate in VPN client 0.5.1. It is not a claim of censorship resistance or universal superiority. The client automatically installs a SHA-256-pinned binary and uses its existing device certificate.

## Build and test

Linux, Go 1.24 or newer; standard library only.

```sh
go test -race ./...
go vet ./...
go test -run '^$' -fuzz FuzzFrames -fuzztime 10s
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o evgenium-tunnel .
GOOS=linux GOARCH=riscv64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o evgenium-tunnel-riscv64 .
```

Builds also support Linux amd64 and arm64. The executable never changes routes, DNS, firewall rules or global kernel settings. The UDP listener must be loopback IPv4. Its fixed peer must be loopback or an address assigned in the same network namespace. Bind each WireGuard UDP socket in the same network namespace as the carrier; its interface can subsequently be moved into an isolated namespace.

## Authentication and operation

Use a dedicated private CA and distinct server/client certificates. The server certificate must have the server DNS name/IP in its SAN and serverAuth usage. The client certificate needs clientAuth usage and a CN equal to `-peer-name`. The CA private key is not required by the running transport. Keep private keys mode 0600; do not commit them.

Example (documentation addresses; substitute your own):

```sh
# Server: only forwards authenticated traffic to a fixed local WireGuard socket.
./evgenium-tunnel -mode server -listen 0.0.0.0:24577 \
  -udp-peer 127.0.0.1:24547 -peer-name evgenium-client \
  -ca ca.pem -cert server.pem -key server-key.pem

# Client: WireGuard sends to 127.0.0.1:24561 from its fixed port 24567.
./evgenium-tunnel -mode client -server 192.0.2.10:24577 \
  -server-name 192.0.2.10 -udp-listen 127.0.0.1:24561 \
  -udp-peer 127.0.0.1:24567 \
  -ca ca.pem -cert client.pem -key client-key.pem
```

Restrict the server TCP port to intended source addresses with your firewall **before** starting it. The server permits up to eight concurrent sessions including unfinished handshakes (`-max-sessions`, hard limit 32). Each session gets a separate connected UDP socket. It does not accept remote destination addresses and cannot be used as an arbitrary proxy.

Default datagram queue: 1024 packets, bounded at 4096. Default requested UDP receive buffer: 4 MiB. Linux may cap this; startup logs report the actual value. If granted CAP_NET_ADMIN, the process attempts SO_RCVBUFFORCE on its own socket only. Linux reports doubled accounting sizes. Do not interpret a successful setsockopt as proof of loss-free delivery.

Live-session packets remain in FIFO order regardless of their age by default. The carrier cannot distinguish obsolete packets from delayed IPsec/WireGuard traffic; discarding them after 500 ms can amplify losses during brief congestion. The bounded queue still drops new arrivals on overflow, and a failed session discards its entire queue. `-max-age 0` disables age expiry (the default); a positive duration up to 5 seconds retains the legacy opt-in expiry policy and its `stale_drops` counter. The writer batches at most 32 already queued frames and immediately flushes sparse traffic. `-batch-packets 1..32` bounds coalescing for controlled comparisons; the default remains 32 and no delay is added to wait for a batch. Optional `-pace-mbps` limits local UDP delivery; this option has not been benchmarked. It is not adaptive congestion control.

TLS handshake timeout: 6 seconds; heartbeat interval: 3 seconds; matching-response deadline: 12 seconds; read timeout: 20 seconds; write timeout: 10 seconds. The client reconnects after one second following a session failure. Local UDP binding errors are logged and retried after three seconds. A supervisor should restart the server after a crash. Certificate expiry is enforced; automatic certificate rotation is **not implemented**.

## Wire format v1

TLS 1.3, mutual certificate authentication, ALPN `evgenium/1`, no TLS session tickets. After authentication, each peer sends the eight-byte preamble `EVGT 00 01 00 00` (hex bytes after ASCII EVGT). All integers below are unsigned big endian.

Each frame has an 11-byte header: type (1 byte), payload length (2 bytes), sequence (8 bytes). DATA type 1 has 1–4096 payload bytes and a strictly increasing sequence, starting at 1 per session. PING type 2 and PONG type 3 have an 8-byte timestamp payload; the sequence field is unused. A PONG echoes the timestamp. Incoming lengths/types are validated before payload allocation. Repeated/out-of-order DATA sequence values terminate the session. Sequence gaps count datagrams discarded before transmission; the protocol does not retransmit them itself.

TLS supplies cryptographic confidentiality, integrity and peer authentication. No custom encryption is used. This wire protocol is deliberately identifiable; it does **not** imitate browser HTTPS, REALITY or XHTTP. TCP head-of-line blocking remains a limitation, especially with loss on the outer connection.

## Diagnostics

Every five seconds and on SIGUSR1, logs contain a cumulative JSON `metrics` snapshot with UTC milliseconds. Counters include received/delivered datagrams and bytes, application queue drops, stale drops, kernel socket overflow, sequence gaps, protocol errors, stream read errors, UDP delivery errors, reconnections, active sessions and latest heartbeat RTT. No payloads or credentials are logged. Compare deltas within one process lifetime; process restart resets counters. Kernel SO_RXQ_OVFL is reported with a subsequent received packet, so absence of a fresh sample is not proof of no loss. Metrics are process-wide across sessions.

Additional metrics: `tls_flushes`, `frames_written`, `write_us`, `max_write_us`,
`max_queue_us`. The write duration includes encoding and flushing; frames count
encoded DATA/control frames, not delivery acknowledgements. Queue age includes
packets rejected as stale.

Linux `TCP_INFO` is sampled once per second and at session start/end:
`tcp_samples`, `tcp_sample_errors`, `tcp_retransmissions`, `tcp_max_rtt_us`,
`tcp_max_unacked`. Retransmissions are accumulated per connection; maxima are
process lifetime values. Retransmission can also be spurious after reordering;
it is not proof of filtering. No system TCP parameters are changed. Missing
samples are recorded as errors, never reported as successful measurements.

## Measured scope and limitations

See `EXPERIMENT-2026-10-22.txt` for interleaved RU–Estonia measurements and a controlled queue-size experiment. These are short synthetic inner-TCP transfers, not desktop Internet benchmarks, long-term uptime measurements or evidence that an ISP filters a protocol. A small-socket failure remains unresolved and is explicitly included in the report.

Not yet implemented/validated: independent security review, long-duration and many-client load tests, automatic certificate renewal, adaptive multipath scheduling, UDP congestion control, browser camouflage, long-duration production behavior. No promise of uninterrupted connectivity or superiority to VLESS in general.

## Device ingress (0.2.0 transport / 0.5.1 VPN client)

The Estonia device ingress listens on TCP24578 inside the existing isolated IKE namespace. It reuses the existing server certificate and per-device CA. `-crl devices.pem` enables device mode: a verified clientAuth chain, CN matching `device-[a-f0-9]{24}`, and a fresh correctly signed CRL are mandatory. Missing, future, expired, invalid or revoked credentials are rejected. At most two sessions per certificate and32 total sessions are configured. The existing revocation watcher restarts this carrier when its CRL changes and closes the whole ingress gate if revocation snapshots become stale. UDP forwards only to the local IKE socket4500. The interserver prototype and its separate lab CA are not exposed as a client entrypoint.

See `scripts/direct-ingress/evgenium-direct-evgt.service` and the VPN client's `ee-evgt` candidate. Source-based loopback routing lets the fixed peer be the namespace-local IKE source address while preserving NAT reversal and the server certificate identity. The updater downloads the binary for amd64/arm64/riscv64 and verifies its pinned digest before atomic installation. No Go compiler is required on client machines.

## 0.3.0 recovery protection

An authenticated session now requires a matching heartbeat response within 12 seconds.
Probes run every 3 seconds and have priority over a busy UDP queue. Unsolicited pongs
and incoming payload cannot indefinitely hide a broken reverse path. The wire format
remains version 1 and interoperates with the deployed 0.2.0 server. Session deadlines
use monotonic time. Metrics include heartbeat_timeouts, queue/write latency and Linux
TCP retransmissions; they do not contain packet payloads.

The Linux 0.5.3 client also gives the Russian relay's TCP endpoint a narrow routing
exception inside its own namespace. A new socket after reconnect must select the
uplink source, not the installed IKE virtual address. An isolated regression test
checks that ordinary HTTPS traffic still selects the VPN source:
`sudo python3 scripts/test-relay-reconnect-route.py`.
