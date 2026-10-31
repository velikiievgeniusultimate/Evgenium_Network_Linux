#!/usr/bin/env python3
"""Authenticated WG interface only. Exact bounded echo; no amplification/logging."""
import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('10.78.0.1', 24588))
buckets = {}
while True:
    data, address = sock.recvfrom(4097)
    if not 64 <= len(data) <= 1400 or not data.startswith(b'EVGDIAG1'):
        continue
    now = int(time.monotonic())
    old, count = buckets.get(address[0], (now, 0))
    if now != old:
        count = 0
    if count >= 100:
        continue
    buckets[address[0]] = (now, count+1)
    if len(buckets) > 256:
        buckets = {k: v for k, v in buckets.items() if v[0] >= now-2}
    sock.sendto(data, address)
