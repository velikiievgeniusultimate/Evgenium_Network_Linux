#!/usr/bin/env python3
"""Forced SSH command: relay only to the fixed, TLS-protected Estonia transport."""
import os
import select
import socket
import sys

with socket.create_connection(('38.180.164.67', 24543), timeout=6) as peer:
    peer.settimeout(15)
    while True:
        ready, _, _ = select.select([0, peer], [], [], 60)
        if not ready:
            continue
        for source in ready:
            data = os.read(0, 65536) if source == 0 else peer.recv(65536)
            if not data:
                sys.exit(0)
            if source == 0:
                peer.sendall(data)
            else:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
