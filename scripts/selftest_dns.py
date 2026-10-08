#!/usr/bin/env python3
"""Run as root under unshare -n; never changes host networking."""
import importlib.util
from pathlib import Path
import socket
import subprocess
import threading

spec = importlib.util.spec_from_file_location('vpn', Path(__file__).parents[1] / 'src/vpnctl.py')
vpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vpn)

def command(*args):
    subprocess.run(args, check=True, capture_output=True)

command('ip', 'link', 'set', 'lo', 'up')
command('ip', 'addr', 'add', '192.168.50.1/32', 'dev', 'lo')
command('ip', '-6', 'addr', 'add', 'fe80::1/128', 'dev', 'lo', 'nodad')
listeners = []
for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
    for transport in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        sock = socket.socket(family, transport)
        sock.bind((host, vpn.DNS_PROXY_PORT))
        if transport == socket.SOCK_STREAM:
            sock.listen()
        listeners.append(sock)
        def serve(s=sock, t=transport):
            while True:
                if t == socket.SOCK_DGRAM:
                    data, peer = s.recvfrom(4096)
                    s.sendto(b'CERT-EE-test:' + data, peer)
                else:
                    connection, _ = s.accept()
                    with connection:
                        connection.sendall(b'CERT-EE-test:' + connection.recv(4096))
        threading.Thread(target=serve, daemon=True).start()

rules = vpn.render_guard_rules(65534, set(), set(), dns_redirect=True)
subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True)
for family, address in ((socket.AF_INET, ('127.0.0.53', 53)),
                        (socket.AF_INET, ('192.168.50.1', 53)),
                        (socket.AF_INET6, ('::1', 53)),
                        (socket.AF_INET6, ('fe80::1', 53, 0, socket.if_nametoindex('lo')))):
    for transport in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        with socket.socket(family, transport) as client:
            client.settimeout(3)
            client.connect(address)
            client.sendall(b'query')
            assert client.recv(4096) == b'CERT-EE-test:query', (family, address, transport)
        print('redirect OK', address, 'UDP' if transport == socket.SOCK_DGRAM else 'TCP')
command('nft', 'delete', 'table', 'inet', vpn.NFT_TABLE)
print('DNS namespace integration OK (IPv4/IPv6, TCP/UDP, stub/LAN/link-local)')
