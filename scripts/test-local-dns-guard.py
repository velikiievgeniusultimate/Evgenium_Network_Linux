#!/usr/bin/env python3
"""Exercise the full guard with a real loopback resolver, without host changes."""
import importlib.util
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def run(*args, **kw):
    result = subprocess.run(args, text=True, capture_output=True, **kw)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result

def inside():
    spec = importlib.util.spec_from_file_location('tunnel', ROOT/'src/starfive_tunnel.py')
    tunnel = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tunnel)
    run('ip', 'link', 'add', tunnel.FULL_HOST, 'type', 'dummy')
    run('ip', 'addr', 'add', '172.29.247.1/30', 'dev', tunnel.FULL_HOST)
    run('ip', 'link', 'set', tunnel.FULL_HOST, 'up')
    run('ip', 'route', 'add', 'default', 'dev', tunnel.FULL_HOST)
    stub = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stub.bind(('127.0.0.53', 53))
    def serve():
        while True:
            data, peer = stub.recvfrom(512)
            # A complete A response for the health probe; echo probes stay simple.
            answer = (data[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+
                      data[12:]+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04\xc0\x00\x02\x01'
                      if len(data) >= 12 else b'local-resolver-answer')
            stub.sendto(answer, peer)
    threading.Thread(target=serve, daemon=True).start()
    def query():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(.5)
            try:
                client.sendto(b'query', ('127.0.0.53', 53))
                return client.recv(512) == b'local-resolver-answer'
            except (TimeoutError, OSError):
                return False
    fixed = tunnel.full_firewall()
    old = fixed.replace('  ip daddr 127.0.0.0/8 return\n', '')
    run('nft', '-f', '-', input=old)
    assert not query(), 'The old guard should reproduce the broken loopback resolver'
    with tempfile.NamedTemporaryFile(mode='w+') as config:
        config.write('nameserver 127.0.0.53\n'); config.flush()
        assert not tunnel.system_dns_health(Path(config.name))
        run('nft', '-f', '-', input='delete table inet '+tunnel.FULL_GUARD+'\n'+fixed)
        tunnel.clear_dns_mappings()
        assert tunnel.system_dns_health(Path(config.name))
    assert query(), 'Loopback resolver must remain reachable with strict guard installed'
    run('nft', 'delete', 'table', 'inet', tunnel.FULL_GUARD)
    assert query()
    print(json.dumps({'old_guard_breaks_local_dns': True,
                      'fixed_guard_preserves_local_dns': True,
                      'disconnect_preserves_local_dns': True,
                      'host_network_changed': False}))

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--inside':
        inside()
    else:
        namespace = 'evg-stub-'+secrets.token_hex(4)
        run('ip', 'netns', 'add', namespace)
        try:
            run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
            print(run('ip', 'netns', 'exec', namespace, sys.executable,
                      __file__, '--inside').stdout, end='')
        finally:
            run('ip', 'netns', 'del', namespace)
