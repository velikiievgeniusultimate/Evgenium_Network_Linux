#!/usr/bin/env python3
"""Push public revocations through the pinned, forced-command SSH identity."""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path('/etc/evgenium-direct-sync')
PUBLIC_HOST = '38.180.164.67'
INNER_HOST = '10.203.81.1'


def ssh_command(inner=False):
    cmd = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=4', '-o', 'ServerAliveInterval=3',
           '-o', 'ServerAliveCountMax=2', '-o', 'UserKnownHostsFile=' + str(ROOT / 'known_hosts'),
           '-i', str(ROOT / 'id_ed25519')]
    if inner:
        # Pin the same server identity, never trust an independently discovered inner host.
        cmd += ['-o', 'HostKeyAlias=' + PUBLIC_HOST]
    cmd += ['root@' + (INNER_HOST if inner else PUBLIC_HOST)]
    return ['ip', 'netns', 'exec', 'evg-link'] + cmd if inner else cmd


def send_snapshot(body):
    payload = json.dumps(body)
    for inner in (False, True):
        try:
            result = subprocess.run(ssh_command(inner), input=payload, text=True,
                                    capture_output=True, timeout=18)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and result.stdout.strip() == 'accepted':
            return 'wireguard' if inner else 'public'
    raise RuntimeError('revocation_sync_failed')


def sync():
    data = json.loads(Path('/var/lib/evgenium-enrollment/accounts.json').read_text())
    disabled = sorted({d['identity'] for a in data.values() for d in a.get('devices', {}).values()
                       if not a.get('enabled') or d.get('disabled')})
    body = {'issued': int(time.time()), 'disabled': disabled,
            'crl': Path('/etc/swanctl/x509crl/devices.pem').read_text()}
    return send_snapshot(body)


def main():
    if '--once' in sys.argv:
        sync()
        return
    bad = False
    previous_route = None
    while True:
        try:
            route = sync()
            if bad:
                print('revocation_sync_recovered', flush=True)
            if route != previous_route:
                print('revocation_sync_route=' + route, flush=True)
            previous_route = route
            bad = False
        except Exception:
            if not bad:
                print('revocation_sync_unavailable', flush=True)
            bad = True
        time.sleep(10)


if __name__ == '__main__':
    main()
