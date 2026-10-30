"""Root-only WireGuard peer operations. Client private keys never enter this module."""
import base64
import binascii
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time

CONFIG = Path('/etc/evgenium-wireguard/config.json')


def public_key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError('invalid_public_key')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError('invalid_public_key') from None
    if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode() != value:
        raise ValueError('invalid_public_key')
    return value


def config():
    value = json.loads(CONFIG.read_text())
    if value.get('interface') != 'evg-clients':
        raise RuntimeError('wireguard_configuration')
    public_key(value.get('public_key'))
    endpoint = value.get('endpoint', '')
    if not isinstance(endpoint, str) or not re.fullmatch(r'[A-Za-z0-9.-]+:[0-9]{1,5}', endpoint):
        raise RuntimeError('wireguard_configuration')
    if not 1 <= int(endpoint.rsplit(':', 1)[1]) <= 65535:
        raise RuntimeError('wireguard_configuration')
    if value.get('subnet') != '10.78.0.0/24':
        raise RuntimeError('wireguard_configuration')
    return value


def address(value):
    try:
        parsed = ipaddress.ip_interface(value)
    except (ValueError, TypeError):
        raise ValueError('invalid_peer_address') from None
    if parsed.network.prefixlen != 32 or parsed.ip not in ipaddress.ip_network('10.78.0.0/24') or int(parsed.ip) & 255 in (0, 1, 255):
        raise ValueError('invalid_peer_address')
    return str(parsed)


def command(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
    if result.returncode:
        raise RuntimeError('wireguard_unavailable')
    return result.stdout.decode('utf-8', 'strict')


def apply_peer(record):
    cfg = config()
    key = public_key(record['public_key'])
    command(['wg', 'set', cfg['interface'], 'peer', key, 'allowed-ips', address(record['address'])])


def remove_peer(record):
    cfg = config()
    command(['wg', 'set', cfg['interface'], 'peer', public_key(record['public_key']), 'remove'])


def allocate_address(data):
    # Tombstones reserve their addresses, preventing an old profile from sharing
    # an address with a new identity after a partial or retried revocation.
    used = {d.get('address') for a in data.values() for d in a.get('devices', {}).values() if d.get('type') == 'wireguard'}
    for number in range(2, 255):
        candidate = f'10.78.0.{number}/32'
        if candidate not in used:
            return candidate
    raise PermissionError('address_pool_full')


def sync(data):
    """Restore only enabled database peers and remove unknown/revoked peers.

    Must run while the issuer accounts lock is held. Configuration grants this
    service exclusive ownership of evg-clients; no other interface is touched.
    """
    cfg = config()
    wanted = {}
    addresses = set()
    for account in data.values():
        for record in account.get('devices', {}).values():
            if record.get('type') != 'wireguard':
                continue
            key = public_key(record['public_key'])
            if account.get('enabled') and not account.get('deleted') and not account.get('delete_pending') and not record.get('disabled'):
                if key in wanted:
                    raise RuntimeError('duplicate_peer_key')
                peer_address = address(record['address'])
                if peer_address in addresses:
                    raise RuntimeError('duplicate_peer_address')
                addresses.add(peer_address)
                wanted[key] = record
    existing = command(['wg', 'show', cfg['interface'], 'peers']).split()
    for key in existing:
        if key not in wanted:
            command(['wg', 'set', cfg['interface'], 'peer', public_key(key), 'remove'])
    for record in wanted.values():
        apply_peer(record)
    return {'peers': len(wanted)}


def connections():
    """Return public keys and counters only: never use `wg show ... dump`.

    A recent handshake indicates a reachable peer, not application availability.
    """
    try:
        cfg = config()
        handshake = command(['wg', 'show', cfg['interface'], 'latest-handshakes'])
        transfer = command(['wg', 'show', cfg['interface'], 'transfer'])
        traffic = {}
        for row in transfer.splitlines():
            key, received, sent = row.split()
            traffic[public_key(key)] = (int(received), int(sent))
        now = int(time.time())
        rows = []
        for row in handshake.splitlines():
            key, timestamp = row.split()
            key = public_key(key); timestamp = int(timestamp)
            received, sent = traffic.get(key, (0, 0))
            rows.append({'identity': 'wg:' + key, 'state': 'ESTABLISHED' if 0 < timestamp <= now and now-timestamp <= 180 else 'IDLE',
                         'virtual_ips': [], 'connected_seconds': None, 'handshake_at': timestamp or None,
                         'children': [{'bytes_in': received, 'bytes_out': sent}], 'type': 'wireguard'})
        return {'available': True, 'items': rows, 'sampled_at': now}
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        return {'available': False, 'items': [], 'sampled_at': int(time.time())}
