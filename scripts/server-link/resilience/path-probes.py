#!/usr/bin/env python3
"""Independent authenticated WireGuard probes for each delivery path."""
import json
from pathlib import Path
import subprocess
import sys

def command(*args, check=True):
    return subprocess.run(list(args), capture_output=True, text=True, check=check)

cfg = json.loads(Path(sys.argv[1]).read_text())
if cfg['side'] == 'client':
    for name, p in cfg['paths'].items():
        ns = 'evg-probe-' + name
        interface = 'evg-p-' + name
        command('ip', 'netns', 'add', ns, check=False)
        if command('ip', '-n', ns, 'link', 'show', interface, check=False).returncode:
            command('ip', 'link', 'add', interface, 'type', 'wireguard')
            command('ip', 'link', 'set', interface, 'netns', ns)
        prefix = ['ip', 'netns', 'exec', ns]
        command(*prefix, cfg['wg'], 'set', interface, 'private-key', p['key'],
                'listen-port', str(p['listen']), 'peer', cfg['peer_key'],
                'allowed-ips', cfg['peer_ip']+'/32', 'endpoint', '127.0.0.1:'+str(p['port']),
                'persistent-keepalive', '5')
        command('ip', '-n', ns, 'addr', 'replace', p['ip']+'/32', 'dev', interface)
        command('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        command('ip', '-n', ns, 'link', 'set', interface, 'mtu', '1280', 'up')
        command('ip', '-n', ns, 'route', 'replace', cfg['peer_ip']+'/32', 'dev', interface)
else:
    table = command('nft', 'list', 'chain', 'inet', 'evg_ru_link', 'input').stdout
    for name, p in cfg['paths'].items():
        command(cfg['wg'], 'set', cfg['interface'], 'peer', p['public_key'], 'allowed-ips', p['ip']+'/32')
        command('ip', 'route', 'replace', p['ip']+'/32', 'dev', cfg['interface'])
        comment = 'evgenium-probe-' + name
        if comment not in table:
            command('nft', 'insert', 'rule', 'inet', 'evg_ru_link', 'input',
                    'iifname', cfg['interface'], 'ip', 'saddr', p['ip'],
                    'ip', 'protocol', 'icmp', 'accept', 'comment', '"'+comment+'"')
