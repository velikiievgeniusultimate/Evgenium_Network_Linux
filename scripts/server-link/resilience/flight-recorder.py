#!/usr/bin/env python3
"""Bounded encrypted-wire capture and incident-triggered diagnostics; no recovery."""
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

os.umask(0o077)
cfg = json.loads(Path(sys.argv[1]).read_text())
root = Path('/var/log/evgenium-flight')
root.mkdir(mode=0o700, parents=True, exist_ok=True)
ring = root / 'ring'
ring.mkdir(mode=0o700, exist_ok=True)
stop = False
signal.signal(signal.SIGTERM, lambda *_: globals().__setitem__('stop', True))
signal.signal(signal.SIGINT, lambda *_: globals().__setitem__('stop', True))

def run(argv, timeout=3):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {'rc': r.returncode, 'out': r.stdout[-24000:], 'err': r.stderr[-2000:]}
    except subprocess.TimeoutExpired:
        return {'rc': 124, 'out': '', 'err': 'deadline'}

def append(item):
    path = root / 'probes.jsonl'
    if path.exists() and path.stat().st_size > 4 * 1024 * 1024:
        for i in range(2, 0, -1):
            old = Path(str(path) + '.' + str(i))
            if old.exists():
                old.replace(str(path) + '.' + str(i + 1))
        path.replace(str(path) + '.1')
    with path.open('a') as f:
        f.write(json.dumps(item, separators=(',', ':')) + '\n')

def capture(folder, snaplen, count, size):
    log = (folder / 'capture.log').open('ab')
    p = subprocess.Popen(['tcpdump', '-Z', 'root', '-n', '-i', cfg['interface'],
        '-B', '8192', '-s', str(snaplen), '-U', '-C', str(size), '-W', str(count),
        '-w', str(folder / 'wire.pcap'), cfg['filter']], stdout=subprocess.DEVNULL, stderr=log)
    log.close()
    return p

def finish(p):
    if p and p.poll() is None:
        p.send_signal(signal.SIGINT)
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

def probe(spec):
    name, kind, address, *rest = spec
    start = time.monotonic()
    if kind == 'tcp':
        try:
            with socket.create_connection((address, rest[0]), 1.2):
                ok = True
        except OSError:
            ok = False
    else:
        prefix = ['ip', 'netns', 'exec', cfg['namespace']] if kind == 'inner' and cfg.get('namespace') else []
        ok = run(prefix + ['ping', '-n', '-c', '1', '-W', '1', address], 2)['rc'] == 0
    return name, {'ok': ok, 'ms': round((time.monotonic()-start)*1000, 1)}

def snapshot(folder, suffix):
    # No configs, environment, credentials, connection payloads or `wg dump`.
    commands = {'routes': ['ip', '-j', 'route'], 'rules': ['ip', '-j', 'rule'],
        'links': ['ip', '-s', '-j', 'link'], 'sockets': ['ss', '-tin', 'dst', cfg['peer']],
        'conntrack': ['sysctl', 'net.netfilter.nf_conntrack_count', 'net.netfilter.nf_conntrack_max'],
        'kernel': ['journalctl', '-k', '--since', '2 minutes ago', '--no-pager', '-n', '60']}
    if cfg.get('namespace'):
        commands['inner_routes'] = ['ip', '-n', cfg['namespace'], '-j', 'route']
    data = {name: run(argv) for name, argv in commands.items()}
    data['utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    (folder / (suffix + '.json')).write_text(json.dumps(data))

cap = capture(ring, 192, 8, 16)
burst = None
incident = None
deadline = 0
last_event = 0
failures = 0
try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        while not stop:
            start = time.monotonic()
            result = dict(pool.map(probe, cfg['probes']))
            bad = any(not result[name]['ok'] for name in cfg['trigger'])
            failures = failures + 1 if bad else 0
            item = {'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'node': cfg['node'], 'monotonic': round(start, 3), 'probes': result,
                    'load': os.getloadavg(), 'capture_alive': cap.poll() is None}
            mem = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
            item['mem_available_kib'] = int(mem['MemAvailable'].split()[0])
            if cfg.get('mode_file'):
                item['mode'] = Path(cfg['mode_file']).read_text().strip()
            if failures >= 2 and start-last_event > 90 and burst is None:
                incident = root / ('incident-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()))
                incident.mkdir(mode=0o700)
                for old in sorted(root.glob('incident-*'))[:-2]:
                    shutil.rmtree(old)
                # The active file can end in an incomplete final record; closed files remain valid.
                for path in sorted(ring.glob('wire.pcap*'), key=lambda p: p.stat().st_mtime)[-2:]:
                    shutil.copyfile(path, incident / ('before-' + path.name))
                snapshot(incident, 'start')
                burst = capture(incident, 0, 2, 32)
                deadline = start + 60
                last_event = start
                item['incident'] = incident.name
            if burst and (start >= deadline or burst.poll() is not None):
                finish(burst)
                snapshot(incident, 'end')
                burst = None
            if cap.poll() is not None:
                item['capture_exit'] = cap.returncode
                cap = capture(ring, 192, 8, 16)
            append(item)
            for _ in range(max(1, int((2-(time.monotonic()-start))*10))):
                if stop:
                    break
                time.sleep(.1)
finally:
    finish(burst)
    finish(cap)
