#!/usr/bin/env python3
"""Choose only independently proven paths; keep data inside the existing WG tunnel."""
import concurrent.futures
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import time

ORDER = ('tcp', 'hy', 'home')
PORTS = {'tcp': 24549, 'hy': 24545, 'home': 24553}
BASE = Path('/var/lib/evgenium-link')
LOG = Path('/var/log/evgenium-link/health.jsonl')
STOP = False

def choose(mode, streaks, failures, since_switch, preferred='tcp'):
    if since_switch < 6:
        return None
    if failures >= 2:
        return next((p for p in ORDER if p != mode and streaks.get(p, 0) >= 2), None)
    if mode != preferred and since_switch >= 180 and streaks.get(preferred, 0) >= 90:
        return preferred
    return None

def stalled_transport(mode, inner, bad, since_restart):
    # Never restart the working data transport because a separate probe failed.
    # One bounded repair at a time, even when every physical path is unavailable.
    return next((p for p in ORDER if bad.get(p, 0) >= 6
                 and since_restart.get(p, 0) >= 120
                 and (p != mode or not inner)), None)

def command(argv, timeout=3):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, '', 'deadline')

def ping(namespace):
    start = time.monotonic()
    r = command(['ip','netns','exec',namespace,'ping','-n','-c','1','-W','1','10.203.81.1'], 2)
    return {'ok': r.returncode == 0, 'ms': round((time.monotonic()-start)*1000, 1)}

def append(data):
    if LOG.exists() and LOG.stat().st_size > 8*1024*1024:
        for i in range(14, 0, -1):
            p = Path(str(LOG)+'.'+str(i))
            if p.exists():
                p.replace(str(LOG)+'.'+str(i+1))
        LOG.replace(str(LOG)+'.1')
    with LOG.open('a') as f:
        f.write(json.dumps(data, separators=(',',':'))+'\n')

def main():
    global STOP
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: globals().__setitem__('STOP', True))
    lock = (BASE/'resilient-health.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
    streaks = {p: 0 for p in ORDER}
    failures = 0
    bad = {p: 0 for p in ORDER}
    restarted = {p: time.monotonic()-120 for p in ORDER}
    last_switch = time.monotonic()-180
    last_egress = 0
    egress_ok = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        while not STOP:
            start = time.monotonic()
            if (BASE/'maintenance').exists() or (BASE/'resource-hold').exists():
                time.sleep(2)
                continue
            mode = (BASE/'mode').read_text().strip()
            futures = {p:pool.submit(ping,'evg-probe-'+p) for p in ORDER}
            real = pool.submit(ping,'evg-link')
            paths = {p:f.result() for p,f in futures.items()}
            inner = real.result()['ok']
            for p in ORDER:
                streaks[p] = streaks[p]+1 if paths[p]['ok'] else 0
                bad[p] = 0 if paths[p]['ok'] else bad[p]+1
            endpoint = command(['ip','netns','exec','evg-link','wg','show','evg-wg','endpoints'])
            actual = endpoint.stdout.split()[-1] if endpoint.stdout.split() else None
            matches = actual == '127.0.0.1:'+str(PORTS.get(mode, 0))
            failures = 0 if inner and matches else failures+1
            row = {'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                'monotonic':round(start,2),'mode':mode,'local_ok':endpoint.returncode==0,
                'inner_ok':inner,'actual_endpoint':actual,'endpoint_matches_mode':matches,
                'paths':paths,'failures':failures}
            preferred = (BASE/'preferred-mode').read_text().strip() if (BASE/'preferred-mode').exists() else 'tcp'
            target = choose(mode,streaks,failures,start-last_switch,preferred)
            if target:
                r = command(['python3','/opt/evgenium-link/transport.py',target], 10)
                row.update(action='switch_own_transport',target=target,action_ok=r.returncode==0,
                           reason='failed_path' if failures>=2 else 'preferred_path_stable_180s')
                last_switch = start
                if r.returncode == 0:
                    failures = 0
            repair = stalled_transport(target if target and row.get('action_ok') else mode,
                                       inner, bad, {p:start-restarted[p] for p in ORDER})
            if repair:
                unit = 'evgenium-link-'+repair+'.service'
                r = command(['systemctl','restart',unit], 10)
                restarted[repair] = time.monotonic()
                row['transport_repair'] = {'path':repair,'ok':r.returncode==0,
                                           'reason':'six_failed_independent_probes'}
                # Require fresh successful probes before considering this path usable.
                bad[repair] = 0
                streaks[repair] = 0
            if inner and time.monotonic()-last_egress >= 30:
                r = command(['ip','netns','exec','evg-link','curl','-4','--noproxy','*','-fsS',
                    '--connect-timeout','2','--max-time','3','https://api.ipify.org'],4)
                last_egress = time.monotonic()
                egress_ok = r.returncode==0 and r.stdout.strip()=='38.180.164.67'
                row['egress_ok'] = egress_ok
                row['egress_exit'] = r.returncode
            row.update(last_egress_ok=egress_ok,egress_age_s=round(time.monotonic()-last_egress))
            append(row)
            pending = BASE/'resilient-health-state.tmp'
            pending.write_text(json.dumps(row))
            pending.replace(BASE/'resilient-health-state.json')
            for _ in range(max(1,int((2-(time.monotonic()-start))*10))):
                if STOP:
                    break
                time.sleep(.1)

if __name__ == '__main__':
    main()
