#!/usr/bin/python3
"""Route authenticated IKEv2 clients into the existing Estonia namespace.
Stop keeps the guard and an unreachable policy route. Only uninstall restores Russia egress.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

BASE = Path('/var/lib/evgenium-link/relay')
NS = 'evg-link'
HOST = 'evg-relay-host'
PEER = 'evg-relay-peer'
TABLE = '51827'
PRIO = '210'
POOL = '10.77.0.0/24'
LABEL = 'evgenium-estonia-relay'

def run(*args, check=True, data=None):
    return subprocess.run(list(args), input=data, text=True, capture_output=True, check=check, timeout=15)

def nft(script, ns=False):
    prefix = ['ip', 'netns', 'exec', NS] if ns else []
    run(*prefix, 'nft', '-c', '-f', '-', data=script)
    run(*prefix, 'nft', '-f', '-', data=script)

def replace_table(family, name, body, ns=False):
    prefix = ['ip', 'netns', 'exec', NS] if ns else []
    exists = run(*prefix, 'nft', 'list', 'table', family, name, check=False).returncode == 0
    nft((f'delete table {family} {name}\n' if exists else '')+body, ns)

def remove_accept():
    data = json.loads(run('nft', '-j', '-a', 'list', 'chain', 'inet', 'firewall', 'forward').stdout)
    for item in data['nftables']:
        rule = item.get('rule', {})
        if rule.get('comment') == LABEL:
            run('nft', 'delete', 'rule', 'inet', 'firewall', 'forward', 'handle', str(rule['handle']))

def guard():
    replace_table('inet', 'evg_relay_guard', f'''table inet evg_relay_guard {{
 chain forward {{
  type filter hook forward priority -15; policy accept;
  ip saddr {POOL} ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} counter drop
  ip saddr {POOL} ipsec in reqid > 0 oifname "{HOST}" counter accept
  ip saddr {POOL} counter drop
  iifname "{HOST}" ip daddr {POOL} ipsec out reqid > 0 ct state established,related counter accept
  iifname "{HOST}" counter drop
  oifname "{HOST}" counter drop
 }}
 chain mss {{
  type filter hook forward priority -151; policy accept;
  ip saddr {POOL} tcp flags syn tcp option maxseg size > 1240 tcp option maxseg size set 1240
  ip daddr {POOL} tcp flags syn tcp option maxseg size > 1240 tcp option maxseg size set 1240
 }}
}}\n''')

def policy():
    run('ip', 'route', 'replace', 'unreachable', 'default', 'metric', '32760', 'table', TABLE)
    rules = json.loads(run('ip', '-j', '-4', 'rule').stdout)
    mine = [r for r in rules if r.get('priority') == int(PRIO)]
    if mine and (len(mine) != 1 or str(mine[0].get('table')) != TABLE or (mine[0].get('src') != POOL and (mine[0].get('src') != '10.77.0.0' or mine[0].get('srclen') != 24))):
        raise RuntimeError('policy priority collision')
    if not mine:
        run('ip', 'rule', 'add', 'priority', PRIO, 'from', POOL, 'lookup', TABLE)

def start():
    if not BASE.exists():
        if Path('/sys/class/net/'+HOST).exists() or run('ip','route','show','table',TABLE,check=False).stdout.strip():
            raise RuntimeError('unowned relay objects')
        BASE.mkdir(mode=0o700)
    guard()
    policy()
    if not Path('/run/netns/'+NS).exists():
        run('ip','netns','add',NS)
    if Path('/sys/class/net/'+PEER).exists():
        run('ip','link','set',PEER,'netns',NS)
    if not Path('/sys/class/net/'+HOST).exists():
        run('ip','link','add',HOST,'type','veth','peer','name',PEER)
        run('ip','link','set',PEER,'netns',NS)
    run('ip','addr','replace','10.203.72.1/30','dev',HOST)
    run('ip','-n',NS,'addr','replace','10.203.72.2/30','dev',PEER)
    run('ip','link','set',HOST,'mtu','1280','up')
    run('ip','-n',NS,'link','set',PEER,'mtu','1280','up')
    Path('/proc/sys/net/ipv4/conf/'+HOST+'/forwarding').write_text('1\n')
    Path('/proc/sys/net/ipv4/conf/'+HOST+'/rp_filter').write_text('0\n')
    run('ip','netns','exec',NS,'sysctl','-qw','net.ipv4.conf.'+PEER+'.forwarding=1')
    run('ip','-n',NS,'route','replace',POOL,'via','10.203.72.1','dev',PEER)
    replace_table('inet','evg_relay',f'''table inet evg_relay {{
 chain input {{ type filter hook input priority -15; policy accept; iifname "{PEER}" counter drop; }}
 chain forward {{
  type filter hook forward priority -15; policy drop;
  iifname "{PEER}" oifname "evg-wg" ip saddr {POOL} ct state new,established,related counter accept
  iifname "evg-wg" oifname "{PEER}" ip daddr {POOL} ct state established,related counter accept
 }}
 chain nat {{ type nat hook postrouting priority srcnat; policy accept;
  ip saddr {POOL} oifname "evg-wg" snat ip to 10.203.71.2
 }}
}}\n''',ns=True)
    remove_accept()
    run('nft','add','rule','inet','firewall','forward','ip','saddr',POOL,'ipsec','in','reqid','>','0','oifname',HOST,'counter','accept','comment',LABEL)
    run('ip','route','replace','default','via','10.203.72.2','dev',HOST,'metric','10','table',TABLE)
    print('relay enabled; only authenticated client pool routed to Estonia')

def stop():
    if not BASE.exists(): return
    run('ip','route','del','default','metric','10','table',TABLE,check=False)
    guard(); policy()
    remove_accept()
    run('ip','link','del',HOST,check=False)
    run('ip','netns','exec',NS,'nft','delete','table','inet','evg_relay',check=False)
    print('relay stopped; client egress remains blocked')

def check():
    if not BASE.exists() or Path('/var/lib/evgenium-link/resource-hold').exists(): return
    if run('systemctl','is-active','--quiet','evgenium-relay',check=False).returncode != 0: return
    healthy = Path('/sys/class/net/'+HOST).exists()
    healthy = healthy and run('nft','list','table','inet','evg_relay_guard',check=False).returncode == 0
    healthy = healthy and LABEL in run('nft','list','chain','inet','firewall','forward',check=False).stdout
    healthy = healthy and run('ip','netns','exec',NS,'nft','list','table','inet','evg_relay',check=False).returncode == 0
    healthy = healthy and 'via 10.203.72.2' in run('ip','route','show','table',TABLE,check=False).stdout
    if healthy: return
    path=BASE/'repairs.json'
    attempts=json.loads(path.read_text()) if path.exists() else []
    attempts=[x for x in attempts if time.time()-x<3600]
    if len(attempts)>=5: raise RuntimeError('relay repair budget exhausted')
    attempts.append(time.time());path.write_text(json.dumps(attempts));path.chmod(0o600)
    start()

if __name__ == '__main__':
    if sys.argv[1] == 'start': start()
    elif sys.argv[1] == 'stop': stop()
    elif sys.argv[1] == 'check': check()
    else: raise SystemExit('use start or stop')
