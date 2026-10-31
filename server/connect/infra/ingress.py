#!/usr/bin/python3
"""Own WireGuard entry; the only client forwarding path is the Estonia relay.

Does not modify either host's default route, DNS or existing WireGuard peers.
The unreachable policy route and early nft drops remain when the relay fails.
"""
import json
import pathlib
import subprocess
import sys

B = pathlib.Path('/etc/evgenium-wireguard')
STATE = pathlib.Path('/var/lib/evgenium-wireguard/ingress-owned.json')
IF = 'evg-clients'
TABLE = 'evg_wg_clients'
NS_TABLE = 'evg_wg_entry'
NS = 'evg-link'
PREFIX = 'evgenium-wg-entry-'


def run(args, check=True, **kwargs):
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=15, **kwargs)


def state_write(data):
    STATE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = STATE.with_suffix('.new')
    temp.write_text(json.dumps(data)); temp.chmod(0o600); temp.replace(STATE)


def nft_rules(text, namespace=False):
    prefix = ['ip', 'netns', 'exec', NS] if namespace else []
    run(prefix + ['nft', '-f', '-'], input=text)


def replace_table(name, rules, namespace=False):
    prefix = ['ip', 'netns', 'exec', NS] if namespace else []
    present = run(prefix + ['nft', 'list', 'table', 'inet', name], False).returncode == 0
    nft_rules((f'delete table inet {name}\n' if present else '') + rules, namespace)


def firewall_remove():
    for chain in ['input', 'forward']:
        obj = json.loads(run(['nft', '-ja', 'list', 'chain', 'inet', 'firewall', chain]).stdout)
        for row in obj['nftables']:
            rule = row.get('rule', {})
            if rule.get('comment', '').startswith(PREFIX):
                run(['nft', 'delete', 'rule', 'inet', 'firewall', chain, 'handle', str(rule['handle'])])


def up():
    if pathlib.Path('/var/lib/evgenium-link/resource-hold').exists():
        raise RuntimeError('resource_hold_active')
    owned = STATE.exists()
    if not owned:
        if pathlib.Path('/sys/class/net', IF).exists(): raise RuntimeError('unowned_interface')
        if '10.78.0.' in run(['ip', '-4', 'route', 'show', 'table', 'all']).stdout: raise RuntimeError('subnet_collision')
        if run(['ip', '-4', 'route', 'show', 'table', '51828'], False).stdout.strip(): raise RuntimeError('policy_table_collision')
        for name, ns in [(TABLE, False), (NS_TABLE, True)]:
            pre = ['ip', 'netns', 'exec', NS] if ns else []
            if run(pre + ['nft', 'list', 'table', 'inet', name], False).returncode == 0: raise RuntimeError('unowned_firewall_table')
        state_write({'interface': IF, 'table': 51828, 'namespace': NS})
    # A missing relay never permits fallback to the host's main Internet route.
    run(['ip', '-4', 'route', 'replace', 'unreachable', 'default', 'table', '51828', 'metric', '32760'])
    rules = run(['ip', '-4', 'rule', 'show']).stdout
    if 'from 10.78.0.0/24 lookup 51828' not in rules:
        if any(line.startswith('211:') for line in rules.splitlines()): raise RuntimeError('rule_priority_collision')
        run(['ip', '-4', 'rule', 'add', 'priority', '211', 'from', '10.78.0.0/24', 'lookup', '51828'])
    replace_table(TABLE, f'''table inet {TABLE} {{
 chain input {{ type filter hook input priority -40; policy accept;
  iifname "{IF}" ip saddr 10.78.0.0/24 ip daddr 195.209.211.163 tcp dport {{ 80, 8443 }} counter accept
  iifname "{IF}" ip saddr 10.78.0.0/24 ip daddr 195.209.211.163 tcp dport 9444 ct original proto-dst 443 counter accept
  iifname "{IF}" ip saddr 10.78.0.0/24 ip daddr 10.78.0.1 udp dport 24588 counter accept
  iifname "{IF}" counter drop
 }}
 chain forward {{ type filter hook forward priority -40; policy accept;
  iifname "{IF}" meta nfproto ipv6 counter drop
  oifname "{IF}" meta nfproto ipv6 counter drop
  iifname "{IF}" ip saddr != 10.78.0.0/24 counter drop
  iifname "{IF}" ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }} counter drop
  iifname "{IF}" oifname != "evg-relay-host" counter drop
  oifname "{IF}" iifname != "evg-relay-host" counter drop
  oifname "{IF}" ct state != {{ established, related }} counter drop
 }}
}}''')
    replace_table(NS_TABLE, f'''table inet {NS_TABLE} {{
 chain input {{ type filter hook input priority -40; policy accept; iifname "evg-relay-peer" ip saddr 10.78.0.0/24 counter drop; }}
 chain forward {{ type filter hook forward priority -20; policy accept;
  iifname "evg-relay-peer" ip saddr 10.78.0.0/24 oifname != "evg-wg" counter drop
  oifname "evg-relay-peer" ip daddr 10.78.0.0/24 iifname != "evg-wg" counter drop
 }}
 chain nat {{ type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.78.0.0/24 oifname "evg-wg" snat ip to 10.203.81.2
 }}
}}''', True)
    # The relay's default policy is drop; whitelist only this new client subnet.
    existing = json.loads(run(['ip', 'netns', 'exec', NS, 'nft', '-ja', 'list', 'chain', 'inet', 'evg_relay', 'forward']).stdout)
    comments = {x.get('rule', {}).get('comment') for x in existing['nftables']}
    ns = ''
    for tag, rule in [('out', 'iifname "evg-relay-peer" oifname "evg-wg" ip saddr 10.78.0.0/24 ct state established,related,new'), ('in', 'iifname "evg-wg" oifname "evg-relay-peer" ip daddr 10.78.0.0/24 ct state established,related')]:
        if PREFIX+tag not in comments: ns += f'insert rule inet evg_relay forward {rule} counter accept comment "{PREFIX+tag}"\n'
    if ns: nft_rules(ns, True)
    firewall_remove()
    nft_rules(f'''insert rule inet firewall input udp dport 51820 counter accept comment "{PREFIX}input"
insert rule inet firewall input iifname "{IF}" ip saddr 10.78.0.0/24 ip daddr 10.78.0.1 udp dport 24588 counter accept comment "{PREFIX}diagnostic"
insert rule inet firewall input tcp dport {{ 24580, 24581 }} counter accept comment "{PREFIX}windows-carriers"
insert rule inet firewall forward iifname "{IF}" ip saddr 10.78.0.0/24 oifname "evg-relay-host" ct state established,related,new counter accept comment "{PREFIX}out"
insert rule inet firewall forward iifname "evg-relay-host" oifname "{IF}" ip daddr 10.78.0.0/24 ct state established,related counter accept comment "{PREFIX}in"
''')
    run(['ip', '-4', 'route', 'replace', 'default', 'via', '10.203.82.2', 'dev', 'evg-relay-host', 'table', '51828', 'metric', '10'])
    run(['ip', 'netns', 'exec', NS, 'ip', '-4', 'route', 'replace', '10.78.0.0/24', 'via', '10.203.82.1', 'dev', 'evg-relay-peer'])
    if not pathlib.Path('/sys/class/net', IF).exists(): run(['ip', 'link', 'add', IF, 'type', 'wireguard'])
    run(['wg', 'set', IF, 'listen-port', '51820', 'private-key', str(B/'server.key')])
    present = json.loads(run(['ip', '-j', '-4', 'addr', 'show', 'dev', IF]).stdout)
    if not any(a.get('local') == '10.78.0.1' for i in present for a in i.get('addr_info', [])):
        run(['ip', 'addr', 'add', '10.78.0.1/24', 'dev', IF])
    run(['ip', 'link', 'set', IF, 'mtu', '1280', 'up'])
    run(['/usr/bin/python3', '/usr/local/sbin/evgenium-token-issuer', 'sync-wireguard'])
    print('WireGuard entry ready; client forwarding limited to the Estonia relay.')


def down():
    if not STATE.exists(): return
    # Keep policy, firewall drops and tombstone; stopping cannot expose clients.
    run(['ip', 'link', 'delete', IF], False)
    firewall_remove()
    print('Own WireGuard entry stopped; fail-closed policy retained.')


if __name__ == '__main__':
    if sys.argv[1:] == ['up']: up()
    elif sys.argv[1:] == ['down']: down()
    else: raise SystemExit('expected up|down')
