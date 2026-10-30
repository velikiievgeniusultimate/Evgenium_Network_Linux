#!/usr/bin/python3
"""Publish own hostname on 443 while retaining the existing TLS listener unchanged.

NAT only applies to new inbound connections. Removing the owned table restores
new 443 connections directly to the original listener; established flows persist.
"""
import json
import pathlib
import subprocess
import sys
TABLE='evg_connect_public'
PREFIX='evgenium-connect-front-'
STATE=pathlib.Path('/opt/evgenium-connect-infra/front-owned.json')


def run(args, check=True, **kw):
    return subprocess.run(args, text=True, capture_output=True, timeout=10, check=check, **kw)


def remove_input():
    obj=json.loads(run(['nft','-ja','list','chain','inet','firewall','input']).stdout)
    for item in obj['nftables']:
        rule=item.get('rule',{})
        if rule.get('comment','').startswith(PREFIX):
            run(['nft','delete','rule','inet','firewall','input','handle',str(rule['handle'])])


def up(http_only=False):
    if not STATE.exists():
        if run(['nft','list','table','inet',TABLE],False).returncode==0:raise RuntimeError('unowned_front_table')
        STATE.write_text(json.dumps({'table':TABLE,'public':'195.209.211.163'}));STATE.chmod(0o600)
    remove_input()
    rules=f'insert rule inet firewall input ip daddr 195.209.211.163 tcp dport 80 counter accept comment "{PREFIX}http"\n'
    if not http_only:
        # Direct access to 9444 remains blocked; only DNATed original 443 enters.
        rules+=f'insert rule inet firewall input ip daddr 195.209.211.163 tcp dport 9444 ct original proto-dst 443 counter accept comment "{PREFIX}https"\n'
        if run(['nft','list','table','inet',TABLE],False).returncode==0:rules+=f'delete table inet {TABLE}\n'
        rules+=f'''table inet {TABLE} {{
 chain prerouting {{ type nat hook prerouting priority dstnat - 1; policy accept;
  iifname "enp3s0" ip daddr 195.209.211.163 tcp dport 443 counter redirect to :9444
 }}
}}
'''
    run(['nft','-f','-'],input=rules)


def down():
    if not STATE.exists():return
    run(['nft','delete','table','inet',TABLE],False)
    remove_input()


if __name__=='__main__':
    if sys.argv[1:]==['up']:up()
    elif sys.argv[1:]==['http']:up(True)
    elif sys.argv[1:]==['down']:down()
    else:raise SystemExit('expected up|http|down')
