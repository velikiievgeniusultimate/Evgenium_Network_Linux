#!/usr/bin/env python3
"""Own exactly one ingress rule in the deployment's existing firewall."""
import json,subprocess,sys
TAG='evgenium-tcp-relay'
def run(*args):return subprocess.check_output(args,text=True)
rules=json.loads(run('nft','-j','list','chain','inet','firewall','input'))['nftables']
for item in rules:
 r=item.get('rule',{})
 if r.get('comment')==TAG:run('nft','delete','rule','inet','firewall','input','handle',str(r['handle']))
if sys.argv[1]=='open':
 run('nft','insert','rule','inet','firewall','input','tcp','dport','24579','ct','state','new','limit','rate','60/second','burst','120','packets','accept','comment','"'+TAG+'"')
