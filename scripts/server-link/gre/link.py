#!/usr/bin/python3
"""Own keyed GRE carrying authenticated WireGuard only. Never forwards plaintext."""
import pathlib,json,subprocess,sys
B=pathlib.Path('/opt/evgenium-direct-gre');IF='evg-gre-wan';TABLE='evg_direct_gre';COMMENT='evgenium-direct-gre'
c=json.loads((B/'config.json').read_text());state=B/'owned.json'
def q(a,check=True,**kw):return subprocess.run(a,text=True,capture_output=True,check=check,timeout=15,**kw)
def save(s):
 p=B/'owned.tmp';p.write_text(json.dumps(s));p.chmod(0o600);p.replace(state)
def down():
 if not state.exists():return
 s=json.loads(state.read_text())
 if s.get('outer_rule'):
  obj=json.loads(q(['nft','-ja','list','chain','inet','firewall','input']).stdout)
  for x in obj['nftables']:
   r=x.get('rule',{})
   if r.get('comment')==COMMENT:q(['nft','delete','rule','inet','firewall','input','handle',str(r['handle'])])
 if s.get('table'):q(['nft','delete','table','inet',TABLE],False)
 if s.get('link'):q(['ip','link','delete',IF],False)
 state.unlink(missing_ok=True)
def up():
 if pathlib.Path('/var/lib/evgenium-link/resource-hold').exists():raise RuntimeError('resource hold active')
 if state.exists():down()
 assert not pathlib.Path('/sys/class/net',IF).exists(),'unowned GRE interface'
 assert q(['nft','list','table','inet',TABLE],False).returncode!=0,'unowned GRE table'
 assert '10.203.119.' not in q(['ip','-4','route','show','table','all']).stdout,'GRE subnet collision'
 s={};save(s)
 try:
  q(['ip','tunnel','add',IF,'mode','gre','local',c['local'],'remote',c['remote'],'key','3882046209','ttl','64']);s['link']=True;save(s)
  q(['ip','link','set',IF,'mtu','1440']);q(['ip','addr','add',c['address']+'/30','dev',IF])
  port='sport' if c['role']=='ru' else 'dport'
  rules=f'''table inet {TABLE} {{
 chain input {{ type filter hook input priority -40; policy accept;
  iifname "{IF}" ip saddr {c['peer']} ip daddr {c['address']} udp {port} 24547 accept
  iifname "{IF}" ip saddr {c['peer']} ip daddr {c['address']} ip protocol icmp accept
  iifname "{IF}" counter drop
 }}
 chain forward {{ type filter hook forward priority -40; policy accept; iifname "{IF}" drop; oifname "{IF}" drop; }}
 chain output {{ type filter hook output priority -40; policy accept;
  oifname "{IF}" ip saddr {c['address']} ip daddr {c['peer']} udp {'dport' if c['role']=='ru' else 'sport'} 24547 accept
  oifname "{IF}" ip saddr {c['address']} ip daddr {c['peer']} ip protocol icmp accept
  oifname "{IF}" counter drop
 }}
}}'''
  q(['nft','-f','-'],input=rules);s['table']=True;save(s)
  if c['role']=='ru':
   q(['nft','-f','-'],input=f'insert rule inet firewall input ip saddr {c["remote"]} ip protocol gre counter accept comment "{COMMENT}"\n');s['outer_rule']=True;save(s)
  q(['ip','link','set',IF,'up'])
 except BaseException:
  down();raise
if sys.argv[1]=='up':up()
elif sys.argv[1]=='down':down()
elif sys.argv[1]=='hold':
 if pathlib.Path('/var/lib/evgenium-link/resource-hold').exists():q(['systemctl','stop','evgenium-direct-gre.service'])
else:raise SystemExit('bad action')
