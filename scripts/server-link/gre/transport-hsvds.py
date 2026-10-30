#!/usr/bin/python3
"""Select StarFive's delivery path and reject packets from inactive relays."""
import pathlib,subprocess,sys
BASE=pathlib.Path('/var/lib/evgenium-link')
ENDPOINTS={'direct':('38.180.164.67',24547,'enp3s0'),'hy':('127.0.0.1',24545,'lo'),'tcp':('127.0.0.1',24549,'lo')}
ENDPOINTS['home']=('127.0.0.1',24553,'lo')
ENDPOINTS['reality']=('127.0.0.1',24555,'lo')
ENDPOINTS['xhttp']=('127.0.0.1',24557,'lo')
ENDPOINTS['xhttpcf']=('127.0.0.1',24593,'lo')
ENDPOINTS['evgt']=('127.0.0.1',24569,'lo')
ENDPOINTS['gre']=('10.203.119.1',24547,'evg-gre-wan')
mode=sys.argv[1]
if mode in ('xhttpcf','evgt','gre') and (BASE/'resource-hold').exists():raise SystemExit('resource hold active')
if mode not in ENDPOINTS:raise SystemExit('Invalid transport')
address,port,interface=ENDPOINTS[mode]
exists=subprocess.run(['nft','list','table','inet','evg_link_transport'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
rules=('delete table inet evg_link_transport\n' if exists else '')+f'''table inet evg_link_transport {{
 chain input {{
  type filter hook input priority -6; policy accept;
  udp dport 24544 iifname "{interface}" ip saddr {address} udp sport {port} counter accept
  udp dport 24544 counter drop
 }}
}}
'''
subprocess.run(['nft','-f','-'],input=rules,text=True,check=True)
peer=pathlib.Path('/etc/evgenium-link/peer.key').read_text().strip()
subprocess.run(['ip','netns','exec','evg-link','/usr/bin/wg','set','evg-wg','peer',peer,'endpoint',f'{address}:{port}'],check=True)
p=BASE/'mode.tmp';p.write_text(mode+'\n');p.chmod(0o600);p.replace(BASE/'mode')
