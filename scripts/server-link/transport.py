#!/usr/bin/python3
"""Select StarFive's delivery path and reject packets from inactive relays."""
import pathlib,subprocess,sys
BASE=pathlib.Path('/var/lib/evgenium-link')
ENDPOINTS={'direct':('38.180.164.67',24447,'eth0'),'hy':('127.0.0.1',24445,'lo'),'tcp':('127.0.0.1',24449,'lo')}
mode=sys.argv[1]
if mode not in ENDPOINTS:raise SystemExit('Invalid transport')
address,port,interface=ENDPOINTS[mode]
exists=subprocess.run(['nft','list','table','inet','evg_link_transport'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
rules=('delete table inet evg_link_transport\n' if exists else '')+f'''table inet evg_link_transport {{
 chain input {{
  type filter hook input priority -6; policy accept;
  udp dport 24444 iifname "{interface}" ip saddr {address} udp sport {port} counter accept
  udp dport 24444 counter drop
 }}
}}
'''
subprocess.run(['nft','-f','-'],input=rules,text=True,check=True)
peer=pathlib.Path('/etc/evgenium-link/peer.key').read_text().strip()
subprocess.run(['ip','netns','exec','evg-link','/opt/evgenium-link/package/usr/bin/wg','set','evg-wg','peer',peer,'endpoint',f'{address}:{port}'],check=True)
p=BASE/'mode.tmp';p.write_text(mode+'\n');p.chmod(0o600);p.replace(BASE/'mode')
