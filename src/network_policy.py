"""Local traffic selection for the token tunnel. No remote proxy protocol."""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import time

api = None
tunnel = None
PATH = Path('/etc/vpn-manager/policy.json')
RUN = Path('/run/vpn-manager')
SERVICE = 'evgenium-policy.service'
WAYDROID_SERVICE = 'evgenium-waydroid-network.service'
TUN = 'evn-policy'
DIRECT = 0x45564E31
VPN = 0x45564E32
PHYSICAL_TABLE = '51830'
VPN_TABLE = '51831'
DNS_PORT = 18553
CHECK_PORT = 18554
CATEGORIES = ('applications','networks','ports','dns')
BASE = {
 'applications': [{'id':'mapper','value':'evgenium-waydroid-mapper','label':'Waydroid Mapper'}],
 'networks': [{'id':'lan','value':'connected','label':'Устройства текущей локальной сети'},
              {'id':'linklocal','value':'169.254.0.0/16','label':'Устройства с автоматическим локальным адресом'}],
 'ports': [{'id':'discovery','value':'discovery','label':'Обнаружение устройств: mDNS, SSDP, LLMNR (только локальная сеть)'}],
 'dns': [{'id':'stub','value':'127.0.0.0/8','label':'Системный DNS внутри компьютера'}]
}

def defaults():
 return {'schema':1,'waydroid_direct':True,'disabled_base':[], 'applications':[], 'networks':[], 'ports':[], 'dns':[]}

def load():
 if not PATH.exists():return defaults()
 value=json.loads(PATH.read_text())
 if value.get('schema')!=1:raise RuntimeError('Неизвестная версия правил исключений.')
 return {**defaults(),**value}

def save(value):
 PATH.parent.mkdir(parents=True,exist_ok=True)
 tmp=PATH.with_suffix('.new')
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f,ensure_ascii=False,indent=2)
 os.replace(tmp,PATH)

def enabled(p,cat,key):return cat+':'+key not in p['disabled_base']

def normalize(category,value):
 value=str(value).strip()
 if not value or len(value)>512 or any(ord(c)<32 for c in value):raise ValueError('Некорректное исключение.')
 if category=='applications':
  if not re.fullmatch(r'[\w./ +@()\-]+',value):raise ValueError('Укажите имя процесса или полный путь.')
  if '/' in value and not value.startswith('/'):raise ValueError('Путь должен быть абсолютным.')
  return value
 if category=='networks':
  try:
   net=ipaddress.ip_network(value,strict=False)
   if net.version!=4:raise ValueError('Поддерживаются адреса вида 192.168.1.10.')
   # Addresses owned by our tunnels cannot be routed physically.
   reserved=['10.77.0.0/24',tunnel.NETWORK,tunnel.FULL_NET,'198.18.254.0/30'] if tunnel else ['10.77.0.0/24','172.29.246.0/30','172.29.247.0/30','198.18.254.0/30']
   if any(net.overlaps(ipaddress.ip_network(n)) for n in reserved):raise ValueError('Диапазон пересекается со служебной сетью VPN. Добавьте более узкую сеть.')
   return str(net)
  except ValueError as exc:
   if '/' in value or re.fullmatch(r'[\d.]+',value):raise exc
  exact=value.startswith('=');value=value.lstrip('=').lower().rstrip('.')
  try:value=value.encode('idna').decode('ascii')
  except UnicodeError:raise ValueError('Некорректный домен.')
  if len(value)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in value.split('.')):raise ValueError('Введите домен без https:// и пути.')
  return ('=' if exact else '')+value
 if category=='dns':
  addr=ipaddress.ip_address(value)
  if addr.version!=4 or addr.is_unspecified or addr.is_multicast or addr.is_loopback:raise ValueError('Укажите адрес внешнего или домашнего DNS-сервера; локальный DNS находится в базовых правилах.')
  return str(addr)
 if category=='ports':
  match=re.fullmatch(r'(tcp|udp|both):(\d{1,5})(?::(out|in|both))?',value.lower())
  if not match or not 1<=int(match[2])<=65535:raise ValueError('Формат: tcp:443:out, udp:25565:in или both:25565:both.')
  if int(match[2])==53:raise ValueError('DNS настраивается во вкладке DNS.')
  return f'{match[1]}:{int(match[2])}:{match[3] or "both"}'
 raise ValueError('Неизвестная категория.')

def migration(settings):
 if PATH.exists():return
 p=defaults(); rejected=[]
 sources={'applications':settings.get('direct_apps'),'networks':settings.get('direct_networks')}
 for category,key in sources.items():
  if key and Path(key).is_file():
   for line in Path(key).read_text().splitlines():
    s=line.strip()
    if not s or s.startswith('#'):continue
    try:p[category].append(normalize(category,s))
    except ValueError:rejected.append({'category':category,'value':s})
 key=settings.get('direct_sites')
 if key and Path(key).is_file():
  for line in Path(key).read_text().splitlines():
   s=line.strip()
   if not s or s.startswith('#'):continue
   s=s.replace('full:','=',1).removeprefix('domain:')
   try:p['networks'].append(normalize('networks',s))
   except ValueError:rejected.append({'category':'networks','value':s})
 for proto,port in api.read_server_ports(settings):p['ports'].append(f'{proto}:{port}:in')
 for c in CATEGORIES:p[c]=list(dict.fromkeys(p[c]))
 p['migration_skipped']=rejected
 save(p)

def public():
 p=load();base={}
 for c,entries in BASE.items():base[c]=[{**e,'enabled':enabled(p,c,e['id'])} for e in entries]
 return {**p,'base':base}

def ports(p,direction):
 result={'tcp':set(),'udp':set()}
 for value in p['ports']:
  proto,number,side=value.split(':')
  if side not in (direction,'both'):continue
  for protocol in ('tcp','udp') if proto=='both' else (proto,):result[protocol].add(int(number))
 return result

def local_networks(route):
 data=json.loads(tunnel.command(['ip','-j','-4','addr','show','dev',route['dev']]).stdout)
 return sorted({str(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}",strict=False)) for link in data for a in link.get('addr_info',[]) if a.get('scope')=='global'})

def direct_networks(p,lan):
 values=[]
 for value in p['networks']:
  try:values.append(str(ipaddress.ip_network(value)))
  except ValueError:pass
 if enabled(p,'networks','lan'):
  for item in lan:
   remaining=[ipaddress.ip_network(item)]
   for reserved in ['10.77.0.0/24','172.29.246.0/30','172.29.247.0/30','198.18.254.0/30']:
    block=ipaddress.ip_network(reserved);updated=[]
    for net in remaining:
     if not net.overlaps(block):updated.append(net)
     elif block.subnet_of(net):updated.extend(net.address_exclude(block))
    remaining=updated
   values += [str(n) for n in remaining]
 if enabled(p,'networks','linklocal'):values+=['169.254.0.0/16']
 return sorted(set(values))

def config(p):
 rules=[{'type':'field','inboundTag':['check'],'outboundTag':'vpn'},
        {'type':'field','inboundTag':['dns-in'],'outboundTag':'dns'}]
 apps=list(p['applications'])
 if enabled(p,'applications','mapper'):apps+=['evgenium-waydroid-mapper']
 if apps:rules.append({'type':'field','process':apps,'inboundTag':['tun'],'outboundTag':'direct'})
 domains=[]
 for value in p['networks']:
  try:ipaddress.ip_network(value)
  except ValueError:domains.append(('full:'+value[1:]) if value.startswith('=') else 'domain:'+value)
 if domains:rules.append({'type':'field','domain':domains,'inboundTag':['tun'],'outboundTag':'direct'})
 # DNS engine requests must never inherit domain/application bypass rules.
 rules+=[{'type':'field','inboundTag':['dns-engine'],'outboundTag':'vpn'},
         {'type':'field','inboundTag':['tun'],'outboundTag':'vpn'}]
 return {'log':{'loglevel':'warning','access':'none'},
  'inbounds':[{'tag':'tun','protocol':'tun','settings':{'name':TUN,'mtu':1280,'gateway':['198.18.254.1/30']},
               'sniffing':{'enabled':True,'destOverride':['http','tls','quic'],'routeOnly':True}},
              {'tag':'dns-in','listen':'127.0.0.1','port':DNS_PORT,'protocol':'dokodemo-door','settings':{'address':'1.1.1.1','port':53,'network':'tcp,udp'}},
              {'tag':'check','listen':'127.0.0.1','port':CHECK_PORT,'protocol':'socks','settings':{'auth':'noauth','udp':False}}],
  'dns':{'servers':['1.1.1.1','9.9.9.9'],'queryStrategy':'UseIPv4','tag':'dns-engine','disableFallback':False},
  'outbounds':[{'tag':tag,'protocol':'freedom','settings':{'domainStrategy':'UseIPv4'},'streamSettings':{'sockopt':{'mark':mark}}} for tag,mark in [('vpn',VPN),('direct',DIRECT)]]+
               [{'tag':'dns','protocol':'dns','settings':{'rules':[{'qType':'1,28','action':'hijack'},{'action':'direct'}]},'streamSettings':{'sockopt':{'mark':VPN}}}],
  'routing':{'domainStrategy':'AsIs','rules':rules}}

def nft_set(items):return '{ '+', '.join(str(x) for x in sorted(items))+' }'

def firewall(p,lan,uid):
 # Route marks are set only by this privileged classifier or explicit kernel rules.
 mark=[];dns=[];forward=[];nat=['meta nfproto ipv4 meta mark '+str(DIRECT)+' oifname != "lo" masquerade']
 if enabled(p,'dns','stub'):dns.append('ip daddr 127.0.0.0/8 return')
 if p['dns']:
  dns.append(f'ip daddr {nft_set(p["dns"])} return')
  mark.append(f'ip daddr {nft_set(p["dns"])} meta l4proto {{ tcp, udp }} th dport 53 meta mark set {DIRECT} return')
 # Interface-bound system resolvers must keep DNS on the tunnel interface.
 # Redirecting their upstream socket to loopback breaks SO_BINDTODEVICE.
 # Only an explicitly disabled loopback-stub rule uses the local DNS listener.
 dns+=['ip daddr 127.0.0.0/8 meta l4proto { tcp, udp } th dport 53 redirect to :'+str(DNS_PORT),
       'meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 dnat ip to 1.1.1.1']
 mark+=['meta l4proto { tcp, udp } th dport 53 meta mark set '+str(VPN)+' return']
 waynets=waydroid_network()['networks']
 mark.append(f'ip daddr @waydroid_networks meta mark set {DIRECT} return')
 mark.append(f'oifname "waydroid0" udp sport 67 udp dport 68 meta mark set {DIRECT} return')
 nets=direct_networks(p,lan)
 if nets:mark.append(f'ip daddr {nft_set(nets)} meta mark set {DIRECT} return')
 if enabled(p,'ports','discovery'):
  mark+=['ip daddr { 224.0.0.251, 224.0.0.252, 239.255.255.250 } udp dport { 5353, 5355, 1900 } meta mark set '+str(DIRECT)+' return']
 for direction in ('out','in'):
  for proto,values in ports(p,direction).items():
   if values:mark.append(('ct direction reply ' if direction=='in' else '')+f'{proto} {"sport" if direction=="in" else "dport"} {nft_set(values)} meta mark set {DIRECT} return')
 if p['waydroid_direct']:
  forward=['iifname "waydroid0" meta nfproto ipv4 meta mark set '+str(DIRECT)+' ct mark set '+str(DIRECT), 'ct direction reply ct mark '+str(DIRECT)+' meta mark set '+str(DIRECT)]

 def lines(items):return '\n'.join('  '+x for x in items)
 return f'''table inet {tunnel.FULL_GUARD} {{
 set waydroid_networks {{ type ipv4_addr; flags interval; {('elements = '+nft_set(waynets)+';') if waynets else ''} }}
 chain route {{ type route hook output priority -150; policy accept;
  meta skuid {uid} return
  meta mark set 0
  ip daddr 127.0.0.0/8 return
{lines(mark)}
 }}
 chain dns {{ type nat hook output priority -101; policy accept;
  meta skuid {uid} return
{lines(dns)}
 }}
 chain preroute {{ type filter hook prerouting priority -150; policy accept;
{lines(forward)}
 }}
 chain waydroid_dns {{ type nat hook prerouting priority -101; policy accept;
  iifname "waydroid0" meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 dnat ip to 1.1.1.1
 }}
 chain source {{ type nat hook postrouting priority srcnat; policy accept;
  meta nfproto ipv4 oifname "{tunnel.FULL_HOST}" snat ip to 172.29.247.1
{lines(nat)}
 }}
 chain output {{ type filter hook output priority -30; policy drop;
  oifname "lo" accept
  meta nfproto ipv4 meta mark {DIRECT} accept
  meta nfproto ipv4 meta mark {VPN} meta l4proto {{ tcp, udp }} th dport 53 oifname "{tunnel.FULL_HOST}" accept
  meta nfproto ipv4 meta skuid {uid} meta mark {VPN} oifname "{tunnel.FULL_HOST}" accept
  meta nfproto ipv4 oifname "{TUN}" accept
  ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept
 }}
 chain forward {{ type filter hook forward priority -30; policy drop;
  iifname "{tunnel.HOST}" ip saddr {tunnel.CLIENT} ip daddr {tunnel.SERVER} udp dport {tunnel.IKE_PORT} accept
  iifname "{tunnel.HOST}" ip saddr {tunnel.CLIENT} ip daddr {tunnel.SERVER} tcp dport 8443 accept
  oifname "{tunnel.HOST}" ip daddr {tunnel.CLIENT} ct state established,related accept
  iifname "waydroid0" meta nfproto ipv4 meta mark {DIRECT} accept
  oifname "waydroid0" meta nfproto ipv4 ct state established,related accept
  meta nfproto ipv4 oifname "{TUN}" accept
  meta nfproto ipv4 iifname "{TUN}" ct state established,related accept
  meta nfproto ipv4 oifname "{tunnel.FULL_HOST}" accept
  meta nfproto ipv4 iifname "{tunnel.FULL_HOST}" ct state established,related accept
 }}
}}'''

UNIT='''[Unit]
Description=Evgenium local application and domain routing
After=network.target
Wants=evgenium-waydroid-network.service
[Service]
User=vpn-xray
Group=vpn-xray
ExecStart=/opt/vpn-manager/bin/xray run -config /run/vpn-manager/policy.json
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
DeviceAllow=/dev/net/tun rw
UMask=0077
'''

WAYDROID_UNIT='''[Unit]
Description=Evgenium Waydroid network lifecycle
After=evgenium-policy.service
PartOf=evgenium-policy.service
[Service]
ExecStart=/usr/local/sbin/vpnctl internal-waydroid-watch
Restart=on-failure
RestartSec=2
UMask=0077
'''

def waydroid_network():
 result=tunnel.command(['ip','-j','-4','addr','show','dev','waydroid0'],check=False)
 if result.returncode:return {'index':None,'networks':[]}
 links=json.loads(result.stdout)
 networks=sorted({str(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}",strict=False)) for link in links if 'UP' in link.get('flags',[]) for a in link.get('addr_info',[]) if a.get('scope')=='global'})
 return {'index':links[0].get('ifindex') if links else None,'networks':networks}

def sync_waydroid_network(force=False):
 # Caller holds operation.lock. Only this VPN's set/table are modified.
 state=waydroid_network();cache=RUN/'waydroid-network.json'
 try:previous=json.loads(cache.read_text())
 except (OSError,ValueError):previous=None
 if not force and state==previous:return
 routes=json.loads(tunnel.command(['ip','-j','-4','route','show','table',PHYSICAL_TABLE]).stdout)
 stale={r['dst'] for r in routes if r.get('dev')=='waydroid0' and r.get('dst') not in state['networks']}
 for network in state['networks']:
  tunnel.command(['ip','route','replace',network,'dev','waydroid0','scope','link','table',PHYSICAL_TABLE])
 rules='flush set inet '+tunnel.FULL_GUARD+' waydroid_networks\n'
 if state['networks']:rules+='add element inet '+tunnel.FULL_GUARD+' waydroid_networks '+nft_set(state['networks'])+'\n'
 tunnel.command(['nft','-f','-'],data=rules)
 for network in stale:tunnel.command(['ip','route','del',network,'dev','waydroid0','table',PHYSICAL_TABLE],check=False)
 cache.write_text(json.dumps(state));cache.chmod(0o600)

def watch_waydroid():
 import sys
 last_error=None
 while True:
  try:
   RUN.mkdir(parents=True,exist_ok=True)
   with (RUN/'operation.lock').open('a+') as lock:
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:pass
    else:
     if tunnel.full_guard_active() and Path('/sys/class/net/'+TUN).exists():sync_waydroid_network()
   last_error=None
  except Exception as exc:
   message=str(exc)
   if message!=last_error:print('Waydroid network sync: '+message,file=sys.stderr,flush=True)
   last_error=message
  time.sleep(1)

def install():
 Path('/etc/systemd/system/'+SERVICE).write_text(UNIT)
 Path('/etc/systemd/system/'+WAYDROID_SERVICE).write_text(WAYDROID_UNIT)
 tunnel.command(['systemctl','daemon-reload'])

def apply():
 p=load();settings=api.load_settings();route=tunnel.physical_route();lan=local_networks(route)
 api.ensure_runtime(settings)
 cfg=RUN/'policy.json';tmp=RUN/'policy.new.json'
 tmp.write_text(json.dumps(config(p)));os.chmod(tmp,0o640);os.chown(tmp,0,int(settings['xray_gid']))
 check=tunnel.command([api.XRAY,'run','-test','-config',tmp],check=False)
 if check.returncode:raise RuntimeError('Обработчик исключений не принял настройки.')
 rules=firewall(p,lan,int(settings['xray_uid']))
 replacement=('delete table inet '+tunnel.FULL_GUARD+'\n' if tunnel.full_guard_active() else '')+rules
 tunnel.command(['nft','-c','-f','-'],data=replacement)
 ownership=PATH.with_name('policy-network.json')
 if not ownership.exists():
  for table in (PHYSICAL_TABLE,VPN_TABLE):
   if tunnel.command(['ip','route','show','table',table],check=False).stdout.strip():raise RuntimeError('Таблица маршрутизации исключений занята другой программой.')
  existing=json.loads(tunnel.command(['ip','-j','-4','rule']).stdout)
  if any(r.get('priority') in (76,77,78) for r in existing):raise RuntimeError('Приоритеты маршрутизации исключений заняты другой программой.')
  tunnel.write(ownership,json.dumps({'tables':[PHYSICAL_TABLE,VPN_TABLE]}))
 # Build physical and VPN-only tables before allowing any new marks.
 for table in (PHYSICAL_TABLE,VPN_TABLE):
  tunnel.command(['ip','route','replace','unreachable','default','metric','32760','table',table])
 for network in lan+['169.254.0.0/16','224.0.0.0/4']:
  tunnel.command(['ip','route','replace',network,'dev',route['dev'],'scope','link','table',PHYSICAL_TABLE])
 tunnel.command(['ip','route','replace','default','via',route['gateway'],'dev',route['dev'],'metric','10','table',PHYSICAL_TABLE])
 tunnel.command(['ip','route','replace','default','via','172.29.247.2','dev',tunnel.FULL_HOST,'metric','10','table',VPN_TABLE])
 for priority,mark,table in [(76,DIRECT,PHYSICAL_TABLE),(77,VPN,VPN_TABLE)]:
  tunnel.command(['ip','rule','del','priority',priority,'fwmark',str(mark),'lookup',table],check=False)
  tunnel.command(['ip','rule','add','priority',priority,'fwmark',str(mark),'lookup',table])
 # Replies to a forwarded container return through its connected main route.
 tunnel.command(['ip','rule','del','priority','78','iif',TUN,'lookup','main'],check=False)
 tunnel.command(['ip','rule','add','priority','78','iif',TUN,'lookup','main'])
 # A temporary closed state is acceptable; an unguarded state is not.
 os.replace(tmp,cfg)
 tunnel.write(tunnel.ROOT/'full-guard.nft',rules)
 tunnel.command(['nft','-f','-'],data=replacement)
 sync_waydroid_network(force=True)
 install()
 tunnel.command(['systemctl','restart',SERVICE])
 for _ in range(80):
  if Path('/sys/class/net/'+TUN).exists():break
  time.sleep(.1)
 else:raise RuntimeError('Не удалось запустить обработчик исключений.')
 tunnel.command(['ip','route','replace','default','dev',TUN,'metric','10','table',tunnel.FULL_TABLE])
 tunnel.clear_dns_mappings()
 # Explicitly requested DNS exceptions need stale port-53 mappings removed too.
 for proto in ('udp','tcp'):
  tunnel.command(['conntrack','-D','-f','ipv4','-p',proto,'--dport','53','--reply-port-src',str(DNS_PORT)],check=False)


def stop(release=False):
 tunnel.command(['systemctl','stop',SERVICE],check=False)
 if release and PATH.with_name('policy-network.json').exists():
  tunnel.command(['ip','rule','del','priority','78','iif',TUN,'lookup','main'],check=False)
  for priority,mark,table in [(76,DIRECT,PHYSICAL_TABLE),(77,VPN,VPN_TABLE)]:
   tunnel.command(['ip','rule','del','priority',priority,'fwmark',str(mark),'lookup',table],check=False)
   tunnel.command(['ip','route','flush','table',table],check=False)
  PATH.with_name('policy-network.json').unlink(missing_ok=True)


def change(action,category='',value='',state=None):
 old=load();p=json.loads(json.dumps(old))
 if action=='waydroid':p['waydroid_direct']=bool(state)
 elif action=='base':
  if category not in BASE or value not in {e['id'] for e in BASE[category]}:raise ValueError('Неизвестное базовое правило.')
  key=category+':'+value
  p['disabled_base']=[x for x in p['disabled_base'] if x!=key]
  if not state:p['disabled_base'].append(key)
 elif action in ('add','remove'):
  if category not in CATEGORIES:raise ValueError('Неизвестная категория.')
  value=normalize(category,value)
  if action=='add' and value not in p[category]:p[category].append(value)
  if action=='remove':p[category]=[x for x in p[category] if x!=value]
 else:raise ValueError('Неизвестное действие.')
 if p==old:return public()
 save(p)
 if tunnel.full_guard_active() and Path('/sys/class/net/'+tunnel.FULL_HOST).exists():
  try:apply()
  except Exception:
   save(old)
   try:apply()
   except Exception:pass
   raise
 return public()

def ensure_route():
 if Path('/sys/class/net/'+TUN).exists():
  tunnel.command(['ip','route','replace','default','dev',TUN,'metric','10','table',tunnel.FULL_TABLE])
 else:raise RuntimeError('policy_engine_unavailable')
