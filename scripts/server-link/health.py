#!/usr/bin/python3
import json,subprocess,time,pathlib,sys,random
node=sys.argv[1];base=pathlib.Path('/var/lib/evgenium-link');log=pathlib.Path('/var/log/evgenium-link/health.jsonl');statefile=base/'health-state.json'
try:state=json.loads(statefile.read_text())
except (OSError,ValueError):state={}
now=time.time();prefix=['ip','netns','exec','evg-link'] if node=='star' else []
def cmd(args,timeout=8):
 try:return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
 except subprocess.TimeoutExpired:return None
if (base/'maintenance').exists() or (base/'resource-hold').exists():sys.exit(0)
link=cmd(['ip','-n','evg-link','-j','link','show','evg-wg'] if node=='star' else ['ip','-j','link','show','evg-wg'])
local_ok=link is not None and link.returncode==0 and '"UP"' in link.stdout
peer='10.203.71.1' if node=='star' else '10.203.71.2'
ping=cmd(prefix+['ping','-n','-c','1','-W','2',peer]);inner=ping is not None and ping.returncode==0
mode=(base/'mode').read_text().strip() if (base/'mode').exists() else 'direct'
endpoints=cmd(prefix+['/opt/evgenium-link/package/usr/bin/wg','show','evg-wg','endpoints'])
actual_endpoint=endpoints.stdout.split()[-1] if endpoints is not None and endpoints.returncode==0 and endpoints.stdout.split() else None
d={'mode':mode,'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now)),'monotonic':round(time.monotonic(),2),'local_ok':local_ok,'inner_ok':inner}
if node=='star':
 expected_endpoint={'direct':'38.180.164.67:24447','hy':'127.0.0.1:24445','tcp':'127.0.0.1:24449'}.get(mode)
 d['actual_endpoint']=actual_endpoint;d['endpoint_matches_mode']=actual_endpoint==expected_endpoint
wg=cmd(prefix+['/opt/evgenium-link/package/usr/bin/wg','show','evg-wg','latest-handshakes'])
if wg is not None and wg.returncode==0:
 timestamps=[int(l.split()[-1]) for l in wg.stdout.splitlines() if l.split()]
 last=max(timestamps,default=0);d['handshake_age_s']=round(now-last) if last else None
if not inner:
 physical=cmd(['ip','-j','link','show','eth0'])
 try:d['physical_link_up']='LOWER_UP' in json.loads(physical.stdout)[0]['flags']
 except Exception:d['physical_link_up']=None
 if node=='star':
  route=cmd(['ip','-j','route','get','38.180.164.67']);d['underlay_route_ok']=route is not None and route.returncode==0
  for name,addr in [('gateway','192.168.0.1'),('peer_underlay','38.180.164.67')]:
   r=cmd(['ping','-n','-c','1','-W','1',addr]);d[name+'_echo_ok']=r is not None and r.returncode==0
 for unit in ['evgenium-link-hy','evgenium-link-tcp']:
  r=cmd(['systemctl','is-active',unit]);d[unit]=r.stdout.strip() if r is not None else 'unknown'

# External service failures never trigger link restarts.
if node=='star' and inner and now-state.get('last_egress',0)>=60:
 r=cmd(prefix+['curl','-4','-sS','--connect-timeout','3','--max-time','6','https://www.cloudflare.com/cdn-cgi/trace'])
 d['egress_ok']=r is not None and r.returncode==0 and '\nip=38.180.164.67\n' in '\n'+r.stdout
 state['last_egress']=now;state['last_egress_ok']=d['egress_ok']
 if not d['egress_ok']:
  d['egress_curl_exit']=r.returncode if r is not None else 'timeout'
  d['egress_error']=r.stderr[:160] if r is not None else 'probe deadline exceeded'
  r2=cmd(prefix+['curl','-4','-sS','--connect-timeout','3','--max-time','6','https://api.ipify.org'])
  d['independent_egress_ok']=r2 is not None and r2.returncode==0 and r2.stdout.strip()=='38.180.164.67'
if node=='star':
 d['last_egress_ok']=state.get('last_egress_ok');d['egress_age_s']=round(now-state['last_egress']) if state.get('last_egress') else None
state['failures']=0 if inner and d.get('endpoint_matches_mode',True) else state.get('failures',0)+1
attempts=[t for t in state.get('attempts',[]) if now-t<3600]
# Only the initiating StarFive changes transport. Estonia repairs missing local objects.
needs_repair=not local_ok
needs_switch=node=='star' and local_ok and state['failures']>=3 and d.get('physical_link_up') is not False and d.get('underlay_route_ok') is not False
needs_endpoint_repair=node=='star' and local_ok and inner and not d.get('endpoint_matches_mode',True) and state['failures']>=3
if (needs_repair or needs_switch or needs_endpoint_repair) and now>=state.get('retry_after',0):
 if len(attempts)<5:
  if needs_repair:
   r=cmd(['systemctl','restart','evgenium-link'],timeout=40)
   d['action']='restart_own_link';d['action_ok']=r is not None and r.returncode==0
  elif needs_endpoint_repair:
   r=cmd(['/usr/bin/python3','/opt/evgenium-link/transport.py',mode],timeout=20)
   d['action']='restore_selected_endpoint';d['action_ok']=r is not None and r.returncode==0
  else:
   preferred=(base/'preferred-mode').read_text().strip() if (base/'preferred-mode').exists() else 'hy'
   target=preferred if mode=='tcp' else 'tcp'
   if target!='direct':cmd(['systemctl','start','evgenium-link-'+('hy' if target=='hy' else 'tcp')],timeout=15)
   r=cmd(['/usr/bin/python3','/opt/evgenium-link/transport.py',target],timeout=20)
   success=r is not None and r.returncode==0
   d['action']='switch_own_transport';d['target']=target;d['action_ok']=success
  attempts.append(now);state['retry_after']=now+min(1800,60*2**min(len(attempts)-1,5))+random.uniform(0,10)
  if needs_switch:state['retry_after']=max(state['retry_after'],now+300)
  state['failures']=0
 else:d['action']='recovery_budget_exhausted'
state['attempts']=attempts
# At most once per day, record certificate renewal urgency without exporting keys.
if now-state.get('cert_check',0)>86400:
 r=cmd(['openssl','x509','-in','/etc/evgenium-link/hy-tls.crt','-noout','-checkend','2592000'])
 d['tls_valid_over_30_days']=r is not None and r.returncode==0
 state['cert_check']=now
statefile.write_text(json.dumps(state));statefile.chmod(0o600)
if log.exists() and log.stat().st_size>1024*1024:
 for i in range(2,0,-1):
  old=pathlib.Path(str(log)+'.'+str(i));new=pathlib.Path(str(log)+'.'+str(i+1))
  if old.exists():old.replace(new)
 log.replace(str(log)+'.1')
with log.open('a') as f:f.write(json.dumps(d,separators=(',',':'))+'\n')
