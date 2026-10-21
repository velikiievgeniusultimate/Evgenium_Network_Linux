"""Opt-in diagnostic reports: strict allowlist, no raw logs, identities or secrets."""
import json,math,platform,re,secrets,time,subprocess
from pathlib import Path
PHASES={'off','prepare','token','daemon','handshake','health','measure','routing','connected','checking','repairing','failed','ranking','reference','starting','interrupted','egress_wait'}
CODES={'','none','other','connection_failed','path_health_failed','confirmed_speed_drop','ranking_exhausted','system_dns_failed','private_dns_stopped','private_dns_not_ready','handshake_failed','estonia_egress_failed','host_egress_failed','enrollment_unavailable','integrity_failed','sa_not_installed','health_failed','command_failed','tls_carrier_stopped','tls_carrier_not_ready'}
PATHS={'ru-udp','ee-udp','ee-tls','ee-evgt',''}
XFRM={'XfrmInError','XfrmInNoStates','XfrmInStateProtoError','XfrmInStateSeqError','XfrmInStateExpired','XfrmInStateMismatch','XfrmInTmplMismatch','XfrmInNoPols','XfrmInPolBlock','XfrmOutError','XfrmOutNoStates','XfrmOutStateExpired','XfrmOutPolBlock'}
NUMBERS=XFRM|{'download_mbps','upload_mbps','latency_ms','score','losses','sample_bytes','rx_bytes','tx_bytes','rx_packets','tx_packets','rx_errors','tx_errors','rx_dropped','tx_dropped'}
def number(v):
 if type(v) not in (int,float) or not math.isfinite(v) or not 0<=v<=2**63:raise ValueError('metric')
 return round(v,3) if isinstance(v,float) else v

def clean_bundle(body):
 if not isinstance(body,dict) or body.get('schema')!=1 or body.get('event')!='support_bundle' or body.get('consent') is not True:raise ValueError('consent')
 if not re.fullmatch('[a-f0-9]{32}',str(body.get('report_id',''))):raise ValueError('report_id')
 version=body.get('manager','')
 if not isinstance(version,str) or not re.fullmatch(r'\d+\.\d+\.\d+',version):raise ValueError('version')
 if body.get('architecture') not in {'x86_64','aarch64','riscv64','other'}:raise ValueError('architecture')
 if body.get('system') not in {'arch','endeavouros','fedora','steamos','debian','ubuntu','other'}:raise ValueError('system')
 result={k:body[k] for k in ('schema','event','consent','report_id','manager','architecture','system')}
 result['time']=number(body.get('time',0))
 events=body.get('events',[])
 if not isinstance(events,list) or len(events)>128:raise ValueError('events')
 result['events']=[]
 for item in events:
  if not isinstance(item,dict) or item.get('phase') not in PHASES or item.get('code','') not in CODES or item.get('path','') not in PATHS:raise ValueError('event')
  result['events'].append({'time':number(item['time']),'phase':item['phase'],'code':item.get('code',''),'path':item.get('path',''),'active':item.get('active') is True})
 state=body.get('state',{})
 if not isinstance(state,dict):raise ValueError('state')
 result['state']={k:state.get(k) is True for k in ('active','guard','namespace','dns_fallback')}
 result['paths']={}
 paths=body.get('paths',{})
 if not isinstance(paths,dict) or len(paths)>len(PATHS)-1:raise ValueError('paths')
 for name,values in paths.items():
  if name not in PATHS-{''}:raise ValueError('path')
  if not isinstance(values,dict):raise ValueError('path')
  result['paths'][name]={k:number(v) for k,v in values.items() if k in NUMBERS}
 counters=body.get('counters',{})
 if not isinstance(counters,dict):raise ValueError('counters')
 result['counters']={k:number(v) for k,v in counters.items() if k in NUMBERS}
 return result

def record(root,write,data):
 event={'time':int(time.time()),'phase':data.get('phase') if data.get('phase') in PHASES else 'failed',
        'code':data.get('error_code','') if data.get('error_code','') in CODES else 'other',
        'path':data.get('path','') if data.get('path','') in PATHS else '', 'active':data.get('active') is True}
 path=root/'events.json'
 try:events=json.loads(path.read_text())
 except (OSError,ValueError):events=[]
 if not events or any(events[-1].get(k)!=event[k] for k in ('phase','code','path','active')):
  write(path,json.dumps((events+[event])[-128:]))

def prepare(tunnel,version):
 try:events=json.loads((tunnel.ROOT/'events.json').read_text())
 except (OSError,ValueError):events=[]
 try:paths=json.loads((tunnel.ROOT/'ranking.json').read_text())['entries']
 except (OSError,ValueError,KeyError):paths={}
 try:network=json.loads(tunnel.full_state().read_text())
 except (OSError,ValueError):network={}
 try:system=platform.freedesktop_os_release().get('ID','other')
 except OSError:system='other'
 if system not in {'arch','endeavouros','fedora','steamos','debian','ubuntu'}:system='other'
 arch=platform.machine();arch=arch if arch in {'x86_64','aarch64','riscv64'} else 'other'
 counters={}
 # Only the VPN's own interface, no process list or remote addresses.
 stats=Path('/sys/class/net')/tunnel.FULL_HOST/'statistics'
 for key in ('rx_bytes','tx_bytes','rx_packets','tx_packets','rx_errors','tx_errors','rx_dropped','tx_dropped'):
  try:counters[key]=int((stats/key).read_text())
  except (OSError,ValueError):pass
 if Path('/run/netns',tunnel.NS).exists():
  try:
   result=tunnel.inside(['cat','/proc/net/xfrm_stat'],check=False,timeout=2)
   for line in result.stdout.splitlines():
    key,value=line.split()
    if key in XFRM:counters[key]=int(value)
  except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):pass
 report=clean_bundle({'schema':1,'event':'support_bundle','consent':True,'report_id':secrets.token_hex(16),
   'manager':version,'time':int(time.time()),'architecture':arch,'system':system,'events':events,
   'paths':paths,'counters':counters,'state':{'active':tunnel.saved().get('active',False),
    'guard':tunnel.full_guard_active(),'namespace':Path('/run/netns',tunnel.NS).exists(),'dns_fallback':network.get('dns_fallback',False)}})
 # Preparing a preview is never permission to transmit it.
 report['consent']=False
 tunnel.write(tunnel.ROOT/'support-preview.json',json.dumps(report,ensure_ascii=False,indent=2))
 return report

def send(tunnel,report_id,consent):
 if consent is not True:raise ValueError('Для отправки требуется явное согласие.')
 report=json.loads((tunnel.ROOT/'support-preview.json').read_text())
 if report.get('report_id')!=report_id or time.time()-report.get('time',0)>86400:raise ValueError('Сначала подготовьте новый отчёт.')
 report['consent']=True;report=clean_bundle(report)
 # Never install a bypass around an active kill switch to upload a report.
 if Path('/run/netns',tunnel.NS).exists() and tunnel.installed():
  try:selected=json.loads((tunnel.ROOT/'active-path.json').read_text())['id']
  except (OSError,ValueError,KeyError):selected='ru-udp'
  candidate=next(x for x in tunnel.CANDIDATES if x['id']==selected)
  with tunnel.namespace():reply=tunnel.tls_request(tunnel.HEALTH,'/report',report,client=True,identity=candidate['identity'])
 elif not tunnel.full_guard_active():
  reply=tunnel.tls_request(tunnel.SERVER,'/report',report,client=True)
 else:raise RuntimeError('Защита блокирует сеть. Отчёт сохранён; отправьте после восстановления или явного отключения VPN.')
 if reply.get('accepted') is not True or reply.get('report_id')!=report_id:raise RuntimeError('Сервер не подтвердил получение отчёта.')
 return report_id
