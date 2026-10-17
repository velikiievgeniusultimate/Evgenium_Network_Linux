from pathlib import Path
import json,collections,time,os,subprocess
base=Path('/var/log/evgenium-link')
def read_rows(name):
 for suffix in ['.3','.2','.1','']:
  p=base/(name+suffix)
  if p.exists():
   for line in p.read_text().splitlines():
    try:yield json.loads(line)
    except ValueError:continue
p=base/'probes.jsonl';out={}

if p.exists():
 rows=[json.loads(l) for l in p.read_text().splitlines() if l.startswith('{')];out['last']=rows[-1] if rows else None
 out['elapsed_s']=max((r.get('elapsed',0) for r in rows),default=0);g=collections.defaultdict(list)
 for r in rows:
  if 'ok' in r:g[r['kind']].append(r)
 out['checks']={k:{'n':len(v),'failed':sum(not r['ok'] for r in v)} for k,v in g.items()}
 pings=sorted(r['result'] for r in g['inner_ping'] if r['ok']);out['ping_ms']={str(q):round(pings[min(len(pings)-1,int(q*len(pings)))],2) for q in [.5,.95,.99]} if pings else {}
 out['failures']=[r for r in rows if r.get('ok') is False][-8:]
 out['udp_lost']=sum(r['result']['lost'] for r in g['udp_echo'] if r['ok']);out['udp_sent']=sum(r['result']['sent'] for r in g['udp_echo'] if r['ok'])
p=Path('/var/log/evgenium-link/resources.jsonl')
if p.exists():
 rows=list(read_rows('resources.jsonl'));rs=[r for r in rows if 'cpu' in r];out['resources']={'samples':len(rs),'max_busy':max((r['cpu']['cpu']['busy'] for r in rs),default=None),'min_available_mib':min((r['available_mib'] for r in rs),default=None),'last':rs[-1] if rs else None,'guards':[r for r in rows if 'event' in r]}
for name in ['voice-baseline.json','voice-loss.json']:
 p=Path('/var/log/evgenium-link')/name
 if p.exists() and p.stat().st_size:
  try:out[name]=json.loads(p.read_text())
  except:pass
health=list(read_rows('health.jsonl'))
if health:
 out['health']={'first':health[0]['utc'],'last':health[-1],'samples':len(health),'endpoint_mismatches':[r for r in health if r.get('endpoint_matches_mode') is False][-20:],'inner_failed':sum(r.get('inner_ok') is False for r in health),'egress_failed':sum(r.get('egress_ok') is False for r in health),'actions':[r for r in health if 'action' in r][-30:]}
services=list(read_rows('services.jsonl'))
if services:
 groups=collections.defaultdict(list)
 for r in services:groups[r['kind']].append(r)
 out['services']={'first':services[0]['utc'],'last':services[-1]['utc'],'checks':{k:{'n':len(v),'failed':sum(r.get('ok') is False for r in v)} for k,v in groups.items()},'failures':[r for r in services if r.get('ok') is False][-20:]}
print(json.dumps(out,separators=(',',':')))
