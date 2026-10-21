#!/usr/bin/env python3
"""Aggregate consented reports without printing device identifiers or raw records."""
import argparse,collections,json,time
from pathlib import Path

def summary(root,days=7):
 result={'reports':0,'devices':0,'versions':collections.Counter(),'failures':collections.Counter(),'paths':{}}
 devices=set();seen=set();cutoff=time.time()-days*86400
 for path in sorted(Path(root).glob('*.jsonl')):
  if path.stat().st_mtime<cutoff:continue
  with path.open() as stream:
   for line in stream:
    try:r=json.loads(line)
    except ValueError:continue
    if r.get('event')!='support_bundle' or r.get('consent') is not True or r.get('received',0)<cutoff:continue
    key=(r.get('device'),r.get('report_id'))
    if key in seen:continue
    seen.add(key);devices.add(r.get('device'));result['reports']+=1;result['versions'][r['manager']]+=1
    for event in r.get('events',[]):
     if event.get('code'):result['failures'][event['code']]+=1
    for name,values in r.get('paths',{}).items():
     dest=result['paths'].setdefault(name,{'samples':0,'download_mbps':[],'upload_mbps':[]})
     dest['samples']+=1
     for k in ('download_mbps','upload_mbps'):
      if k in values:dest[k].append(values[k])
 result['devices']=len(devices)
 for values in result['paths'].values():
  for k in ('download_mbps','upload_mbps'):
   data=sorted(values[k]);values[k]={'median':data[len(data)//2] if data else None,'samples':len(data)}
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--directory',default='/var/log/evgenium-experimental');p.add_argument('--days',type=int,choices=range(1,8),default=7);a=p.parse_args()
 print(json.dumps(summary(a.directory,a.days),ensure_ascii=False,indent=2))
