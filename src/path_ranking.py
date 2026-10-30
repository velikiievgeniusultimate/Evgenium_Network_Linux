"""Persistent candidate order. Losses survive successes/restarts until explicit repair."""
import json,math,os,time
from pathlib import Path
class Ranking:
 def __init__(self,path,ids):self.path=Path(path);self.ids=tuple(ids);self.data=None
 def load(self):
  try:
   value=json.loads(self.path.read_text())
   if not isinstance(value,dict):return False
   if value.get('schema')!=1 or set(value.get('entries',{}))!=set(self.ids):return False
   if sorted(value.get('order',[]))!=sorted(self.ids):return False
   for e in value['entries'].values():
    if not isinstance(e,dict):return False
    for key in ('score','download_mbps','upload_mbps','latency_ms'):
     v=e.get(key,0)
     if type(v) not in (int,float) or not math.isfinite(v) or v<0:return False
    if type(e.get('losses')) is not int or not 0<=e['losses']<=3:return False
   self.data=value;return True
  except (OSError,ValueError,TypeError,AttributeError):return False
 def save(self):
  self.path.parent.mkdir(parents=True,exist_ok=True)
  tmp=self.path.with_suffix('.new');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as f:json.dump(self.data,f,separators=(',',':'))
  os.replace(tmp,self.path)
 def build(self,measurements):
  entries={}
  for identity in self.ids:
   m=measurements[identity];ok=m.get('ok',False)
   down=max(0,float(m.get('download_mbps',0)));up=max(0,float(m.get('upload_mbps',0)))
   score=(2*down*up/(down+up) if down+up else 1)/(1+max(0,float(m.get('latency_ms',0)))/200) if ok else 0
   entries[identity]={**m,'score':round(score,3),'losses':0 if ok else 1}
  self.data={'schema':1,'created':int(time.time()),'entries':entries,
             'order':sorted(self.ids,key=lambda x:entries[x]['score'],reverse=True)}
  self.save()
 def candidates(self):return [x for x in self.data['order'] if self.data['entries'][x]['losses']<3]
 def bootstrap(self):
  # No synthetic speed/health result: try the RU ingress first, then fallbacks.
  order=sorted(self.ids,key=lambda identity:identity!='ru-udp')
  self.data={'schema':1,'created':int(time.time()),'entries':{identity:{'score':0,'losses':0} for identity in self.ids},'order':order}
  self.save()
 def lose(self,identity,reason):
  e=self.data['entries'][identity];e['losses']=min(3,e['losses']+1);e['last_failure']=int(time.time());e['reason']=reason
  self.save()
 def next_after(self,identity):
  order=self.data['order'];rest=order[order.index(identity)+1:]
  return next((x for x in rest if self.data['entries'][x]['losses']<3),None)
