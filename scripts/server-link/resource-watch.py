import pathlib,time,json,subprocess,sys
node=sys.argv[1];duration=int(sys.argv[2]) if len(sys.argv)>2 else 4800;log=pathlib.Path('/var/log/evgenium-link/resources.jsonl')
def snap():
 cpu={}
 for l in pathlib.Path('/proc/stat').read_text().splitlines():
  if l.startswith('cpu'):p=l.split();cpu[p[0]]=list(map(int,p[1:9]))
 mem={l.split(':')[0]:int(l.split()[1]) for l in pathlib.Path('/proc/meminfo').read_text().splitlines()}
 net={}
 for l in pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]:
  name,v=l.split(':');v=list(map(int,v.split()));net[name.strip()]={'rx':v[0],'tx':v[8],'rxdrop':v[3],'txdrop':v[11]}
 return cpu,mem,net
prev,_,_=snap();high=0;start=time.monotonic()
while duration==0 or time.monotonic()-start<duration:
 time.sleep(10);cpu,mem,net=snap();usage={}
 for k,v in cpu.items():
  d=[x-y for x,y in zip(v,prev[k])];total=sum(d);usage[k]={'busy':round(100*(total-d[3]-d[4]-d[7])/max(1,total),2),'steal':round(100*d[7]/max(1,total),2),'iowait':round(100*d[4]/max(1,total),2),'softirq':round(100*d[6]/max(1,total),2)}
 prev=cpu
 protected={}
 for name in (['x-ui'] if node=='est' else ['strongswan']):
  r=subprocess.run(['systemctl','show',name,'-p','MainPID','-p','MemoryCurrent','-p','ActiveEnterTimestamp'],capture_output=True,text=True);protected[name]=r.stdout.strip()
 d={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'cpu':usage,'available_mib':round(mem['MemAvailable']/1024),'net':net,'protected':protected}
 if log.exists() and log.stat().st_size>2*1024*1024:
  for i in range(2,0,-1):
   old=pathlib.Path(str(log)+'.'+str(i));new=pathlib.Path(str(log)+'.'+str(i+1))
   if old.exists():old.replace(new)
  log.replace(str(log)+'.1')
 with log.open('a') as f:f.write(json.dumps(d,separators=(',',':'))+'\n')
 bad=usage['cpu']['busy']>50 or mem['MemAvailable']<(1024 if node=='est' else 2048)*1024
 high=high+1 if bad else 0
 if high>=3:
  with log.open('a') as f:f.write(json.dumps({'event':'resource_guard_stop','utc':d['utc']})+'\n')
  pathlib.Path('/var/lib/evgenium-link/resource-hold').touch()
  subprocess.run(['systemctl','stop','evgenium-link-health.timer'])
  subprocess.run(['systemctl','stop','evgenium-link','evgenium-link-hy','evgenium-link-tcp']);break
