import importlib.util,pathlib,concurrent.futures
spec=importlib.util.spec_from_file_location('probes','/opt/evgenium-link/probe-client.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
p.LOG='/var/log/evgenium-link/services.jsonl'
log=pathlib.Path(p.LOG)
if log.exists() and log.stat().st_size>1024*1024:
 for i in range(2,0,-1):
  old=pathlib.Path(str(log)+'.'+str(i));new=pathlib.Path(str(log)+'.'+str(i+1))
  if old.exists():old.replace(new)
 log.replace(str(log)+'.1')
p.timed('inner_ping',p.ping)
p.timed('dns_udp',p.dns);p.timed('dns_tcp',lambda:p.dns(True));p.timed('egress',p.egress)
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
 list(ex.map(lambda kv:p.timed(kv[0],lambda:p.req(kv[1])),p.URLS.items()))
p.timed('discord_ws',p.ws)
