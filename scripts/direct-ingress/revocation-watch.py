#!/usr/bin/env python3
"""Close only the direct ingress if revocation snapshots go stale (24 hours)."""
import hashlib,json,re,subprocess,time
from pathlib import Path
ROOT=Path('/etc/evgenium-direct');last=None;opened=False;delayed=False

def call(args,data=None):
 return subprocess.run(args,input=data,text=True,capture_output=True,timeout=15)
def swan(*args):return call(['ip','netns','exec','evg-direct','swanctl',*args,'--uri','unix:///run/evgenium-direct/charon.vici'])
while True:
 try:
  state=json.loads((ROOT/'revocations.json').read_text())
  age=time.time()-state['issued']
  fresh=0<=age<86400
  if (age>60)!=delayed:
   delayed=age>60;print('revocation_delivery_delayed' if delayed else 'revocation_delivery_recovered',flush=True)
  digest=hashlib.sha256((ROOT/'devices.pem').read_bytes()).hexdigest()
  if fresh and digest!=last:
   result=swan('--load-creds','--noprompt','--file',str(ROOT/'connection.conf'))
   if result.returncode or 'failed' in (result.stdout+result.stderr).lower():raise RuntimeError('crl_load_failed')
   for unit in ['evgenium-direct-tls','evgenium-direct-health']:
    if call(['systemctl','try-restart',unit]).returncode:raise RuntimeError('crl_reload_failed')
   last=digest
  disabled=set(state['disabled'])
  if disabled or not fresh:
   listing=swan('--list-sas','--raw')
   if listing.returncode:raise RuntimeError('sessions_unavailable')
   for part in listing.stdout.split('list-sa event ')[1:]:
    header=part.split('child-sas',1)[0]
    remote=re.search(r'(?<![\w-])remote-id=([^\s{}]+)',header)
    number=re.search(r'(?<![\w-])uniqueid=(\d+)(?=[\s}])',header)
    if number and (not fresh or remote and remote[1] in disabled):swan('--terminate','--ike-id',number[1])
  if fresh!=opened:
   rules='flush set inet evg_direct permit\n'+('add element inet evg_direct permit { 10.203.93.2 }\n' if fresh else '')
   if call(['nft','-f','-'],rules).returncode:raise RuntimeError('gate_failed')
   opened=fresh;print('direct_ingress_ready' if fresh else 'direct_ingress_revocation_stale',flush=True)
 except Exception as e:
  call(['nft','flush','set','inet','evg_direct','permit']);opened=False
  print(type(e).__name__,flush=True)
 time.sleep(2)
