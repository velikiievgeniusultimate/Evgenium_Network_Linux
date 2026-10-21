#!/usr/bin/env python3
"""Push only public CRL and disabled identities through a pinned restricted SSH key."""
import json,subprocess,sys,time
from pathlib import Path
ROOT=Path('/etc/evgenium-direct-sync')
def sync():
 data=json.loads(Path('/var/lib/evgenium-enrollment/accounts.json').read_text())
 disabled=sorted({d['identity'] for a in data.values() for d in a.get('devices',{}).values()
                  if not a.get('enabled') or d.get('disabled')})
 body={'issued':int(time.time()),'disabled':disabled,'crl':Path('/etc/swanctl/x509crl/devices.pem').read_text()}
 cmd=['ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','IdentitiesOnly=yes',
      '-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=4','-o','ServerAliveInterval=3',
      '-o','ServerAliveCountMax=2','-o','UserKnownHostsFile='+str(ROOT/'known_hosts'),
      '-i',str(ROOT/'id_ed25519'),'root@38.180.164.67']
 r=subprocess.run(cmd,input=json.dumps(body),text=True,capture_output=True,timeout=18)
 if r.returncode or r.stdout.strip()!='accepted':raise RuntimeError('revocation_sync_failed')
if '--once' in sys.argv:sync()
else:
 bad=False
 while True:
  try:
   sync()
   if bad:print('revocation_sync_recovered',flush=True)
   bad=False
  except Exception:
   if not bad:print('revocation_sync_unavailable',flush=True)
   bad=True
  time.sleep(10)
