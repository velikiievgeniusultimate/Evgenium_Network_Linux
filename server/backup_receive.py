#!/usr/bin/env python3
"""Forced SSH command: accepts only bounded encrypted backup envelopes."""
import json,os,sys,time
from pathlib import Path
os.umask(0o077)
data=sys.stdin.buffer.read(64*1024*1024+1)
if len(data)>64*1024*1024:raise SystemExit('backup too large')
envelope=json.loads(data)
if set(envelope)!={'schema','key','nonce','data'} or envelope['schema']!=1:raise SystemExit('invalid envelope')
root=Path('/root/evgenium-backups/ru-daily');root.mkdir(mode=0o700,parents=True,exist_ok=True)
name=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.evgbak';temp=root/(name+'.tmp')
with temp.open('wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
temp.replace(root/name)
for old in sorted(root.glob('*.evgbak'))[:-7]:old.unlink()
print('Encrypted backup accepted')
