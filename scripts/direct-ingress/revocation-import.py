#!/usr/bin/env python3
"""Restricted SSH command. Accept only a CA-verified CRL and disabled identities."""
import json,os,re,subprocess,sys,time
from pathlib import Path
os.umask(0o077)
root=Path('/etc/evgenium-direct')
raw=sys.stdin.buffer.read(2*1024*1024+1)
if len(raw)>2*1024*1024:sys.exit(2)
data=json.loads(raw)
if set(data)!={'issued','crl','disabled'}:sys.exit(2)
if type(data['issued']) is not int or abs(time.time()-data['issued'])>60:sys.exit(2)
if not isinstance(data['disabled'],list) or len(data['disabled'])>10000:sys.exit(2)
if any(not isinstance(x,str) or not re.fullmatch('device-[a-f0-9]{24}',x) for x in data['disabled']):sys.exit(2)
if not isinstance(data['crl'],str) or len(data['crl'])>1500000:sys.exit(2)
previous=root/'revocations.json'
if previous.exists() and json.loads(previous.read_text())['issued']>data['issued']:sys.exit(2)
tmp=root/'devices.new'
tmp.write_text(data['crl'])
r=subprocess.run(['openssl','crl','-in',str(tmp),'-CAfile',str(root/'ca.pem'),'-verify','-noout'],capture_output=True,timeout=5)
if r.returncode:tmp.unlink();sys.exit(2)
os.replace(tmp,root/'devices.pem')
tmp=root/'revocations.new';tmp.write_text(json.dumps({'issued':data['issued'],'disabled':data['disabled']}));os.replace(tmp,previous)
print('accepted')
