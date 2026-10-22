#!/usr/bin/env python3
"""Consistent project snapshot. Server has only the RSA encryption public key.
Restore is deliberately offline: never roll CA/revocations back over a live server.
Requires python3-cryptography. JSON envelope: RSA-OAEP-SHA256 + AES-256-GCM.
"""
import argparse,base64,fcntl,io,json,os,sqlite3,tarfile,tempfile,time
from pathlib import Path
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
AAD=b'evgenium-backup-v1'
def encrypt(raw, public):
 key=os.urandom(32);nonce=os.urandom(12)
 wrapped=serialization.load_pem_public_key(public).encrypt(key,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=AAD))
 return json.dumps({'schema':1,'key':base64.b64encode(wrapped).decode(),'nonce':base64.b64encode(nonce).decode(),'data':base64.b64encode(AESGCM(key).encrypt(nonce,raw,AAD)).decode()},separators=(',',':')).encode()
def decrypt(raw,private):
 envelope=json.loads(raw);assert envelope['schema']==1
 key=serialization.load_pem_private_key(private,password=None).decrypt(base64.b64decode(envelope['key']),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=AAD))
 return AESGCM(key).decrypt(base64.b64decode(envelope['nonce']),base64.b64decode(envelope['data']),AAD)
def snapshot():
 with open('/var/lib/evgenium-enrollment/accounts.lock','a') as a,open('/root/evgenium-ikev2-pki/ca.lock','a') as c:
  fcntl.flock(a,fcntl.LOCK_EX);fcntl.flock(c,fcntl.LOCK_EX)
  with tempfile.TemporaryDirectory(prefix='evgenium-backup-') as folder:
   db=Path(folder)/'panel.sqlite3';source=sqlite3.connect('file:/var/lib/evgenium-panel/panel.sqlite3?mode=ro',uri=True);dest=sqlite3.connect(db)
   source.backup(dest);assert dest.execute('PRAGMA integrity_check').fetchone()==('ok',);dest.close();source.close()
   result=io.BytesIO()
   with tarfile.open(fileobj=result,mode='w:gz') as t:
    paths=['/root/evgenium-ikev2-pki','/etc/swanctl','/etc/strongswan.d','/etc/evgenium-panel','/etc/evgenium-panel-tunnel','/var/lib/evgenium-enrollment','/var/lib/evgenium-panel-broker','/etc/nftables.conf','/etc/nftables.d','/etc/evgenium-link','/etc/sysctl.d/70-evgenium-vpn.conf','/var/lib/evgenium-link','/opt/evgenium-panel','/opt/evgenium-link']
    paths += [str(p) for root in ['/etc/systemd/system','/usr/local/sbin'] for p in Path(root).glob('evgenium-*')]
    for name in paths:
     p=Path(name)
     if p.exists():t.add(p,arcname=str(p).lstrip('/'))
    t.add(db,arcname='var/lib/evgenium-panel/panel.sqlite3')
   return result.getvalue()
def main():
 p=argparse.ArgumentParser();p.add_argument('--public-key',default='/etc/evgenium-backup/public.pem');p.add_argument('--output',default='/var/backups/evgenium');a=p.parse_args();os.umask(0o077)
 folder=Path(a.output);folder.mkdir(mode=0o700,parents=True,exist_ok=True)
 with (folder/'backup.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  data=encrypt(snapshot(),Path(a.public_key).read_bytes());name=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.evgbak';temp=folder/(name+'.tmp')
  with temp.open('wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
  temp.replace(folder/name)
  for old in sorted(folder.glob('*.evgbak'))[:-7]:old.unlink()
  print(json.dumps({'ok':True,'file':name,'encrypted_bytes':len(data)}))
if __name__=='__main__':main()
