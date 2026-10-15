#!/usr/bin/env python3
"""Temporary test-only TCP transfer endpoint, reachable solely from one IPsec VIP."""
import hashlib,ipaddress,json,os,signal,socket,subprocess,sys,time,uuid
client=str(ipaddress.IPv4Address(sys.argv[1]));assert ipaddress.ip_address(client) in ipaddress.ip_network('10.77.0.0/24')
comment='evn-bench-'+uuid.uuid4().hex;handle=None;stop=False

def terminate(*_):
 global stop
 stop=True
signal.signal(signal.SIGTERM,terminate);signal.signal(signal.SIGINT,terminate)

def nft(*args):return subprocess.check_output(['nft',*args],text=True)
try:
 nft('insert','rule','inet','firewall','input','ip','saddr',client,'ip','daddr','10.77.0.1','tcp','dport','5201','ipsec','in','reqid','>','0','accept','comment',comment)
 rules=json.loads(nft('-j','-a','list','chain','inet','firewall','input'))['nftables']
 handle=next(x['rule']['handle']for x in rules if x.get('rule',{}).get('comment')==comment)
 block=hashlib.shake_256(b'evgenium-raw-transfer-v1').digest(65536)
 with socket.socket()as listener:
  listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('10.77.0.1',5201));listener.listen(2);listener.settimeout(1)
  deadline=time.monotonic()+180
  while not stop and time.monotonic()<deadline:
   try:connection,peer=listener.accept()
   except TimeoutError:continue
   with connection:
    if peer[0]!=client:continue
    connection.settimeout(12)
    try:
     stream=connection.makefile('rb');request=json.loads(stream.readline(256));size=request['size'];limit=request.get('limit_mbps',100)
     if type(size)is not int or not 1<=size<=32*1024*1024 or type(limit)is not int or not 1<=limit<=150:continue
     start=time.monotonic();count=0;digest=hashlib.sha256()
     if request['op']=='download':
      connection.sendall(b'OK\n')
      while count<size and not stop:
       chunk=block[:min(len(block),size-count)];connection.sendall(chunk);count+=len(chunk)
       time.sleep(max(0,start+count*8/(limit*1e6)-time.monotonic()))
     elif request['op']=='upload':
      connection.sendall(b'OK\n')
      while count<size:
       chunk=stream.read(min(65536,size-count))
       if not chunk:break
       count+=len(chunk);digest.update(chunk)
      connection.sendall(json.dumps({'bytes':count,'sha256':digest.hexdigest()}).encode()+b'\n')
    except (OSError,ValueError,KeyError):pass
finally:
 if handle is not None:nft('delete','rule','inet','firewall','input','handle',str(handle))
