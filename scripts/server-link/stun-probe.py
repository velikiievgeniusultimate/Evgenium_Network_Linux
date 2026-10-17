import socket,struct,os,json,time
for i in range(3):
 tx=os.urandom(12);q=struct.pack('!HHI',1,0,0x2112A442)+tx;t=time.monotonic()
 try:
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
   s.settimeout(3);s.sendto(q,('stun.cloudflare.com',3478));b,_=s.recvfrom(2048)
  assert b[:2]==b'\x01\x01' and b[8:20]==tx
  off=20;mapping=None
  while off+4<=len(b):
   typ,n=struct.unpack('!HH',b[off:off+4]);v=b[off+4:off+4+n];off+=4+((n+3)//4)*4
   if typ==0x20 and v[1]==1:mapping=socket.inet_ntoa(bytes(x^y for x,y in zip(v[4:8],bytes.fromhex('2112a442'))))
  print(json.dumps({'ok':True,'ms':round((time.monotonic()-t)*1000,2),'egress':mapping,'expected':mapping=='38.180.164.67'}),flush=True)
 except Exception as e: print(json.dumps({'ok':False,'error':str(e)}),flush=True)
 time.sleep(1)
