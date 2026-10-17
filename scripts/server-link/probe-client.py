import os,sys,time,json,socket,ssl,struct,hashlib,subprocess,urllib.request,concurrent.futures,random,base64
LOG='/var/log/evgenium-link/probes.jsonl'
DATA=bytes(range(256))*1024
START=time.monotonic()
ctx=ssl.create_default_context()
def emit(kind,**kw):
 d=dict(utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),elapsed=round(time.monotonic()-START,2),kind=kind,**kw)
 with open(LOG,'a',buffering=1) as f:f.write(json.dumps(d,separators=(',',':'))+'\n')
def timed(kind,fn):
 t=time.monotonic()
 try:r=fn();emit(kind,ok=True,ms=round((time.monotonic()-t)*1000,2),result=r)
 except Exception as e:emit(kind,ok=False,ms=round((time.monotonic()-t)*1000,2),error=str(e)[:180])
def req(url):
 with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Evgenium-Link-Diagnostic/1.0'}),timeout=6) as r:
  b=r.read(32768); return {'status':r.status,'bytes':len(b)}
def ping():
 r=subprocess.run(['ping','-n','-c','1','-W','2','10.203.71.1'],stdout=subprocess.PIPE,text=True)
 if r.returncode:raise RuntimeError('no echo reply')
 import re
 return float(re.search(r'time=([\d.]+)',r.stdout)[1])
def receive(s,n):
 out=b''
 while len(out)<n:
  chunk=s.recv(n-len(out))
  if not chunk:raise RuntimeError('connection closed before complete response')
  out+=chunk
 return out
def dns(tcp=False):
 tx=os.urandom(2);q=tx+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x07discord\x03com\x00\x00\x01\x00\x01'
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
  s.settimeout(3);s.connect(('1.1.1.1',53))
  if tcp:s.sendall(struct.pack('!H',len(q))+q);n=struct.unpack('!H',receive(s,2))[0];b=receive(s,n)
  else:s.send(q);b=s.recv(4096)
 if b[:2]!=tx or b[3]&15:raise RuntimeError('invalid DNS response')
 return {'answers':struct.unpack('!H',b[6:8])[0]}
def udp():
 rtts=[];lost=0
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(.4);s.connect(('10.203.71.1',18081))
  for i in range(50):
   b=struct.pack('!I',i)+os.urandom(156);t=time.monotonic();s.send(b)
   try:
    if s.recv(1200)!=b:raise RuntimeError('payload mismatch')
    rtts.append((time.monotonic()-t)*1000)
   except socket.timeout:lost+=1
   time.sleep(max(0,.02-(time.monotonic()-t)))
 if not rtts:raise RuntimeError('all 50 UDP datagrams lost')
 rtts.sort();return {'sent':50,'lost':lost,'p50_ms':round(rtts[len(rtts)//2],2),'max_ms':round(max(rtts),2)}
def transfer():
 with urllib.request.urlopen('http://10.203.71.1:18080/blob',timeout=8) as r:b=r.read()
 if b!=DATA:raise RuntimeError('download integrity mismatch')
 with socket.create_connection(('10.203.71.1',18080),3) as s:
  s.settimeout(8);s.sendall(b'POST /upload HTTP/1.0\r\nHost: probe\r\nContent-Length: 262144\r\n\r\n')
  for i in range(0,len(DATA),4096):s.sendall(DATA[i:i+4096]);time.sleep(4096/125000)
  out=b''
  while True:
   b=s.recv(4096)
   if not b:break
   out+=b
  if hashlib.sha256(DATA).hexdigest().encode() not in out:raise RuntimeError('upload integrity mismatch')
 return {'each_direction_bytes':len(DATA),'rate_cap_bps':1000000}
def ws():
 with socket.create_connection(('gateway.discord.gg',443),5) as raw:
  with ctx.wrap_socket(raw,server_hostname='gateway.discord.gg') as s:
   s.settimeout(5);key=base64.b64encode(os.urandom(16)).decode()
   s.sendall(('GET /?v=10&encoding=json HTTP/1.1\r\nHost: gateway.discord.gg\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: '+key+'\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
   b=b''
   while b'\r\n\r\n' not in b:
    chunk=s.recv(4096)
    if not chunk:raise RuntimeError('websocket closed before upgrade')
    b+=chunk
    if len(b)>16384:raise RuntimeError('oversized websocket headers')
   head,tail=b.split(b'\r\n\r\n',1)
   if not head.startswith(b'HTTP/1.1 101'):raise RuntimeError(head.split(b'\r\n')[0].decode())
   expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
   if expected.lower() not in head.lower():raise RuntimeError('invalid websocket accept')
   if len(tail)<2:tail+=receive(s,2-len(tail))
   n=tail[1]&127;o=2
   if n==126:
    if len(tail)<4:tail+=receive(s,4-len(tail))
    n=struct.unpack('!H',tail[2:4])[0];o=4
   if len(tail)<o+n:tail+=receive(s,o+n-len(tail))
   msg=json.loads(tail[o:o+n]);
   if msg.get('op')!=10:raise RuntimeError('expected HELLO')
   return {'upgrade':101,'hello':True,'heartbeat_interval':msg.get('d',{}).get('heartbeat_interval')}
def egress():
 with urllib.request.urlopen('https://www.cloudflare.com/cdn-cgi/trace',timeout=6) as r:b=r.read(8192).decode()
 if 'ip=38.180.164.67\n' not in b:raise RuntimeError('unexpected egress')
 return {'expected_estonia_ip':True}
URLS={'discord_api':'https://discord.com/api/v10/gateway','discord_cdn':'https://cdn.discordapp.com/embed/avatars/0.png','youtube':'https://www.youtube.com/robots.txt','github':'https://github.com/robots.txt','telegram':'https://telegram.org/','cloudflare':'https://www.cloudflare.com/cdn-cgi/trace'}
def main():
 DURATION=int(sys.argv[1]) if len(sys.argv)>1 else 3600
 emit('start',duration=DURATION)
 i=0
 while time.monotonic()-START<DURATION:
  t=time.monotonic();timed('inner_ping',ping)
  if i%2==0:timed('udp_echo',udp)
  if i%4==0:
   timed('dns_udp',dns);timed('dns_tcp',lambda:dns(True));timed('egress',egress)
   with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
    list(ex.map(lambda kv:timed(kv[0],lambda:req(kv[1])),URLS.items()))
  if i%20==0:timed('discord_ws',ws);timed('transfer',transfer)
  i+=1;time.sleep(max(0,15-(time.monotonic()-t)))
 emit('complete')

if __name__=='__main__':main()
