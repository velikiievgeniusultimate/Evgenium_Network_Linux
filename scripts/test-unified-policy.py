#!/usr/bin/env python3
"""Real kernel/TUN checks in disposable namespaces; no host routes or services changed."""
import importlib.util,json,os,pwd,socket,subprocess,sys,tempfile,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def run(args,**kw):return subprocess.run([str(x) for x in args],check=True,text=True,capture_output=True,**kw)

def child(directory):
 spec=importlib.util.spec_from_file_location('manager',ROOT/'src/vpnctl.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 p=m.policy;t=m.starfive_tunnel;d=Path(directory);account=pwd.getpwnam('vpn-xray')
 p.PATH=d/'policy.json';p.RUN=d;t.ROOT=d/'tunnel';t.ROOT.mkdir();d.chmod(0o755)
 settings={'xray_uid':account.pw_uid,'xray_gid':account.pw_gid}
 class API:
  XRAY=Path(os.environ.get('EVG_TEST_XRAY','/opt/vpn-manager/bin/xray'))
  def load_settings(self):return settings
  def ensure_runtime(self,_):pass
 p.api=API();p.install=lambda:None
 engine=None;log=(d/'engine.log').open('w')
 def command(args,check=True,timeout=20,data=None,**kw):
  nonlocal engine
  args=[str(x) for x in args]
  if args[:2]==['systemctl','restart']:
   if engine:
    engine.terminate();engine.wait(timeout=5)
   engine=subprocess.Popen(['setpriv','--reuid',str(account.pw_uid),'--regid',str(account.pw_gid),'--clear-groups','--inh-caps=+net_admin,+net_raw,+sys_ptrace,+dac_read_search','--ambient-caps=+net_admin,+net_raw,+sys_ptrace,+dac_read_search',str(p.api.XRAY),'run','-config',str(d/'policy.json')],stdout=log,stderr=log)
   return subprocess.CompletedProcess(args,0,'','')
  return subprocess.run(args,input=data,text=True,capture_output=True,check=check,timeout=timeout,**kw)
 t.command=command
 def apply(value):p.save(value);p.apply();time.sleep(.25)
 def curl(host='203.0.113.10',port=18080,resolve=None):
  args=['curl','-4','--noproxy','*','-fsS','--max-time','4']
  if resolve:args+=['--resolve',resolve]
  return run(args+[f'http://{host}:{port}/']).stdout.strip()
 def check(name,actual,expected):
  assert actual==expected,(name,actual,expected)
  print(name,actual,flush=True)
 try:
  run(['ip','route','add','unreachable','default','metric','32760','table',t.FULL_TABLE]);run(['ip','rule','add','priority','80','lookup',t.FULL_TABLE])
  run(['ip','link','set','waydroid0','name','wd-dormant'])
  base=p.defaults();apply(base)
  # Exercise both host filters, including forwarding initially disabled.
  run(['nft','-f','-'],input=t.host_rules('wan',previous_forward=False))
  check('default',curl(),'VPN')
  sample=p.defaults();sample['networks']=['203.0.113.10/32'];apply(sample);check('IP exception',curl(),'DIRECT')
  sample=p.defaults();sample['networks']=['example.test'];apply(sample);check('domain exception',curl('example.test',resolve='example.test:18080:203.0.113.10'),'DIRECT');check('other domain',curl('other.test',resolve='other.test:18080:203.0.113.10'),'VPN')
  sample=p.defaults();sample['ports']=['tcp:18080:out'];apply(sample);check('port exception',curl(),'DIRECT')
  # Incoming server replies need the physical route even when the peer is outside LAN.
  server=subprocess.Popen([sys.executable,'-m','http.server','18081','--bind','0.0.0.0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   sample=p.defaults();sample['ports']=['tcp:18081:in'];apply(sample)
   reply=run(['ip','netns','exec',os.environ['EVG_TEST_DIRECT'],'curl','--interface','203.0.113.10','--noproxy','*','-fsS','--max-time','3','http://198.51.100.2:18081/'])
   assert '<html' in reply.stdout.lower();print('incoming port reply DIRECT',flush=True)
  finally:server.terminate();server.wait(timeout=5)
  sample=p.defaults();sample['applications']=['/usr/bin/curl'];apply(sample);check('application exception',curl(),'DIRECT')
  raw=run([sys.executable,'-c',"import urllib.request; print(urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://203.0.113.10:18080',timeout=4).read().decode())"]).stdout.strip();check('other application',raw,'VPN')
  apply(base)
  wd=os.environ.get('EVG_TEST_WAYDROID')
  def wdget():return run(['ip','netns','exec',wd,'curl','-4','--noproxy','*','-fsS','--max-time','4','http://203.0.113.10:18080/']).stdout.strip()
  run(['ip','link','set','wd-dormant','name','waydroid0'])
  p.sync_waydroid_network()
  check('Waydroid started after VPN',wdget(),'DIRECT')
  def wddns(tcp=False):
   script='''import socket
q=b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00'+b'\\x04test\\x07example\\x00\\x00\\x01\\x00\\x01'
s=socket.socket(socket.AF_INET,TYPE);s.settimeout(3)
if TYPE==socket.SOCK_STREAM:
 s.connect(('10.244.0.1',53));s.sendall(len(q).to_bytes(2,'big')+q);n=int.from_bytes(s.recv(2),'big');data=s.recv(n)
else:s.sendto(q,('10.244.0.1',53));data=s.recv(1024)
print(socket.inet_ntoa(data[-4:]))
'''.replace('TYPE','socket.SOCK_STREAM' if tcp else 'socket.SOCK_DGRAM')
   return run(['ip','netns','exec',wd,sys.executable,'-c',script]).stdout.strip()
  check('Waydroid direct UDP DNS via bridge',wddns(),'203.0.113.11')
  check('Waydroid direct TCP DNS via bridge',wddns(True),'203.0.113.11')
  # A DHCP server bound to the bridge must be able to broadcast its offer.
  listener=subprocess.Popen(['ip','netns','exec',wd,sys.executable,'-u','-c',"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.bind(('',68)); print('ready',flush=True); print(s.recv(128).decode())"],stdout=subprocess.PIPE,text=True)
  assert listener.stdout.readline().strip()=='ready'
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as offer:
   offer.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'waydroid0\0');offer.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);offer.bind(('',67));offer.sendto(b'dhcp-offer',('255.255.255.255',68))
  check('Waydroid DHCP broadcast',listener.communicate(timeout=5)[0].strip(),'dhcp-offer')
  # Interface address loss/reappearance without restarting the classifier.
  run(['ip','addr','del','10.244.0.1/24','dev','waydroid0']);p.sync_waydroid_network()
  assert '10.244.0.0/24' not in run(['ip','route','show','table',p.PHYSICAL_TABLE]).stdout
  run(['ip','addr','add','10.244.0.1/24','dev','waydroid0']);p.sync_waydroid_network()
  check('Waydroid network recreated',wdget(),'DIRECT')
  sample=p.defaults();sample['waydroid_direct']=False;apply(sample);check('Waydroid VPN switch',wdget(),'VPN')
  check('Waydroid VPN UDP DNS via bridge',wddns(),'203.0.113.12')
  check('Waydroid VPN TCP DNS via bridge',wddns(True),'203.0.113.12')
  def dns(address,tcp=False,qtype=1,bind=None):
   q=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x04test\x07example\x00\x00\x01\x00\x01'
   q=q[:-4]+bytes([0,qtype])+q[-2:]
   with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as c:
    if bind:c.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,bind.encode()+b"\0")
    c.settimeout(3)
    if tcp:
     c.connect((address,53));c.sendall(len(q).to_bytes(2,'big')+q);size=int.from_bytes(c.recv(2),'big');data=c.recv(size)
    else:c.sendto(q,(address,53));data=c.recv(1024)
    return data[-3:].decode() if qtype==16 else socket.inet_ntoa(data[-4:])
  apply(base);check('default DNS',dns('1.1.1.1'),'203.0.113.12');check('TCP DNS',dns('1.1.1.1',tcp=True),'203.0.113.12');check('TXT DNS',dns('1.1.1.1',qtype=16),'VPN')
  check('DNS bound to VPN interface',dns('1.1.1.1',bind=t.FULL_HOST),'203.0.113.12')
  sample=p.defaults();sample['dns']=['1.1.1.1'];apply(sample);check('explicit direct DNS',dns('1.1.1.1'),'203.0.113.11')
  sample=p.defaults();sample['disabled_base']=['dns:stub'];apply(sample);check('local DNS override remains local',dns('127.0.0.53'),'203.0.113.12')
  apply(base)
  # Packet-level DNS from a local stub keeps its local leg and VPN upstream.
  import threading
  stub=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);stub.bind(('127.0.0.53',53))
  def serve():
   for _ in range(2):
    data,addr=stub.recvfrom(1024);stub.sendto(data,addr)
  threading.Thread(target=serve,daemon=True).start()
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as c:
   c.settimeout(2);c.sendto(b'local-dns',('127.0.0.53',53));check('loopback stub',c.recv(1024).decode(),'local-dns')
  # Stopping the classifier must remove the usable default, leaving unreachable.
  engine.terminate();engine.wait(timeout=5);engine=None
  try:curl()
  except subprocess.CalledProcessError:print('engine loss: protected traffic blocked',flush=True)
  else:raise AssertionError('Classifier failure leaked traffic')
 finally:
  if engine:engine.terminate();engine.wait(timeout=5)
  log.close()

SERVER=r'''
import http.server,sys
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  b=sys.argv[1].encode();self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def log_message(self,*a):pass
http.server.HTTPServer(('0.0.0.0',18080),H).serve_forever()
'''

DNS_SERVER=r'''
import socket,struct,sys,threading
answer=bytes([203,0,113,int(sys.argv[1])])
def reply(q):
 i=12
 while q[i]:i+=q[i]+1
 question=q[12:i+5];qt=q[i+1:i+3];value=(b'\x03'+(b'DIR' if sys.argv[1]=='11' else b'VPN')) if qt==b'\x00\x10' else answer
 return q[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+question+b'\xc0\x0c'+qt+b'\x00\x01\x00\x00\x00\x01'+len(value).to_bytes(2,'big')+value
def tcp():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',53));s.listen()
 while True:
  c,_=s.accept()
  with c:
   h=c.recv(2)
   if len(h)==2:
    q=c.recv(struct.unpack('!H',h)[0]);r=reply(q);c.sendall(struct.pack('!H',len(r))+r)
threading.Thread(target=tcp,daemon=True).start()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('1.1.1.1',53))
while True:
 q,a=s.recvfrom(1024);s.sendto(reply(q),a)
'''

def main():
 if len(sys.argv)>1 and sys.argv[1]=='child':return child(sys.argv[2])
 if os.geteuid()!=0:raise SystemExit('Run with sudo; the test only changes disposable namespaces.')
 suffix=uuid.uuid4().hex[:7];names=['evg-policy-'+suffix+x for x in ('h','d','v','w')];host,direct,vpn,wd=names;procs=[]
 def inside(ns,args):return run(['ip','netns','exec',ns,*args])
 try:
  for n in names:run(['ip','netns','add',n]);inside(n,['ip','link','set','lo','up'])
  for remote,hname,subnet in [(direct,'wan','198.51.100.'),(vpn,'evn-full-host','172.29.247.')]:
   run(['ip','link','add','e'+suffix,'type','veth','peer','name','r'+suffix])
   run(['ip','link','set','e'+suffix,'netns',host]);run(['ip','link','set','r'+suffix,'netns',remote])
   inside(host,['ip','link','set','e'+suffix,'name',hname]);inside(host,['ip','addr','add',subnet+('2/30' if remote==direct else '1/30'),'dev',hname]);inside(host,['ip','link','set',hname,'up'])
   inside(remote,['ip','addr','add',subnet+('1/30' if remote==direct else '2/30'),'dev','r'+suffix]);inside(remote,['ip','link','set','r'+suffix,'up']);inside(remote,['ip','addr','add','203.0.113.10/32','dev','lo'])
   procs.append(subprocess.Popen(['ip','netns','exec',remote,sys.executable,'-c',SERVER,'DIRECT' if remote==direct else 'VPN'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
  run(['ip','link','add','w'+suffix,'type','veth','peer','name','c'+suffix]);run(['ip','link','set','w'+suffix,'netns',host]);run(['ip','link','set','c'+suffix,'netns',wd])
  inside(host,['ip','link','set','w'+suffix,'name','waydroid0']);inside(host,['ip','addr','add','10.244.0.1/24','dev','waydroid0']);inside(host,['ip','link','set','waydroid0','up'])
  inside(wd,['ip','addr','add','10.244.0.2/24','dev','c'+suffix]);inside(wd,['ip','link','set','c'+suffix,'up']);inside(wd,['ip','route','add','default','via','10.244.0.1'])
  inside(host,['sysctl','-qw','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=0'])
  for n in (direct,vpn):
   inside(n,['ip','addr','add','1.1.1.1/32','dev','lo'])
   procs.append(subprocess.Popen(['ip','netns','exec',n,sys.executable,'-c',DNS_SERVER,'11' if n==direct else '12'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
  inside(host,['ip','route','add','default','via','198.51.100.1','dev','wan'])
  with tempfile.TemporaryDirectory(prefix='evg-policy-test-') as d:
   result=subprocess.run(['ip','netns','exec',host,sys.executable,__file__,'child',d],text=True,capture_output=True,timeout=120,env={**os.environ,'EVG_TEST_WAYDROID':wd,'EVG_TEST_DIRECT':direct})
   print(result.stdout)
   if result.returncode:
    print(result.stderr);print((Path(d)/'engine.log').read_text()[-6000:]);raise SystemExit(result.returncode)
 finally:
  for p in procs:p.terminate();p.wait(timeout=5)
  for n in names:subprocess.run(['ip','netns','del',n],capture_output=True)
if __name__=='__main__':main()
