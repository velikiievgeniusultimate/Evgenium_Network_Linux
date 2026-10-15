#!/usr/bin/env python3
"""Real isolated-tunnel integration checks. Root; never changes the working VPN."""
from pathlib import Path
import importlib.util,json,subprocess,time,socket,ssl,http.client,hashlib,re
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('tunnel',root/'src/starfive_tunnel.py');t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
before=json.loads(Path('/var/lib/vpn-manager/experimental-working-network.json').read_text());checks=[]
def record(name,ok,**metrics):
 checks.append({'test':name,'ok':bool(ok),**metrics});print(name,'PASS'if ok else'FAIL',flush=True)
def unchanged():
 return (subprocess.check_output(['systemctl','show','vpn-xray.service','-p','MainPID','--value'],text=True).strip()==before['xray_pid']and
 hashlib.sha256(Path('/run/vpn-manager/config.json').read_bytes()).hexdigest()==before['config_sha256']and
 hashlib.sha256(Path('/etc/resolv.conf').read_bytes()).hexdigest()==before['dns_sha256']and
 subprocess.check_output(['nft','list','table','inet','vpn_guard'],text=True)==before['guard'])
record('working_vpn_and_dns_unchanged_before',unchanged())
record('ipsec_sa_and_health',t.installed()and t.health())
latency=[]
for _ in range(5):
 start=time.monotonic();assert t.health();latency.append(round((time.monotonic()-start)*1000,2))
record('five_authenticated_health_requests',True,latency_ms=latency)
for size in (56,1200,1360):
 result=t.inside(['ping','-n','-c','10','-i','0.2','-W','1','-M','do','-s',str(size),t.HEALTH],check=False,timeout=10)
 loss=re.search(r'([\d.]+)% packet loss',result.stdout)
 record('ping_'+str(size),result.returncode==0,packet_loss_percent=float(loss[1])if loss else None)
metrics=t.download(8*1024*1024);record('eight_mib_integrity',metrics['integrity'],bytes=metrics['bytes'])
with t.namespace():
 context=ssl.create_default_context(cadata=t.PINNED_CA);context.load_cert_chain(str(t.ROOT/'client.pem'),str(t.ROOT/'client-key.pem'))
 sock=socket.create_connection((t.HEALTH,8443),timeout=8);tls=context.wrap_socket(sock,server_hostname=t.SERVER)
 conn=http.client.HTTPConnection(t.HEALTH,8443,timeout=8);conn.sock=tls;data=hashlib.shake_256(b'upload-test-v1').digest(1024*1024)
 try:
  conn.request('POST','/upload',body=data,headers={'Content-Type':'application/octet-stream'});r=conn.getresponse();reply=json.loads(r.read(4096));valid=r.status==200 and reply.get('received_bytes')==len(data)and reply.get('sha256')==hashlib.sha256(data).hexdigest()
 finally:conn.close()
record('one_mib_upload_integrity',valid)
for domain in ('yandex.ru','mail.ru','www.rt.ru'):
 cp=t.inside(['curl','-4','-sS','--max-time','8','-o','/dev/null','-w','%{http_code}', 'https://'+domain],check=False,timeout=10)
 record('dns_and_https_'+domain,cp.returncode==0 and cp.stdout.strip().isdigit()and int(cp.stdout.strip())>=100,http_status=cp.stdout.strip())
# Deliberately break only this namespace's IKE session. Its own monitor must recover it.
t.swan('--terminate','--ike','starfive',timeout=8)
with t.namespace():
 for address,port in ((t.HEALTH,8443),('1.1.1.1',443),(t.SERVER_LAN,22)):
  escaped=False
  try:socket.create_connection((address,port),timeout=.6).close();escaped=True
  except OSError:pass
  record('no_plaintext_escape_'+address,not escaped)
start=time.monotonic();recovered=False
while time.monotonic()-start<45:
 try:recovered=t.installed()and t.health()
 except (OSError,RuntimeError):pass
 if recovered:break
 time.sleep(1)
record('automatic_reconnect_after_sa_loss',recovered,elapsed_s=round(time.monotonic()-start,2))
record('working_vpn_and_dns_unchanged_after',unchanged())
report={'scope':'notebook namespace -> StarFive on same home LAN; no external ISP-segment claim','cipher':'ESP ChaCha20-Poly1305','checks':checks,'passed':sum(x['ok']for x in checks),'failed':sum(not x['ok']for x in checks)}
(root/'artifacts/tunnel-integration.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
assert report['failed']==0,report
