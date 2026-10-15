import hashlib,json,socket,time
from pathlib import Path
import importlib.util
spec=importlib.util.spec_from_file_location('tunnel',Path(__file__).resolve().parents[1]/'src/starfive_tunnel.py');t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
block=hashlib.shake_256(b'evgenium-raw-transfer-v1').digest(65536);results=[]
with t.namespace():
 for op,size in [('download',16*1024*1024),('upload',8*1024*1024)]:
  with socket.create_connection(('10.77.0.1',5201),timeout=15)as sock:
   sock.sendall(json.dumps({'op':op,'size':size,'limit_mbps':100}).encode()+b'\n');stream=sock.makefile('rb');assert stream.readline(8)==b'OK\n';start=time.monotonic();count=0;digest=hashlib.sha256()
   if op=='download':
    while count<size:
     chunk=stream.read(min(65536,size-count))
     if not chunk:break
     digest.update(chunk);count+=len(chunk)
    expected=hashlib.sha256((block*(size//len(block)+1))[:size]).hexdigest();valid=count==size and digest.hexdigest()==expected
   else:
    while count<size:
     chunk=block[:min(len(block),size-count)];sock.sendall(chunk);count+=len(chunk);digest.update(chunk)
     time.sleep(max(0,start+count*8/100e6-time.monotonic()))
    reply=json.loads(stream.readline(256));valid=reply['bytes']==size and reply['sha256']==digest.hexdigest()
   elapsed=time.monotonic()-start;results.append({'direction':op,'bytes':count,'elapsed_s':round(elapsed,3),'mbps':round(count*8/elapsed/1e6,2),'integrity':valid,'rate_cap_mbps':100})
print(json.dumps(results,indent=2));assert all(x['integrity']for x in results)
