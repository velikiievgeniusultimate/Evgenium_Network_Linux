"""Bounded datagram framing over authenticated TLS; IKE/IPsec stays end-to-end."""
import asyncio,contextlib,hashlib,json,ssl,struct,time
from pathlib import Path
MAX_PACKET=65507
class Datagrams(asyncio.DatagramProtocol):
 def __init__(self):self.queue=asyncio.Queue(32);self.transport=None;self.peer=None
 def connection_made(self,t):self.transport=t
 def datagram_received(self,data,peer):
  if len(data)>MAX_PACKET:return
  if self.peer is None:self.peer=peer
  if self.peer!=peer:return
  try:self.queue.put_nowait(data)
  except asyncio.QueueFull:pass
 def error_received(self,error):pass

async def transfer(reader,writer,udp,remote=None):
 async def to_tls():
  while True:
   try:data=await asyncio.wait_for(udp.queue.get(),10)
   except asyncio.TimeoutError:data=b''
   writer.write(struct.pack('!H',len(data))+data);await writer.drain()
 async def from_tls():
  while True:
   size=struct.unpack('!H',await asyncio.wait_for(reader.readexactly(2),30))[0]
   if size>MAX_PACKET:raise ValueError('oversized_frame')
   if not size:continue
   packet=await asyncio.wait_for(reader.readexactly(size),10)
   destination=remote or udp.peer
   if destination is not None:udp.transport.sendto(packet,destination if remote is None else None)
 tasks=[asyncio.create_task(to_tls()),asyncio.create_task(from_tls())]
 try:
  done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
  for task in done:task.result()
 finally:
  for task in tasks:task.cancel()
  await asyncio.gather(*tasks,return_exceptions=True)
  writer.close()
  with contextlib.suppress(Exception):await asyncio.wait_for(writer.wait_closed(),2)

async def client_async(root,address,identity,port=24571):
 ctx=ssl.create_default_context(cafile=str(root/'ca.pem'));ctx.minimum_version=ssl.TLSVersion.TLSv1_3
 ctx.load_cert_chain(str(root/'client.pem'),str(root/'client-key.pem'))
 loop=asyncio.get_running_loop();udp=Datagrams()
 transport,_=await loop.create_datagram_endpoint(lambda:udp,local_addr=('127.0.0.1',24573))
 try:
  while True:
   try:
    reader,writer=await asyncio.wait_for(asyncio.open_connection(address,port,ssl=ctx,server_hostname=identity,ssl_handshake_timeout=6),8)
    await transfer(reader,writer,udp)
   except (OSError,TimeoutError,EOFError,ValueError,asyncio.IncompleteReadError):
    while not udp.queue.empty():udp.queue.get_nowait()
    await asyncio.sleep(1)
 finally:transport.close()

def client(root,address,identity,port=24571):asyncio.run(client_async(Path(root),address,identity,port))

async def server_async(root):
 ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_3
 ctx.load_cert_chain(str(root/'server.pem'),str(root/'server-key.pem'))
 ctx.load_verify_locations(str(root/'ca.pem'));ctx.load_verify_locations(str(root/'devices.pem'))
 ctx.verify_mode=ssl.CERT_REQUIRED;ctx.verify_flags|=ssl.VERIFY_CRL_CHECK_LEAF
 active={};total=0
 async def handle(reader,writer):
  nonlocal total
  cert=writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
  key=hashlib.sha256(cert).digest()
  if total>=64 or active.get(key,0)>=2:writer.close();return
  total+=1;active[key]=active.get(key,0)+1;transport=None
  try:
   udp=Datagrams();udp.peer=('127.0.0.1',4500)
   transport,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda:udp,remote_addr=('127.0.0.1',4500))
   await transfer(reader,writer,udp,remote=('127.0.0.1',4500))
  except (OSError,TimeoutError,EOFError,ValueError,asyncio.IncompleteReadError):pass
  finally:
   if transport:transport.close()
   writer.close();total-=1;active[key]-=1
   if not active[key]:del active[key]
 server=await asyncio.start_server(handle,'0.0.0.0',24571,ssl=ctx,ssl_handshake_timeout=6,limit=131072)
 async with server:await server.serve_forever()

if __name__=='__main__':asyncio.run(server_async(Path('/etc/evgenium-direct')))
