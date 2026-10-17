import socket,sys,time,json,pathlib
if sys.argv[1]=='server':
 import socketserver
 class Handler(socketserver.StreamRequestHandler):
  def handle(self):
   self.connection.settimeout(120)
   while True:
    b=self.rfile.readline(256)
    if not b:break
    self.wfile.write(b);self.wfile.flush()
 class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True
 Server(('10.203.71.1',18084),Handler).serve_forever()
else:
 log=pathlib.Path('/var/log/evgenium-link/stream.jsonl');start=time.monotonic();s=socket.create_connection(('10.203.71.1',18084),5);s.settimeout(60);local=s.getsockname();seq=0
 def emit(**d):
  with log.open('a') as f:f.write(json.dumps(dict(utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),elapsed=round(time.monotonic()-start,2),local=local,**d))+'\n')
 emit(event='connected')
 while time.monotonic()-start<2400:
  b=(str(seq)+'\n').encode();t=time.monotonic()
  try:
   s.sendall(b);out=b''
   while b'\n' not in out:
    x=s.recv(256)
    if not x:raise RuntimeError('connection closed')
    out+=x
   if out!=b:raise RuntimeError('integrity failure')
   emit(seq=seq,ok=True,ms=round((time.monotonic()-t)*1000,2));seq+=1
  except Exception as e:emit(ok=False,error=str(e));break
  time.sleep(2)
 emit(event='finished',responses=seq)
