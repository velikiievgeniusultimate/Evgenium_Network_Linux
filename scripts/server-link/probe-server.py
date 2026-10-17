import http.server,socketserver,threading,time,hashlib,json
DATA=bytes(range(256))*1024
class HTTP(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  body=DATA if self.path=='/blob' else b'evgenium-link-ok\n'
  self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers()
  try:
   for i in range(0,len(body),4096):
    self.wfile.write(body[i:i+4096]);self.wfile.flush()
    if len(body)>4096:time.sleep(4096/125000)
  except (BrokenPipeError,ConnectionResetError):pass
 def do_POST(self):
  n=int(self.headers.get('Content-Length','0'))
  if n>262144:self.send_error(413);return
  body=self.rfile.read(n);out=hashlib.sha256(body).hexdigest().encode()
  self.send_response(200);self.send_header('Content-Length',str(len(out)));self.end_headers();self.wfile.write(out)
class UDP(socketserver.BaseRequestHandler):
 def handle(self):
  b,s=self.request
  if len(b)<=1200:s.sendto(b,self.client_address)
threading.Thread(target=socketserver.UDPServer(('10.203.71.1',18081),UDP).serve_forever,daemon=True).start()
http.server.ThreadingHTTPServer(('10.203.71.1',18080),HTTP).serve_forever()
