import socket,time,struct,os,select,json,sys,hashlib
D=int(sys.argv[1]) if len(sys.argv)>1 else 120
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect((sys.argv[2] if len(sys.argv)>2 else '10.203.71.1',int(sys.argv[3]) if len(sys.argv)>3 else 18081));s.setblocking(False)
start=time.monotonic();nextsend=start;sent={};received={};invalid=0;seq=0
while time.monotonic()<start+D+2:
 now=time.monotonic()
 if now<start+D and now>=nextsend:
  payload=struct.pack('!I',seq)+hashlib.sha256(struct.pack('!I',seq)).digest()*4+b'V'*28
  s.send(payload);sent[seq]=now;seq+=1;nextsend+=.02
 if select.select([s],[],[],.005)[0]:
  b=s.recv(2048);n=struct.unpack('!I',b[:4])[0] if len(b)>=4 else -1
  expected=struct.pack('!I',n)+hashlib.sha256(struct.pack('!I',n)).digest()*4+b'V'*28 if n>=0 else b''
  if b!=expected or n not in sent:invalid+=1
  else:received[n]=(time.monotonic()-sent[n])*1000
r=sorted(received.values());diff=[abs(received[b]-received[a]) for a,b in zip(sorted(received),sorted(received)[1:])]
print(json.dumps({'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'duration_s':D,'sent':len(sent),'received':len(received),'lost':len(sent)-len(received),'invalid':invalid,'rtt_p50_ms':r[len(r)//2] if r else None,'rtt_p95_ms':r[int(len(r)*.95)] if r else None,'rtt_p99_ms':r[int(len(r)*.99)] if r else None,'mean_adjacent_rtt_difference_ms':sum(diff)/len(diff) if diff else None}))
