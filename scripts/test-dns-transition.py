#!/usr/bin/env python3
"""Root-only offline regression; changes networking only in a temporary namespace."""
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
def run(*args,**kwargs):
    result=subprocess.run(args,text=True,capture_output=True,**kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result

def inside():
    import socket
    import threading
    spec=importlib.util.spec_from_file_location('tunnel',ROOT/'src/starfive_tunnel.py')
    tunnel=importlib.util.module_from_spec(spec);spec.loader.exec_module(tunnel)
    sockets=[]
    def echo(address,port,label):
        server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        server.bind((address,port));sockets.append(server)
        def worker():
            while True:
                try:
                    data,peer=server.recvfrom(1024);server.sendto(label.encode(),peer)
                except OSError:return
        threading.Thread(target=worker,daemon=True).start()
    echo('0.0.0.0',18553,'old-dns')
    echo('1.1.1.1',53,'new-dns')
    echo('0.0.0.0',18554,'unrelated')
    def rules(target,first=False):
        prefix='' if first else 'delete table ip test_dns\n'
        run('nft','-f','-',input=prefix+'table ip test_dns {\n chain output {\n type nat hook output priority dstnat; policy accept;\n udp dport 53 '+target+'\n udp dport 9999 redirect to :18554\n }\n}\n')
    def client(port):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.settimeout(1);sock.connect(('127.0.0.53',port));sockets.append(sock)
        return sock
    def query(sock):
        sock.send(b'probe');return sock.recv(1024).decode()
    rules('redirect to :18553',first=True)
    cached=client(53);other=client(9999)
    assert query(cached)=='old-dns' and query(other)=='unrelated'
    rules('dnat to 1.1.1.1:53')
    stale=query(cached)
    assert stale=='old-dns' and query(client(53))=='new-dns'
    tunnel.clear_dns_mappings(previous_vpn=True)
    assert query(cached)=='new-dns'
    # No matching previous entries is a successful, idempotent operation.
    tunnel.clear_dns_mappings(previous_vpn=True)
    # Rollback must also release this mode's DNAT on the same open socket.
    rules('redirect to :18553')
    assert query(cached)=='new-dns'
    tunnel.clear_dns_mappings()
    assert query(cached)=='old-dns'
    assert query(other)=='unrelated'
    untouched=run('conntrack','-L','-p','udp','--dport','9999').stdout
    assert 'dport=18554' in untouched or 'sport=18554' in untouched
    print(json.dumps({'stale_dns_reproduced':True,'same_socket_recovered':True,
                      'reverse_transition_recovered':True,'unrelated_flow_preserved':True,
                      'host_network_changed':False}))

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--inside':
        inside()
    else:
        namespace='evg-dns-'+secrets.token_hex(4)
        run('ip','netns','add',namespace)
        try:
            run('ip','-n',namespace,'link','set','lo','up')
            run('ip','-n',namespace,'addr','add','1.1.1.1/32','dev','lo')
            print(run('ip','netns','exec',namespace,sys.executable,__file__,'--inside').stdout,end='')
        finally:
            run('ip','netns','del',namespace)
