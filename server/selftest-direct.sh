#!/bin/bash
# Root on StarFive: isolated client namespace, dedicated test certificate only.
set -euo pipefail
umask 077
: "${EVGENIUM_TEST_PROFILE:?Use a dedicated test profile}"
base=$(cd -- "$(dirname -- "$0")" && pwd)
export EVGENIUM_DIRECT_MODULE="$base/../src/starfive_experimental.py"
testroot=/root/evgenium-direct-selftest
mkdir -p "$testroot"
cleanup() {
 ip netns del evgenium-direct-test 2>/dev/null || true
 ip link del evd-server 2>/dev/null || true
 nft delete table ip evgenium_direct_selftest 2>/dev/null || true
}
trap cleanup EXIT
ip netns add evgenium-direct-test
ip link add evd-server type veth peer name evd-client
ip link set evd-client netns evgenium-direct-test
ip addr add 10.79.0.1/30 dev evd-server
ip link set evd-server up
ip netns exec evgenium-direct-test ip addr add 10.79.0.2/30 dev evd-client
ip netns exec evgenium-direct-test ip link set lo up
ip netns exec evgenium-direct-test ip link set evd-client up
ip netns exec evgenium-direct-test ip route add default via 10.79.0.1
# Simulate only the router's public-port DNAT. No other traffic is forwarded.
nft -f - <<'NFT'
table ip evgenium_direct_selftest {
 chain prerouting {
  type nat hook prerouting priority dstnat;
  iifname "evd-server" ip daddr 109.194.67.159 tcp dport 8443 dnat to 192.168.0.163:8443
 }
}
NFT
ip netns exec evgenium-direct-test python3 - "$testroot" <<'PY'
import importlib.util,json,os,socket,ssl,http.client,uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('exp',os.environ['EVGENIUM_DIRECT_MODULE'])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.ROOT=Path(__import__('sys').argv[1]);m.STATE=m.ROOT/'state.json';m.PENDING_TEST=m.ROOT/'pending.json'
p=json.loads(Path(os.environ['EVGENIUM_TEST_PROFILE']).read_text())
for name,key in [('ca.pem','ca'),('client.pem','certificate'),('client-key.pem','private_key')]:
 m.write(m.ROOT/name,p[key])
m.save({'telemetry':True})
m.write(m.ROOT/'guard.nft',m.render_guard());m.cmd(['nft','-f',m.ROOT/'guard.nft'])
assert m.active_guard() and not m.connected()
for dest in [('109.194.67.159',8443),('77.88.55.242',443),('192.168.0.163',22)]:
 try:
  socket.create_connection(dest,timeout=1).close()
 except OSError: pass
 else: raise AssertionError('Unmarked traffic escaped: '+str(dest))
print('PASS: unmarked diagnostic, internet and LAN sockets blocked',flush=True)
body={'schema':1,'event':'connection_diagnostic','manager':'0.2.22','report_id':uuid.uuid4().hex,'stage':'handshake','error':'timeout','elapsed_ms':55000,'guard':True,'ipsec':False,'platform':'other'}
assert m.deliver_report(body)
assert m.stored()['delivery_status']=='sent'
assert not m.connected() and m.active_guard()
print('PASS: report delivered with no VPN and active guard',flush=True)
assert 'fwmark 0xe771' not in m.cmd(['ip','rule','show']).stdout
print('PASS: direct routing exception cleaned up',flush=True)
# Simulate the full-tunnel policy table: ordinary route selection uses a VPN IP.
m.cmd(['ip','addr','add','10.77.0.99/32','dev','evd-client'])
m.cmd(['ip','route','add','table','51822','default','via','10.79.0.1','src','10.77.0.99'])
m.cmd(['ip','rule','add','priority','100','lookup','51822'])
assert 'src 10.77.0.99' in m.cmd(['ip','route','get',m.SERVER]).stdout
body['report_id']=uuid.uuid4().hex
assert m.deliver_report(body)
assert m.active_guard()
print('PASS: diagnostic socket bypasses full-tunnel policy routing',flush=True)
m.cmd(['ip','rule','del','priority','100','lookup','51822'])

# mTLS is required, even for the report-only public endpoint.
ctx=ssl.create_default_context(cafile=str(m.ROOT/'ca.pem'))
sock=socket.socket();sock.settimeout(3);sock.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,m.DIRECT_MARK)
try:
 sock.connect((m.SERVER,m.DIRECT_PORT))
 tls=ctx.wrap_socket(sock,server_hostname=m.SERVER)
 conn=http.client.HTTPConnection(m.SERVER,m.DIRECT_PORT);conn.sock=tls
 conn.request('POST','/report',body=json.dumps(body),headers={'Content-Type':'application/json'})
 response=conn.getresponse()
 assert response.status != 200
except (OSError,http.client.HTTPException): pass
finally: sock.close()
print('PASS: public collector rejects missing client certificate',flush=True)
# The public port must not expose transfer or control APIs.
ctx.load_cert_chain(str(m.ROOT/'client.pem'),str(m.ROOT/'client-key.pem'))
sock=socket.socket();sock.settimeout(3);sock.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,m.DIRECT_MARK)
sock.connect((m.SERVER,m.DIRECT_PORT));tls=ctx.wrap_socket(sock,server_hostname=m.SERVER)
conn=http.client.HTTPConnection(m.SERVER,m.DIRECT_PORT);conn.sock=tls
conn.request('GET','/blob?size=1');assert conn.getresponse().status==404;conn.close()
print('PASS: public transfer API is unavailable',flush=True)
PY
